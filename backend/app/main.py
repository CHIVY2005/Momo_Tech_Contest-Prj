"""FastAPI application factory with pure ASGI streaming body limit, security headers, and WAL."""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any, Final

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.api.v1.router import v1_router
from app.config import Settings, get_settings
from app.db.repository import CaseRepository
from app.services.pipeline import AnalysisPipeline

MAX_TRACKED_RATE_IPS: Final[int] = 4096
MULTIPART_ENVELOPE_OVERHEAD_BYTES: Final[int] = 65_536
DEFAULT_JSON_POST_LIMIT_BYTES: Final[int] = 262_144

PROTECTED_SAFE_DEMO_IOCS: Final[list[tuple[str, str]]] = [
    ("domain", "vietcombank.com.vn"),
    ("domain", "napas.com.vn"),
    ("domain", "vneid.gov.vn"),
    ("domain", "dichvucong.gov.vn"),
    ("domain", "techcombank.com.vn"),
    ("domain", "mbbank.com.vn"),
    ("domain", "bidv.com.vn"),
    ("bank_account", "190311112222"),
]

SECURITY_HEADERS: Final[dict[str, str]] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class SlidingWindowRateLimiter:
    """Bounded-memory per-IP sliding-window rate limiter for mutating POST endpoints."""

    def __init__(self, max_per_minute: int) -> None:
        self._limit = max(1, max_per_minute)
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()

    def allow(self, client_key: str) -> bool:
        now = time.monotonic()
        cutoff = now - 60.0
        bucket = self._buckets.get(client_key)
        if bucket is None:
            if len(self._buckets) >= MAX_TRACKED_RATE_IPS:
                self._buckets.popitem(last=False)
            bucket = deque()
            self._buckets[client_key] = bucket
        else:
            self._buckets.move_to_end(client_key)

        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= self._limit:
            return False
        bucket.append(now)
        return True


class SecurityAndLimitsMiddleware:
    """Pure ASGI middleware enforcing rate limits, streaming body caps, and security headers."""

    def __init__(
        self,
        app: ASGIApp,
        limiter: SlidingWindowRateLimiter,
        analyze_limit_bytes: int,
        default_post_limit_bytes: int = DEFAULT_JSON_POST_LIMIT_BYTES,
    ) -> None:
        self.app = app
        self.limiter = limiter
        self.analyze_limit_bytes = analyze_limit_bytes
        self.default_post_limit_bytes = default_post_limit_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def send_with_headers(message: MutableMapping[str, Any]) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                raw_headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                existing = {k.lower() for k, _ in raw_headers}
                for hk, hv in SECURITY_HEADERS.items():
                    if hk.lower().encode("latin-1") not in existing:
                        raw_headers.append((hk.lower().encode("latin-1"), hv.encode("latin-1")))
                message["headers"] = raw_headers
            await send(message)

        method = str(scope.get("method", "GET")).upper()
        path = str(scope.get("path", ""))

        if method == "POST" and path.startswith("/api/v1/"):
            client_tuple = scope.get("client")
            client_ip = str(client_tuple[0]) if client_tuple else "local"
            if not self.limiter.allow(client_ip):
                rate_resp = JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Quá giới hạn số lượt yêu cầu mỗi phút. Vui lòng thử lại sau ít giây."
                    },
                )
                await rate_resp(scope, receive, send_with_headers)
                return

        if method != "POST":
            await self.app(scope, receive, send_with_headers)
            return

        limit = (
            self.analyze_limit_bytes
            if path.startswith("/api/v1/analyze")
            else self.default_post_limit_bytes
        )

        for raw_key, raw_val in scope.get("headers", []):
            if raw_key.lower() == b"content-length":
                try:
                    declared = int(raw_val.decode("ascii").strip())
                except ValueError:
                    bad = JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid Content-Length header."},
                    )
                    await bad(scope, receive, send_with_headers)
                    return
                if declared < 0:
                    bad = JSONResponse(
                        status_code=400,
                        content={"detail": "Negative Content-Length header."},
                    )
                    await bad(scope, receive, send_with_headers)
                    return
                if declared > limit:
                    too_big = JSONResponse(
                        status_code=413,
                        content={"detail": f"Request payload exceeds limit of {limit} bytes."},
                    )
                    await too_big(scope, receive, send_with_headers)
                    return

        seen_bytes = 0

        async def guarded_receive() -> MutableMapping[str, Any]:
            nonlocal seen_bytes
            message = await receive()
            if message["type"] == "http.request":
                body: bytes = message.get("body", b"")
                seen_bytes += len(body)
                if seen_bytes > limit:
                    # Raise HTTPException(413) so FastAPI's form parser re-raises 413 cleanly
                    raise HTTPException(
                        status_code=413,
                        detail=f"Streaming request body exceeded limit of {limit} bytes.",
                    )
            return message

        try:
            await self.app(scope, guarded_receive, send_with_headers)
        except HTTPException as exc:
            if not response_started:
                err = JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
                await err(scope, receive, send_with_headers)
                return
            raise


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and wire a configured VeriShield AI FastAPI application instance."""
    cfg = settings or get_settings()
    app = FastAPI(
        title=cfg.app_name,
        version=cfg.app_version,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    data_dir = Path(__file__).resolve().parent / "data"
    repo = CaseRepository(cfg.sqlite_path, default_ttl_minutes=cfg.block_rule_ttl_minutes)
    repo.init_db()
    repo.seed_if_empty(
        str(data_dir / "seed_iocs.json"),
        protected_iocs=PROTECTED_SAFE_DEMO_IOCS,
    )

    pipeline = AnalysisPipeline(settings=cfg, repo=repo)
    limiter = SlidingWindowRateLimiter(max_per_minute=cfg.rate_limit_per_minute)

    app.state.settings = cfg
    app.state.repo = repo
    app.state.pipeline = pipeline
    app.state.limiter = limiter

    app.add_middleware(
        SecurityAndLimitsMiddleware,
        limiter=limiter,
        analyze_limit_bytes=2 * cfg.max_upload_bytes + MULTIPART_ENVELOPE_OVERHEAD_BYTES,
        default_post_limit_bytes=DEFAULT_JSON_POST_LIMIT_BYTES,
    )

    allow_all = "*" in cfg.cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=not allow_all,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    app.include_router(v1_router)
    return app


_default_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    global _default_app
    if name == "app":
        if _default_app is None:
            _default_app = create_app()
        return _default_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
