"""FastAPI application factory with pure ASGI streaming body limit, security headers, and WAL."""

from __future__ import annotations

import contextlib
import json
import logging
import math
import time
from collections import OrderedDict, deque
from collections.abc import MutableMapping, Sequence
from pathlib import Path
from typing import Any, Final

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.api.v1.router import v1_router
from app.config import Settings, get_settings
from app.core.case_tokens import resolve_case_token_secret
from app.db.repository import CaseRepository
from app.services.assistant_evidence import EphemeralEvidenceStage
from app.services.assistant_rag import AssistantKnowledgeRetriever
from app.services.assistant_service import AssistantService
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

    def __init__(self, max_requests: int, window_seconds: float = 60.0) -> None:
        self._limit = max(1, max_requests)
        self._window = max(1.0, float(window_seconds))
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()

    def peek_capacity(self, client_key: str, *, now: float | None = None) -> tuple[bool, int]:
        current = time.monotonic() if now is None else now
        cutoff = current - self._window
        bucket = self._buckets.get(client_key)
        if bucket is None:
            return True, 0
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self._limit:
            remaining = self._window - (current - bucket[0])
            retry_after = max(1, min(int(math.ceil(self._window)), int(math.ceil(remaining))))
            return False, retry_after
        return True, 0

    def record(self, client_key: str, *, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        cutoff = current - self._window
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
        bucket.append(current)

    def check(self, client_key: str) -> tuple[bool, int]:
        now = time.monotonic()
        allowed, retry_after = self.peek_capacity(client_key, now=now)
        if not allowed:
            return False, retry_after
        self.record(client_key, now=now)
        return True, 0

    def allow(self, client_key: str) -> bool:
        allowed, _ = self.check(client_key)
        return allowed


class CompositeRateLimiter:
    """Dual/multi-window limiter verifying ALL windows before recording in any window."""

    def __init__(self, limiters: Sequence[SlidingWindowRateLimiter]) -> None:
        self._limiters = tuple(limiters)

    def check(self, client_key: str) -> tuple[bool, int]:
        now = time.monotonic()
        max_retry = 0
        for lim in self._limiters:
            allowed, retry_after = lim.peek_capacity(client_key, now=now)
            if not allowed:
                max_retry = max(max_retry, retry_after)
        if max_retry > 0:
            return False, max_retry
        for lim in self._limiters:
            lim.record(client_key, now=now)
        return True, 0

    def allow(self, client_key: str) -> bool:
        allowed, _ = self.check(client_key)
        return allowed


class SecurityAndLimitsMiddleware:
    """Pure ASGI middleware enforcing rate limits, streaming body caps, and security headers."""

    def __init__(
        self,
        app: ASGIApp,
        limiter: SlidingWindowRateLimiter,
        analyze_limit_bytes: int,
        default_post_limit_bytes: int = DEFAULT_JSON_POST_LIMIT_BYTES,
        pin_limiter: SlidingWindowRateLimiter | None = None,
        assistant_limiter: SlidingWindowRateLimiter | CompositeRateLimiter | None = None,
        evidence_limit_bytes: int | None = None,
        telegram_webhook_limiter: SlidingWindowRateLimiter | None = None,
        pdf_get_limiter: SlidingWindowRateLimiter | None = None,
        radar_get_limiter: SlidingWindowRateLimiter | None = None,
    ) -> None:
        self.app = app
        self.limiter = limiter
        self.pin_limiter = pin_limiter
        self.assistant_limiter = assistant_limiter
        self.telegram_webhook_limiter = telegram_webhook_limiter
        self.pdf_get_limiter = pdf_get_limiter
        self.radar_get_limiter = radar_get_limiter
        self.analyze_limit_bytes = analyze_limit_bytes
        self.evidence_limit_bytes = (
            evidence_limit_bytes if evidence_limit_bytes is not None else analyze_limit_bytes
        )
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
        client_tuple = scope.get("client")
        client_ip = str(client_tuple[0]) if client_tuple else "local"

        if method == "POST" and path.startswith("/api/v1/"):
            active_limiter: SlidingWindowRateLimiter | CompositeRateLimiter
            if self.telegram_webhook_limiter is not None and path == "/api/v1/bot/telegram":
                active_limiter = self.telegram_webhook_limiter
            elif self.assistant_limiter is not None and path.startswith("/api/v1/assistant/"):
                active_limiter = self.assistant_limiter
            elif self.pin_limiter is not None and path.startswith("/api/v1/radar/block-rules"):
                active_limiter = self.pin_limiter
            else:
                active_limiter = self.limiter
            allowed, retry_after = active_limiter.check(client_ip)
            if not allowed:
                rate_headers = {"Retry-After": str(retry_after), "Cache-Control": "no-store"}
                if path.startswith("/api/v1/assistant/"):
                    rate_headers["Vary"] = "X-Case-Access-Token"
                rate_resp = JSONResponse(
                    status_code=429,
                    headers=rate_headers,
                    content={
                        "detail": "Bạn thao tác quá nhanh. Vui lòng thử lại sau ít giây."
                    },
                )
                await rate_resp(scope, receive, send_with_headers)
                return

        if method == "GET":
            is_pdf_get = path.startswith("/api/v1/cases/") and path.endswith("/report.pdf")
            is_radar_get = path == "/api/v1/radar/graph"
            get_limiter: SlidingWindowRateLimiter | None = (
                self.pdf_get_limiter
                if is_pdf_get
                else (self.radar_get_limiter if is_radar_get else None)
            )
            if get_limiter is not None:
                allowed, retry_after = get_limiter.check(client_ip)
                if not allowed:
                    rate_headers = {"Retry-After": str(retry_after), "Cache-Control": "no-store"}
                    if is_pdf_get:
                        rate_headers["Vary"] = "X-Case-Access-Token"
                    rate_resp = JSONResponse(
                        status_code=429,
                        headers=rate_headers,
                        content={
                            "detail": "Bạn thao tác quá nhanh. Vui lòng thử lại sau ít giây."
                        },
                    )
                    await rate_resp(scope, receive, send_with_headers)
                    return

        if method != "POST":
            await self.app(scope, receive, send_with_headers)
            return

        if path.startswith("/api/v1/analyze"):
            limit = self.analyze_limit_bytes
        elif path == "/api/v1/assistant/chat/evidence/stream":
            limit = self.evidence_limit_bytes
        else:
            limit = self.default_post_limit_bytes

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


logger = logging.getLogger("verishield.security")


def _load_protected_official_iocs(data_dir: Path) -> list[tuple[str, str]]:
    """Merge canonical protected SAFE demo IOCs with all KB official brand domains."""
    merged: list[tuple[str, str]] = list(PROTECTED_SAFE_DEMO_IOCS)
    seen: set[tuple[str, str]] = {(t, v.strip().lower()) for t, v in merged}
    kb_path = data_dir / "vn_scam_kb.json"
    if kb_path.exists():
        with contextlib.suppress(OSError, ValueError, TypeError):
            payload = json.loads(kb_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                for brand in payload.get("official_brands", []):
                    if not isinstance(brand, dict):
                        continue
                    for dom in brand.get("official_domains", []):
                        if not isinstance(dom, str):
                            continue
                        clean = dom.strip().lower().rstrip(".")
                        key = ("domain", clean)
                        if clean and key not in seen:
                            seen.add(key)
                            merged.append(key)
    return merged


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and wire a configured VeriShield AI FastAPI application instance."""
    cfg = settings or get_settings()
    case_token_secret = resolve_case_token_secret(cfg)
    if cfg.app_env == "production" and not cfg.resolved_ioc_hmac_secret:
        raise ValueError(
            "APP_ENV=production requires an explicit IOC_HMAC_SECRET (>= 16 chars)."
        )
    app = FastAPI(
        title=cfg.app_name,
        version=cfg.app_version,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    data_dir = Path(__file__).resolve().parent / "data"
    repo = CaseRepository(
        cfg.sqlite_path,
        default_ttl_minutes=cfg.block_rule_ttl_minutes,
        ioc_hmac_secret=cfg.resolved_ioc_hmac_secret,
        app_env=cfg.app_env,
    )
    repo.init_db()
    repo.seed_if_empty(
        None if cfg.app_env == "production" else str(data_dir / "seed_iocs.json"),
        protected_iocs=_load_protected_official_iocs(data_dir),
    )

    pipeline = AnalysisPipeline(
        settings=cfg,
        repo=repo,
        case_token_secret=case_token_secret,
    )
    model_dir = Path(cfg.model_dir)
    if not model_dir.is_absolute():
        model_dir = Path(__file__).resolve().parents[1] / cfg.model_dir
    assistant_retriever = AssistantKnowledgeRetriever(
        index_path=model_dir / "assistant_kb_index.json",
        embeddings_path=model_dir / "assistant_kb_embeddings.npy",
    )
    assistant_service = AssistantService(
        settings=cfg,
        repo=repo,
        retriever=assistant_retriever,
        classifier=pipeline.classifier,
    )

    limiter = SlidingWindowRateLimiter(cfg.rate_limit_per_minute, 60.0)
    pin_limiter = SlidingWindowRateLimiter(min(15, cfg.rate_limit_per_minute), 60.0)
    telegram_webhook_limiter = SlidingWindowRateLimiter(
        max(300, cfg.rate_limit_per_minute * 6), 60.0
    )
    pdf_get_limiter = SlidingWindowRateLimiter(min(20, cfg.rate_limit_per_minute), 60.0)
    radar_get_limiter = SlidingWindowRateLimiter(min(60, cfg.rate_limit_per_minute), 60.0)
    assistant_limiter = CompositeRateLimiter(
        [
            SlidingWindowRateLimiter(cfg.assistant_rate_limit_per_minute, 60.0),
            SlidingWindowRateLimiter(cfg.assistant_rate_limit_per_hour, 3600.0),
        ]
    )

    evidence_stage = EphemeralEvidenceStage()
    pdf_cache: OrderedDict[tuple[str, str, int, str], bytes] = OrderedDict()

    app.state.settings = cfg
    app.state.repo = repo
    app.state.pipeline = pipeline
    app.state.limiter = limiter
    app.state.telegram_webhook_limiter = telegram_webhook_limiter
    app.state.pdf_get_limiter = pdf_get_limiter
    app.state.radar_get_limiter = radar_get_limiter
    app.state.assistant_limiter = assistant_limiter
    app.state.assistant_retriever = assistant_retriever
    app.state.assistant_service = assistant_service
    app.state.evidence_stage = evidence_stage
    app.state.pdf_cache = pdf_cache
    app.state.case_token_secret = case_token_secret

    app.add_middleware(
        SecurityAndLimitsMiddleware,
        limiter=limiter,
        pin_limiter=pin_limiter,
        assistant_limiter=assistant_limiter,
        telegram_webhook_limiter=telegram_webhook_limiter,
        pdf_get_limiter=pdf_get_limiter,
        radar_get_limiter=radar_get_limiter,
        analyze_limit_bytes=2 * cfg.max_upload_bytes + MULTIPART_ENVELOPE_OVERHEAD_BYTES,
        evidence_limit_bytes=cfg.max_upload_bytes + MULTIPART_ENVELOPE_OVERHEAD_BYTES,
        default_post_limit_bytes=DEFAULT_JSON_POST_LIMIT_BYTES,
    )

    allow_all = "*" in cfg.cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=not allow_all,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Case-Access-Token"],
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
