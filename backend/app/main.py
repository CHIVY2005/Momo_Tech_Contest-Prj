"""FastAPI application factory with security headers, rate limiting, and SQLite WAL bootstrap."""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Final

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import v1_router
from app.config import Settings, get_settings
from app.db.repository import CaseRepository
from app.services.pipeline import AnalysisPipeline

MAX_TRACKED_RATE_IPS: Final[int] = 4096

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

    allow_all = "*" in cfg.cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=not allow_all,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def _security_and_rate_limit_middleware(
        request: Request,
        call_next: object,
    ) -> Response:
        if request.method == "POST" and request.url.path.startswith("/api/v1/"):
            client_ip = request.client.host if request.client else "local"
            if not limiter.allow(client_ip):
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Quá giới hạn số lượt yêu cầu mỗi phút. Vui lòng thử lại sau ít giây."
                    },
                )

        response: Response = await call_next(request)  # type: ignore[operator]
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    app.include_router(v1_router)
    return app


app = create_app()
