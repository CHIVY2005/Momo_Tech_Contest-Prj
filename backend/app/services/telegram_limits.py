"""Per-chat, per-sender, and concurrency quotas for the Telegram webhook handler."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections import OrderedDict, deque
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Final
from weakref import WeakKeyDictionary

if TYPE_CHECKING:
    from app.services.pipeline import AnalysisPipeline

TG_CHAT_LIMIT_PER_MIN: Final[int] = 10
TG_SENDER_LIMIT_PER_MIN: Final[int] = 8
TG_HEAVY_LIMIT_PER_MIN: Final[int] = 4
TG_MAX_CONCURRENT_ANALYSIS: Final[int] = 4
TG_ANALYSIS_ACQUIRE_TIMEOUT_SEC: Final[float] = 2.0
_MAX_KEYS: Final[int] = 4096

class TelegramRateLimitedError(RuntimeError):
    """Raised internally when a Telegram update exceeds per-chat/user or concurrency quotas."""

class _KeyWindowLimiter:
    def __init__(self, max_events: int, window_sec: float = 60.0) -> None:
        self._limit, self._window = max(1, max_events), max(1.0, float(window_sec))
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()
    def _trim(self, bucket: deque[float], now: float) -> None:
        cutoff = now - self._window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
    def has_capacity(self, key: str, *, now: float) -> bool:
        if (bucket := self._buckets.get(key)) is None:
            return True
        self._trim(bucket, now)
        return len(bucket) < self._limit
    def record(self, key: str, *, now: float) -> None:
        if (bucket := self._buckets.get(key)) is None:
            if len(self._buckets) >= _MAX_KEYS:
                self._buckets.popitem(last=False)
            bucket = self._buckets[key] = deque()
        else:
            self._buckets.move_to_end(key)
        self._trim(bucket, now)
        bucket.append(now)

class TelegramQuotaGuard:
    """Scoped per-pipeline Telegram message/heavy-work limiter + bounded analysis semaphore."""
    def __init__(
        self, *, chat_per_min: int = TG_CHAT_LIMIT_PER_MIN,
        sender_per_min: int = TG_SENDER_LIMIT_PER_MIN, heavy_per_min: int = TG_HEAVY_LIMIT_PER_MIN,
        max_concurrent: int = TG_MAX_CONCURRENT_ANALYSIS,
        acquire_timeout_sec: float = TG_ANALYSIS_ACQUIRE_TIMEOUT_SEC,
    ) -> None:
        self._chat_lim, self._heavy_lim = _KeyWindowLimiter(chat_per_min), _KeyWindowLimiter(heavy_per_min)
        self._sender_lim = _KeyWindowLimiter(sender_per_min)
        self._max_concurrent, self._acquire_timeout = max(1, max_concurrent), max(0.05, acquire_timeout_sec)
        self._sems: WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = WeakKeyDictionary()
    def _check_all(self, checks: list[tuple[_KeyWindowLimiter, str]]) -> bool:
        now = time.monotonic()
        if not all(lim.has_capacity(k, now=now) for lim, k in checks):
            return False
        for lim, k in checks:
            lim.record(k, now=now)
        return True
    def allow_message(self, *, chat_id: int | str | None, sender_user_id: int | str | None) -> bool:
        checks = [(self._chat_lim, str(chat_id))] if chat_id is not None else []
        if sender_user_id is not None:
            checks.append((self._sender_lim, str(sender_user_id)))
        if not checks:
            checks.append((self._chat_lim, "_anonymous"))
        return self._check_all(checks)
    def allow_heavy(self, *, chat_id: int | str | None, sender_user_id: int | str | None) -> bool:
        checks = [(self._heavy_lim, f"user:{sender_user_id}")] if sender_user_id is not None else []
        if chat_id is not None:
            checks.append((self._heavy_lim, f"chat:{chat_id}"))
        if not checks:
            checks.append((self._heavy_lim, "_anonymous"))
        return self._check_all(checks)
    @contextlib.asynccontextmanager
    async def analysis_slot(self) -> AsyncIterator[None]:
        sem = self._sems.setdefault(asyncio.get_running_loop(), asyncio.Semaphore(self._max_concurrent))
        try:
            await asyncio.wait_for(sem.acquire(), timeout=self._acquire_timeout)
        except TimeoutError as exc:
            raise TelegramRateLimitedError("Telegram analysis concurrency saturated.") from exc
        try:
            yield
        finally:
            sem.release()

_PIPELINE_GUARDS: WeakKeyDictionary[AnalysisPipeline, TelegramQuotaGuard] = WeakKeyDictionary()
def get_telegram_quota_guard(pipeline: AnalysisPipeline) -> TelegramQuotaGuard:
    """Return the TelegramQuotaGuard bound to ``pipeline`` (never a process-global singleton)."""
    return _PIPELINE_GUARDS.setdefault(pipeline, TelegramQuotaGuard())
