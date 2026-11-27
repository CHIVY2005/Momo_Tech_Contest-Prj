"""Partitioned SSE concurrency and per-IP slot manager for VeriShield Assistant."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Final

from fastapi import HTTPException

MAX_CONCURRENT_STREAMS: Final[int] = 6
MAX_UNAUTH_CONCURRENT_STREAMS: Final[int] = 2
MAX_CONCURRENT_STREAMS_PER_IP_UNAUTH: Final[int] = 2
MAX_CONCURRENT_STREAMS_PER_IP_AUTH: Final[int] = 3
SEMAPHORE_ACQUIRE_TIMEOUT_SEC: Final[float] = 2.0
_BUSY_MSG_VI: Final[str] = (
    "Trợ lý VeriShield đang bận xử lý nhiều yêu cầu. Vui lòng thử lại sau vài giây."
)
_SLOT_HEADERS: Final[dict[str, str]] = {
    "Retry-After": "2", "Cache-Control": "no-store", "Vary": "X-Case-Access-Token",
}


class AssistantSlotManager:
    """Partition global stream slots between authenticated case users and anonymous callers."""

    def __init__(
        self, *, max_concurrent: int = MAX_CONCURRENT_STREAMS,
        max_unauth: int = MAX_UNAUTH_CONCURRENT_STREAMS,
        max_unauth_per_ip: int = MAX_CONCURRENT_STREAMS_PER_IP_UNAUTH,
        max_auth_per_ip: int = MAX_CONCURRENT_STREAMS_PER_IP_AUTH,
        acquire_timeout_sec: float = SEMAPHORE_ACQUIRE_TIMEOUT_SEC,
    ) -> None:
        total = max(1, max_concurrent)
        self.global_semaphore = asyncio.Semaphore(total)
        self.unauth_semaphore = asyncio.Semaphore(max(1, min(max_unauth, total)))
        self._max_unauth_per_ip = max(1, max_unauth_per_ip)
        self._max_auth_per_ip = max(1, max_auth_per_ip)
        self._acquire_timeout = max(0.05, float(acquire_timeout_sec))
        self._active_by_ip: dict[str, int] = {}

    def _decrement_ip(self, ip_key: str) -> None:
        rem = self._active_by_ip.get(ip_key, 0) - 1
        if rem <= 0:
            self._active_by_ip.pop(ip_key, None)
        else:
            self._active_by_ip[ip_key] = rem

    async def acquire(
        self, *, authenticated: bool = True, client_ip: str | None = None
    ) -> Callable[[], None]:
        """Acquire stream slot(s) and return an idempotent release callback."""
        ip_key = client_ip.strip() if client_ip and client_ip.strip() else None
        if ip_key is not None:
            cap = self._max_auth_per_ip if authenticated else self._max_unauth_per_ip
            if self._active_by_ip.get(ip_key, 0) >= cap:
                raise HTTPException(429, _BUSY_MSG_VI, headers=_SLOT_HEADERS)
            self._active_by_ip[ip_key] = self._active_by_ip.get(ip_key, 0) + 1

        unauth_acquired, loop = False, asyncio.get_running_loop()
        deadline = loop.time() + self._acquire_timeout
        try:
            if not authenticated:
                await asyncio.wait_for(
                    self.unauth_semaphore.acquire(), timeout=max(0.01, deadline - loop.time())
                )
                unauth_acquired = True
            await asyncio.wait_for(
                self.global_semaphore.acquire(), timeout=max(0.01, deadline - loop.time())
            )
        except TimeoutError as exc:
            if unauth_acquired:
                self.unauth_semaphore.release()
            if ip_key is not None:
                self._decrement_ip(ip_key)
            raise HTTPException(429, _BUSY_MSG_VI, headers=_SLOT_HEADERS) from exc
        except BaseException:
            if unauth_acquired:
                self.unauth_semaphore.release()
            if ip_key is not None:
                self._decrement_ip(ip_key)
            raise

        released = False

        def _release() -> None:
            nonlocal released
            if not released:
                released = True
                self.global_semaphore.release()
                if unauth_acquired:
                    self.unauth_semaphore.release()
                if ip_key is not None:
                    self._decrement_ip(ip_key)

        return _release
