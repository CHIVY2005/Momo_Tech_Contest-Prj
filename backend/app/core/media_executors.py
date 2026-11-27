"""Dedicated bounded thread-pool executors for CPU-heavy media and PDF work."""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import weakref
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any


class MediaExecutorBusyError(RuntimeError):
    """Raised when a bounded media executor cannot acquire a concurrency slot before timeout."""


OCR_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vs-ocr")
STT_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vs-stt")
FORENSICS_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vs-forensics")
PDF_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vs-pdf")


async def _await_cf[T](
    cf: concurrent.futures.Future[T],
    loop: asyncio.AbstractEventLoop,
) -> T:
    """Await a concurrent.futures.Future via a real coroutine (safe if wait_for closes coro)."""
    return await asyncio.wrap_future(cf, loop=loop)


class BoundedExecutorPool:
    """Non-detaching concurrency limiter over a dedicated ThreadPoolExecutor."""

    def __init__(self, executor: ThreadPoolExecutor, max_concurrency: int) -> None:
        self._executor = executor
        self._max_concurrency = max(1, max_concurrency)
        self._semaphores: weakref.WeakKeyDictionary[
            asyncio.AbstractEventLoop, asyncio.Semaphore
        ] = weakref.WeakKeyDictionary()

    def _get_semaphore(self, loop: asyncio.AbstractEventLoop) -> asyncio.Semaphore:
        sem = self._semaphores.get(loop)
        if sem is None:
            sem = asyncio.Semaphore(self._max_concurrency)
            self._semaphores[loop] = sem
        return sem

    async def run[T](
        self,
        fn: Callable[..., T],
        /,
        *args: Any,
        timeout_sec: float,
        acquire_timeout_sec: float = 2.0,
        **kwargs: Any,
    ) -> T:
        """Acquire a slot, submit ``fn`` to the dedicated executor, and enforce ``timeout_sec``."""
        loop = asyncio.get_running_loop()
        sem = self._get_semaphore(loop)
        try:
            await asyncio.wait_for(sem.acquire(), timeout=max(0.0, acquire_timeout_sec))
        except TimeoutError as exc:
            raise MediaExecutorBusyError(
                f"Executor pool saturated (acquire timeout {acquire_timeout_sec:.2f}s)."
            ) from exc

        try:
            cf: concurrent.futures.Future[T] = self._executor.submit(fn, *args, **kwargs)
        except BaseException:
            sem.release()
            raise

        def _release(_fut: concurrent.futures.Future[T]) -> None:
            if not loop.is_closed():
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(sem.release)

        cf.add_done_callback(_release)
        return await asyncio.wait_for(_await_cf(cf, loop), timeout=timeout_sec)


_OCR_POOL = BoundedExecutorPool(OCR_EXECUTOR, max_concurrency=2)
_STT_POOL = BoundedExecutorPool(STT_EXECUTOR, max_concurrency=1)
_FORENSICS_POOL = BoundedExecutorPool(FORENSICS_EXECUTOR, max_concurrency=2)
_PDF_POOL = BoundedExecutorPool(PDF_EXECUTOR, max_concurrency=2)


async def run_ocr_bounded[T](
    fn: Callable[..., T],
    /,
    *args: Any,
    timeout_sec: float = 8.0,
    acquire_timeout_sec: float = 2.0,
    **kwargs: Any,
) -> T:
    """Execute a blocking OCR callable inside the dedicated bounded OCR thread pool."""
    return await _OCR_POOL.run(
        fn, *args, timeout_sec=timeout_sec, acquire_timeout_sec=acquire_timeout_sec, **kwargs
    )


async def run_stt_bounded[T](
    fn: Callable[..., T],
    /,
    *args: Any,
    timeout_sec: float = 15.0,
    acquire_timeout_sec: float = 2.0,
    **kwargs: Any,
) -> T:
    """Execute a blocking STT callable inside the dedicated bounded STT thread pool."""
    return await _STT_POOL.run(
        fn, *args, timeout_sec=timeout_sec, acquire_timeout_sec=acquire_timeout_sec, **kwargs
    )


async def run_forensics_bounded[T](
    fn: Callable[..., T],
    /,
    *args: Any,
    timeout_sec: float = 15.0,
    acquire_timeout_sec: float = 5.0,
    **kwargs: Any,
) -> T:
    """Execute a blocking image-forensics callable inside the dedicated bounded pool."""
    return await _FORENSICS_POOL.run(
        fn, *args, timeout_sec=timeout_sec, acquire_timeout_sec=acquire_timeout_sec, **kwargs
    )


async def run_pdf_bounded[T](
    fn: Callable[..., T],
    /,
    *args: Any,
    timeout_sec: float = 15.0,
    acquire_timeout_sec: float = 2.0,
    **kwargs: Any,
) -> T:
    """Execute a blocking PDF rendering callable inside the dedicated bounded PDF pool."""
    return await _PDF_POOL.run(
        fn, *args, timeout_sec=timeout_sec, acquire_timeout_sec=acquire_timeout_sec, **kwargs
    )
