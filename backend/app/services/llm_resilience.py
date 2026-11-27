"""LLM concurrency cap, per-endpoint circuit breaker, failover policy, and jittered backoff."""

from __future__ import annotations

import asyncio
import random
import threading
import time
import weakref
from collections import deque
from dataclasses import dataclass, field
from typing import Final

MAX_CONCURRENT_LLM_CALLS: Final[int] = 6
LLM_SEMAPHORE_ACQUIRE_TIMEOUT_SEC: Final[float] = 3.0
MAX_INTERACTIVE_RETRY_WAIT_SEC: Final[float] = 8.0
MAX_OVERALL_LLM_DEADLINE_SEC: Final[float] = 60.0
MAX_JSON_PARSE_RETRIES: Final[int] = 1

CIRCUIT_FAILURE_THRESHOLD: Final[int] = 5
CIRCUIT_FAILURE_WINDOW_SEC: Final[float] = 60.0
CIRCUIT_OPEN_DURATION_SEC: Final[float] = 20.0

_KEY_FAILOVER_CODES: Final[frozenset[str]] = frozenset({"HTTP_401", "HTTP_403", "HTTP_429"})
_ENDPOINT_OUTAGE_CODES: Final[frozenset[str]] = frozenset(
    {"TIMEOUT", "GEMINI_OCR_TIMEOUT", "NETWORK_TRANSPORT_ERROR"}
)


@dataclass
class _EndpointCircuitState:
    failure_times: deque[float] = field(default_factory=deque)
    open_until: float = 0.0
    half_open_in_flight: bool = False


_CIRCUIT_LOCK = threading.Lock()
_CIRCUIT_STATES: dict[str, _EndpointCircuitState] = {}
_LLM_SEMAPHORES: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, asyncio.Semaphore
] = weakref.WeakKeyDictionary()


def reset_llm_circuit_breaker() -> None:
    """Clear all per-endpoint circuit breaker state (intended for deterministic unit tests)."""
    with _CIRCUIT_LOCK:
        _CIRCUIT_STATES.clear()


def is_endpoint_outage_error(err_code: str | None) -> bool:
    """Return True for terminal endpoint-wide outage errors that should trip the circuit breaker."""
    if not err_code:
        return False
    if err_code in _ENDPOINT_OUTAGE_CODES:
        return True
    if err_code.startswith("HTTP_5") and len(err_code) >= 8 and err_code[5:8].isdigit():
        return len(err_code) == 8 or err_code[8] == "_"
    return False


def should_failover_backup_key(err_code: str) -> bool:
    """Return True ONLY when an error is API-key-specific (auth/quota/client init)."""
    if not err_code or err_code.endswith("_RETRY_AFTER_EXCEEDED"):
        return False
    return err_code in _KEY_FAILOVER_CODES or err_code.startswith("CLIENT_INIT_")


def circuit_try_acquire(endpoint_key: str, *, now: float | None = None) -> tuple[bool, bool]:
    """Check endpoint breaker; returns ``(allowed, is_half_open_probe)``."""
    t = time.monotonic() if now is None else now
    with _CIRCUIT_LOCK:
        state = _CIRCUIT_STATES.get(endpoint_key)
        if state is None or state.open_until <= 0.0:
            return True, False
        if t < state.open_until or state.half_open_in_flight:
            return False, False
        state.half_open_in_flight = True
        return True, True


def circuit_release_probe(endpoint_key: str) -> None:
    """Release an uncompleted half-open probe slot without closing or extending the breaker."""
    with _CIRCUIT_LOCK:
        state = _CIRCUIT_STATES.get(endpoint_key)
        if state is not None:
            state.half_open_in_flight = False


def circuit_record_outcome(
    endpoint_key: str,
    error_code: str | None,
    *,
    is_half_open_probe: bool = False,
    now: float | None = None,
) -> None:
    """Record a terminal call outcome (success or error) for ``endpoint_key``."""
    t = time.monotonic() if now is None else now
    with _CIRCUIT_LOCK:
        state = _CIRCUIT_STATES.setdefault(endpoint_key, _EndpointCircuitState())
        if error_code is None:
            state.failure_times.clear()
            state.open_until = 0.0
            state.half_open_in_flight = False
            return
        if error_code.startswith("CLIENT_INIT_"):
            if is_half_open_probe:
                state.half_open_in_flight = False
            return
        if is_endpoint_outage_error(error_code):
            if is_half_open_probe:
                state.half_open_in_flight = False
                state.open_until = t + CIRCUIT_OPEN_DURATION_SEC
                state.failure_times.clear()
                return
            while state.failure_times and (t - state.failure_times[0]) > CIRCUIT_FAILURE_WINDOW_SEC:
                state.failure_times.popleft()
            state.failure_times.append(t)
            if len(state.failure_times) >= CIRCUIT_FAILURE_THRESHOLD:
                state.open_until = t + CIRCUIT_OPEN_DURATION_SEC
                state.failure_times.clear()
                state.half_open_in_flight = False
            return
        state.failure_times.clear()
        if is_half_open_probe:
            state.open_until = 0.0
            state.half_open_in_flight = False


async def acquire_llm_slot(timeout_sec: float | None = None) -> asyncio.Semaphore | None:
    """Acquire a process-wide per-loop LLM concurrency slot, or return None on timeout."""
    loop = asyncio.get_running_loop()
    sem = _LLM_SEMAPHORES.get(loop)
    if sem is None:
        sem = asyncio.Semaphore(MAX_CONCURRENT_LLM_CALLS)
        _LLM_SEMAPHORES[loop] = sem
    resolved = LLM_SEMAPHORE_ACQUIRE_TIMEOUT_SEC if timeout_sec is None else timeout_sec
    try:
        await asyncio.wait_for(sem.acquire(), timeout=resolved)
        return sem
    except TimeoutError:
        return None


def compute_overall_deadline(timeout_sec: float) -> float:
    """Compute an overall monotonic event-loop deadline bounding retries and failover."""
    budget = min(MAX_OVERALL_LLM_DEADLINE_SEC, max(timeout_sec * 1.6, timeout_sec + 10.0))
    return asyncio.get_running_loop().time() + budget


def jittered_retry_delay(
    retry_idx: int,
    retry_after_sec: float | None,
    remaining_sec: float | None = None,
) -> float | None:
    """Compute jittered retry/cooldown sleep clamped to interactive budget and remaining deadline."""
    min_attempt_headroom = 0.15
    if retry_after_sec is not None:
        if retry_after_sec > MAX_INTERACTIVE_RETRY_WAIT_SEC:
            return None
        jitter_cap = min(0.25, max(0.05, retry_after_sec * 0.15))
        jitter = random.uniform(0.01, jitter_cap)  # noqa: S311
        delay = min(MAX_INTERACTIVE_RETRY_WAIT_SEC, max(0.02, retry_after_sec + jitter))
        if remaining_sec is not None:
            max_sleep = remaining_sec - min_attempt_headroom
            if max_sleep <= 0.0 or retry_after_sec > max_sleep:
                return None
            delay = min(delay, max_sleep)
        return float(max(0.01, delay))

    shift = min(max(0, retry_idx), 10)
    base_delay = min(5.0, 0.5 * float(1 << shift))
    jitter = random.uniform(0.01, 0.15)  # noqa: S311
    delay = min(MAX_INTERACTIVE_RETRY_WAIT_SEC, base_delay + jitter)
    if remaining_sec is not None:
        max_sleep = remaining_sec - min_attempt_headroom
        if max_sleep <= 0.05:
            return None
        delay = min(delay, max_sleep)
    return float(max(0.01, delay))
