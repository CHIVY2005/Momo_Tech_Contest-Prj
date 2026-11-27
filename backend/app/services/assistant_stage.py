"""Bounded fair-eviction RAM stage for Phase-3 supplementary evidence drafts."""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from app.schemas import AnalysisReport
from app.services.pipeline import EphemeralAnalysisBundle

DEFAULT_STAGE_MAX_ENTRIES: Final[int] = 128
DEFAULT_STAGE_TTL_SECONDS: Final[float] = 900.0
MAX_DRAFTS_PER_CASE: Final[int] = 3
MAX_DRAFTS_PER_OWNER: Final[int] = 6


@dataclass(frozen=True, slots=True)
class StagedEvidenceDraft:
    """In-memory PII-redacted supplementary evidence draft (0 raw PII / 0 raw media bytes)."""

    draft_id: str
    parent_case_id: str
    parent_is_demo: bool
    staged_redacted_report: AnalysisReport
    prehashed_iocs: list[dict[str, str]]
    replay_fingerprints: list[dict[str, str]]
    allow_external_media_ai: bool
    created_at: float
    expires_at: float
    owner_key: str | None = None


class EphemeralEvidenceStage:
    """Bounded fair-eviction + TTL RAM stage for single-use supplementary evidence drafts."""

    def __init__(
        self, *, max_entries: int = DEFAULT_STAGE_MAX_ENTRIES,
        ttl_seconds: float = DEFAULT_STAGE_TTL_SECONDS, max_per_case: int = MAX_DRAFTS_PER_CASE,
        max_per_owner: int = MAX_DRAFTS_PER_OWNER, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_entries = max(1, int(max_entries))
        self._ttl_seconds = max(1.0, float(ttl_seconds))
        self._max_per_case = max(1, int(max_per_case))
        self._max_per_owner = max(1, int(max_per_owner))
        self._clock, self._lock = clock, threading.Lock()
        self._drafts: OrderedDict[str, StagedEvidenceDraft] = OrderedDict()

    def _evict_expired_locked(self, now: float) -> None:
        for did in [k for k, d in self._drafts.items() if d.expires_at <= now]:
            self._drafts.pop(did, None)

    def _evict_heaviest_bucket_locked(self) -> None:
        counts: dict[str, int] = {}
        oldest: dict[str, str] = {}
        for did, draft in self._drafts.items():
            bkey = f"owner:{draft.owner_key}" if draft.owner_key else f"case:{draft.parent_case_id}"
            if bkey not in counts:
                counts[bkey], oldest[bkey] = 1, did
            else:
                counts[bkey] += 1
        self._drafts.pop(oldest[max(counts, key=lambda bk: counts[bk])], None)

    def stage(
        self, *, parent_case_id: str, parent_is_demo: bool, bundle: EphemeralAnalysisBundle,
        allow_external_media_ai: bool, owner_key: str | None = None,
    ) -> StagedEvidenceDraft:
        """Store a stripped, pre-hashed supplementary draft with per-case & per-owner fairness."""
        now, clean_pid = self._clock(), parent_case_id.strip()
        clean_owner = owner_key.strip() if owner_key and owner_key.strip() else None
        draft_id = f"drf_{secrets.token_hex(16)}"
        draft = StagedEvidenceDraft(
            draft_id=draft_id, parent_case_id=clean_pid, parent_is_demo=bool(parent_is_demo),
            staged_redacted_report=bundle.staged_redacted_report,
            prehashed_iocs=[dict(item) for item in bundle.prehashed_iocs],
            replay_fingerprints=[dict(item) for item in bundle.replay_fingerprints],
            allow_external_media_ai=bool(allow_external_media_ai),
            created_at=now, expires_at=now + self._ttl_seconds, owner_key=clean_owner,
        )
        with self._lock:
            self._evict_expired_locked(now)
            same_case = [k for k, d in self._drafts.items() if d.parent_case_id == clean_pid]
            while len(same_case) >= self._max_per_case:
                self._drafts.pop(same_case.pop(0), None)
            if clean_owner is not None:
                same_owner = [k for k, d in self._drafts.items() if d.owner_key == clean_owner]
                while len(same_owner) >= self._max_per_owner:
                    self._drafts.pop(same_owner.pop(0), None)
            while len(self._drafts) >= self._max_entries:
                self._evict_heaviest_bucket_locked()
            self._drafts[draft_id] = draft
        return draft

    def pop_for_parent(self, draft_id: str, parent_case_id: str) -> StagedEvidenceDraft | None:
        """Atomically verify parent binding and consume a draft once; return None on mismatch."""
        clean_did, clean_pid = draft_id.strip(), parent_case_id.strip()
        if not clean_did or not clean_pid:
            return None
        now = self._clock()
        with self._lock:
            self._evict_expired_locked(now)
            draft = self._drafts.get(clean_did)
            if draft is None or not hmac.compare_digest(draft.parent_case_id, clean_pid):
                return None
            return self._drafts.pop(clean_did, None)
