# Security Remediation Plan — Groups 4 & 5 (`NV-25` through `NV-41`) — Rev 2 (Plan-Reviewed)

> **Date:** 2026-11-27  
> **Status:** Approved after independent 2-reviewer audit (Plan Reviewers A & B; all 11 P0 & 13 P1 findings incorporated).  
> **Scope:** Close all 17 remaining `needs_validation` security leads from `run-1` (`NV-25`–`NV-41`):  
> - **Group 4 (7 leads, `NV-25`–`NV-31`):** Anti-Fraud Detection Integrity, Fraud Ops Radar & Pipeline Seams  
> - **Group 5 (10 leads, `NV-32`–`NV-41`):** Single-Worker Availability, Resource Exhaustion & Upstream Transport Resilience  
> **Binding Constitution:** `AGENTS.md` (zero MoMo branding, permissive licenses only / zero new dependencies, no `torch`/`transformers`, ONNX CPU arena/mem_pattern disabled, Merchant Receipt Honesty Guardrail, `<UNTRUSTED_USER_CONTENT>` isolation, `< 280` lines target for modified/new service modules, `mypy --strict`, `ruff`, PowerShell 5.1 safe, mandatory `scripts/verify.ps1`).

---

## Architecture & Wave Plan (Strictly Zero File Overlap Per Wave)

| Wave | Work Package | Leads Covered | Owned Files |
|---|---|---|---|
| **Wave 1** | **WP-7** | `NV-25` (IOC/normalization), `NV-26` (guardrails + ONNX offset-window chunking), `NV-27` (ai_orchestrator + monotonic calibrator), `NV-32` (superlinear regex/slicing/redaction), `NV-33` (RFC 1035 host cap) | `backend/app/services/ioc_extractor.py`, `backend/app/services/pii_scrubber.py`, `backend/app/services/receipt_validator.py`, `backend/app/services/guardrails.py`, `backend/app/services/scam_classifier.py`, `backend/app/services/risk_calibrator.py`, `backend/app/services/ai_orchestrator.py`, `backend/tests/unit/test_security_wp7.py` |
| **Wave 1** | **WP-8** | `NV-25` (dedicated cross-hash lookup bucket), `NV-28` (Radar poisoning guard in both `save_report` & `save_staged_report`, `LIMIT 60` & edge protection), `NV-29` (protected subdomain + full KB official domain guard), `NV-30` (demo exclusion & `vs_tg_*` 10-column + child cascade migration), `NV-31` (bank-agnostic `ref_h:`, 30d TTL + upsert refresh, Hamming `<= 3` dHash), `NV-33` (bounded `O(1)` domain expansion & SQL chunking), `NV-35` (batched `init_db` & retention pruning), `NV-36` (SQLite indexes, lock+versioned short-TTL radar cache, targeted campaign lookup), `NV-41` (`telegram_updates` delivery attempts, lease expiry & quarantine) | `backend/app/db/repository.py`, `backend/app/db/migrations.py` *(new helper)*, `backend/tests/unit/test_security_wp4.py` *(3 dynamic-date fixture lines)*, `backend/tests/unit/test_case_tokens.py` *(1 dynamic-date fixture line)*, `backend/tests/unit/test_codex_audit_regressions.py` *(1 dynamic-date fixture line)*, `backend/tests/unit/test_security_wp8.py` |
| **Wave 1** | **WP-9** | `NV-34` (dedicated OCR/STT/forensics/PDF executors, non-detaching `concurrent.futures.Future` semaphores, chunked OCR batch, single-transpose & pre-OCR/QR downscaling, Whisper `cpu_threads=2`), `NV-39` (overall LLM deadline, outer OpenAI `asyncio.timeout` on all 3 post sites + `ocr/gemini_provider.py`, key-only failover short-circuit, memoized base64, jittered `Retry-After` & failover sleep, process concurrency cap & per-endpoint circuit breaker) | `backend/app/core/media_executors.py` *(new)*, `backend/app/services/ocr/service.py`, `backend/app/services/ocr/rapidocr_provider.py`, `backend/app/services/ocr/gemini_provider.py`, `backend/app/services/image_forensics.py`, `backend/app/services/local_stt.py`, `backend/app/services/llm_resilience.py` *(new)*, `backend/app/services/llm_client.py`, `backend/tests/unit/test_security_wp9.py` |
| **Wave 2** | **WP-10** | `NV-25` (post-redirect/sandbox block-rule re-check), `NV-26` (`extra_urls` into guardrails + prepended to `llm_input_text`, static inspect all `iocs.urls[:8]`, live cap 4), `NV-27` (`bool(auds)` guard, unconditional full Tier-1 URL/guardrails/ONNX/KB re-scoring on cloud transcript, preserve `extracted_recipient_account` & OCR injection flag), `NV-30` (`contributes_to_radar=not is_demo`), `NV-31` (read-only Step-3 replay check; register replay only on completion with image & require image for `kind="ref"`), `NV-33` (SSE `aclosing` + error frame + timeout, no session after error), `NV-34` (`media_prevalidated` skip double-decode + bounded forensics/STT executors) | `backend/app/services/pipeline.py`, `backend/app/api/v1/analyze.py`, `backend/tests/unit/test_security_wp6.py` *(update lines 687-702 image+bank-agnostic hash & 759-764 `run_stt_bounded` mock)*, `backend/tests/unit/test_security_wp10.py` |
| **Wave 2** | **WP-11** | `NV-29` (expand `PROTECTED_SAFE_DEMO_IOCS` seeding with all `vn_scam_kb.json` official domains), `NV-36` (GET rate limits for PDF & Radar, PDF IOC/playbook/step/summary caps, `app.state.pdf_cache`, dedicated PDF executor in `cases.py` & `telegram_bot.py`, async Radar offload, `assistant_tools` indexed campaign lookup), `NV-37` (partitioned auth/unauth Assistant slots preserving `_semaphore` & no-arg compat, per-IP concurrency cap when `client_ip` passed, outer SSE timeout + 2s `aclose()` cap), `NV-38` (per-case & per-IP fair eviction in `EphemeralEvidenceStage` + `media_prevalidated=True`), `NV-40` (decoupled Telegram webhook limiter + per-pipeline `TelegramQuotaGuard` with claim release), `NV-41` (permanent 4xx quarantine -> HTTP 200, bounded transient retries with lease release, `/demo ²` + len<=3 ASCII check, pre-cache error containment in both message & PDF callback) | `backend/app/main.py`, `backend/app/api/v1/cases.py`, `backend/app/api/v1/radar.py`, `backend/app/api/v1/assistant.py`, `backend/app/api/v1/telegram.py`, `backend/app/services/report_pdf.py`, `backend/app/services/assistant_slots.py` *(new)*, `backend/app/services/assistant_service.py`, `backend/app/services/assistant_stage.py` *(new)*, `backend/app/services/assistant_evidence.py`, `backend/app/services/assistant_tools.py`, `backend/app/services/telegram_limits.py` *(new)*, `backend/app/services/telegram_bot.py`, `backend/tests/unit/test_security_wp11.py` |

---

## Frozen Cross-Wave Contracts

1. **`app.services.guardrails` (WP-7 -> WP-10):**
   ```python
   def detect_safety_advisory(
       normalized_text: str,
       has_suspicious_url: bool = False,
       extra_urls: Sequence[str] | None = None,
   ) -> tuple[bool, bool, list[str]]: ...

   def evaluate_guardrails(
       text: str,
       has_suspicious_url: bool = False,
       extra_urls: Sequence[str] | None = None,
   ) -> GuardrailResult: ...
   ```

2. **`app.db.repository` (WP-8 -> WP-10 & WP-11):**
   - `strip_visual_blobs_copy(report: AnalysisReport) -> AnalysisReport` — exported pure helper clearing `sandbox.screenshot_base64`, `ela_heatmap_base64`, and `exif_software` across `image_forensics` & `image_forensics_list`.
   - `CaseRepository.hash_receipt_ref_fingerprint(self, bank: str | None, ref_code: str) -> str` — bank-agnostic `f"ref_h:{self.hash_ioc_value('receipt_ref', ref_code.strip().upper())}"`.
   - `CaseRepository.is_protected_ioc(self, ioc_type: IocType, *, raw_value: str | None = None, ioc_hash: str | None = None) -> bool`.
   - `CaseRepository.find_campaign_titles_for_hashes(self, ioc_hashes: Sequence[str], limit: int = 2) -> list[str]`.
   - `CaseRepository.record_telegram_delivery_failure(self, update_id: int, *, permanent: bool, max_attempts: int = 3, owner_id: str | None = None) -> tuple[int, bool]`:
     - Increments `delivery_attempts`.
     - If `status == 'processing'`: verifies `owner_id is None or lease_owner == owner_id`. If `permanent` or `attempts >= max_attempts`, sets `status = 'quarantined', lease_owner = NULL, lease_expires_at = NULL`; otherwise preserves row with `delivery_attempts` incremented and sets `lease_owner = NULL, lease_expires_at = '1970-01-01T00:00:00+00:00'` so the next retry immediately reclaims without 180s deadlock or attempt loss!
     - If `status == 'completed'`: increments `delivery_attempts`, and sets `status = 'quarantined'` when `permanent` or `attempts >= max_attempts`.
   - `CaseRepository.claim_telegram_update(...)` checks context binding first, then returns `("quarantined", None, None)` if `status == 'quarantined'`, and NEVER resets `delivery_attempts` when reclaiming an expired `'processing'` lease.

3. **`app.core.media_executors` (WP-9 -> WP-10 & WP-11):**
   ```python
   class MediaExecutorBusyError(RuntimeError): ...

   async def run_ocr_bounded(
       fn: Callable[..., T], /, *args: Any, timeout_sec: float = 8.0,
       acquire_timeout_sec: float = 2.0, **kwargs: Any,
   ) -> T: ...
   async def run_stt_bounded(
       fn: Callable[..., T], /, *args: Any, timeout_sec: float = 15.0,
       acquire_timeout_sec: float = 2.0, **kwargs: Any,
   ) -> T: ...
   async def run_forensics_bounded(
       fn: Callable[..., T], /, *args: Any, timeout_sec: float = 15.0,
       acquire_timeout_sec: float = 5.0, **kwargs: Any,
   ) -> T: ...
   async def run_pdf_bounded(
       fn: Callable[..., T], /, *args: Any, timeout_sec: float = 15.0,
       acquire_timeout_sec: float = 2.0, **kwargs: Any,
   ) -> T: ...
   ```

4. **`app.services.pipeline.AnalysisPipeline` (WP-10 -> WP-11):**
   - `stream(..., media_prevalidated: bool = False)`, `run(..., media_prevalidated: bool = False)`, `run_ephemeral(..., media_prevalidated: bool = False)`.

---

## Detailed Specification by Work Package

### WP-7 — Core Detection, IOC Normalization, ONNX Windowing & Linear-Time Parsing

1. **`backend/app/services/ioc_extractor.py`:**
   - **Invisible-char handling (`NV-25`):** Define `_INVIS_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")`. Strip invisible chars in `fold_vi_ascii`, `normalize_ioc_value`, `_safe_extract_host`, and scheme-less URL matching — while **preserving** raw invisible chars on explicit `http(s)://` and `extra_urls` stored in `iocs.urls` so `inspect_url` still flags invisible-char URLs (`test_security_wp1.py:355`).
   - **IDNA canonicalization & RFC 1035 cap (`NV-25`, `NV-33`):**
     - `_safe_extract_host(url_or_host)`: strip `_INVIS_RE`, normalize Unicode dots `[\u3002\uff0e\uff61]` -> `.`, reject `..` / trailing `..`, extract hostname via `urlsplit`, strip single trailing `.`, IDNA-encode ONLY when `not host.isascii()` (preserving pure-ASCII `phish.190384756201` / `phish.xn--190384756201` in `test_codex_audit_regressions.py:1283,1424`), enforce `1 <= len(host) <= 253`, `len(labels) <= 127`, all `1 <= len(lbl) <= 63`.
     - `normalize_ioc_value("domain", value)`: return `_safe_extract_host(cleaned)` directly (return `""`, NEVER `or host`, when rejected!).
   - **Host-fair URL ordering (`NV-26`):** In `extract_iocs`, prepend `extra_urls` first, then from `extract_candidate_urls(text)` prioritize the first URL per distinct `_safe_extract_host` before secondary URLs on repeated hosts, then cap at `MAX_EXTRACTED_URLS = 8`.
   - **Phone normalization & extraction (`NV-25`):**
     - `normalize_ioc_value("phone", value)`: collapse 11-digit `84[35789]\d{8}` -> `0...` AND 12-digit `840[35789]\d{8}` (`+84 (0) 909 000 111`) -> `0...`.
     - Upgrade `_VN_PHONE_RE` to support `(+84)`, `(+84) (0)`, `+84 (0)`, `/`, `_` separators while rejecting date prefixes `r"^\d{2}/\d{2}/(?:19|20)\d{2}\b"` in both `extract_iocs` and `_replace_phone` (preventing `"09/11/2026 14:20"` false positives!).
   - **Account extraction (`NV-25`) — preserving `test_ioc_extractor.py:15`:**
     - Keep `LABELED_ACCOUNT_SPAN_RE` blanking matched spans before `_VN_PHONE_RE`.
     - Add **name-separated labeled account** pass (run AFTER `LABELED_ACCOUNT_SPAN_RE` blanking): explicit account label + 1–5 ASCII letter words (`[A-Za-z]{1,20}`, single-line, excluding stop-words `goi|sdt|hotline|zalo|lien|tien|vnd|dong|ngay|luc|ma|gd|otp|cccd|cmnd|the`) + separator + 6–19 digits (with currency/date guards).
     - Add **alphanumeric alias labeled account** pass: explicit account label + `_LABEL_SEP_PAT` + `[A-Za-z0-9][A-Za-z0-9\-_]{5,18}` (normalized 6–19 alnum, `>= 1` letter and `>= 4` digits, rejecting currency tails `r"^\d+(?:vn?d|d|dong|k|tr|trieu)$"`).
     - Add **bare transfer-verb account** pass: `(?:chuyen|nop|gui)(?:[ \t]+(?:tien|khoan|ngay|gap)){0,2}[ \t]+(?:vao|den|toi)[ \t]+(?:so[ \t]+)?(?P<acct>\d(?:[ \t.\-]?\d){7,18})(?!\d)` with currency/date guards.
   - **Eliminate superlinear regex & slicing (`NV-32`):**
     - Fix `_SCHEMELESS_TOKEN_RE` lookbehind from `(?<![/@\w])` to `(?<![/@\w.])` ($O(N)$ on `'0.' * N + '!'`).
     - Remove leading `^` from `_STRICT_CURRENCY_SYMBOL_AFTER_RE` and `_BANK_CURRENCY_WORD_AFTER_RE` and use zero-copy `.match(text, match.end("acct"))` in `is_labeled_account_match`.
     - Decorate `_build_spaced_digits_pattern` with `@lru_cache(maxsize=256)`, skip it in `scrub_free_text_pii` when `any(ch.isalpha() for ch in raw_digits)`, and cap unique `known_phones` / `known_accounts` to `32` each.

2. **`backend/app/services/pii_scrubber.py` (`NV-32`):**
   - Add `@lru_cache(maxsize=256)` compiled helpers for known-entity patterns and cap unique `known_phones` / `known_accounts` to `32` each.

3. **`backend/app/services/receipt_validator.py` (`NV-32`):**
   - Remove leading `^` from `_RECIPIENT_CURRENCY_TAIL_RE`, add `_COMMA_DIGIT_AT_RE = re.compile(r",\d")`, and replace all `cleaned[e_idx:]` / `cleaned[acct_match.end():]` slices (lines 244, 254, 255, 345) with zero-copy `.match(cleaned, pos)`.

4. **`backend/app/services/guardrails.py` (`NV-26`, keep `< 280` lines):**
   - Add `extra_urls: Sequence[str] | None = None` to `_has_non_official_url`, `detect_safety_advisory`, and `evaluate_guardrails`.
   - In `_has_non_official_url`, check `has_disallowed_url_backslash(raw)` on each `extra_url` BEFORE normalizing scheme-less entries with `f"https://{raw}"`, then verify strict ASCII host & official suffix. Tighten lines to stay `< 280` lines.

5. **`backend/app/services/scam_classifier.py` (`NV-26`):**
   - Trigger multi-window scanning strictly whenever `len(encoded.ids) >= MAX_MODEL_SEQ_LEN` (NO `len > 450` gate!).
   - Use `encoded.offsets` (mapping last non-special token end char offset minus `len("query: ")` and stepping with overlap, fallback to `max(1, len(window_text) * 3 // 4)` if offsets empty) to scan contiguous overlapping windows up to `MAX_INFERENCE_WINDOWS = 12` covering all 8,000 chars (+ final tail window if still beyond), with early-exit once any window hits `scam_prob >= 0.75` or `inj_prob >= 0.75`. Normal `< 192`-token messages still run 1 single pass!
   - Aggregate conservatively: `max(scam_prob)`, `max(inj_prob)`, `min(adv_prob)`; choose the highest `(scam_prob, inj_prob)` window's label/probabilities when `>= 0.45`, else head window's label/probabilities with conservative summary scores.

6. **`backend/app/services/ai_orchestrator.py` (`NV-27`):**
   - Reuse `strip_xml_breakout_tags` from `app.services.guardrails` inside `_sanitize_untrusted_text` (strips `< /UNTRUSTED_USER_CONTENT>` and all prompt tags).
   - Compute `has_audio_input = bool(audio_bytes or audios)` in `run_gemini_reasoning` and assign `transcript=(parsed.transcript or local_transcript) if has_audio_input else local_transcript` on BOTH override and live paths (lines 448 & 515).

7. **`backend/app/services/risk_calibrator.py` (`NV-27`, keep `< 260` lines):**
   - In the `elif llm_avail:` branch (`not onnx_avail and llm_avail`): compute `fused = round(0.45 * t1 + 0.55 * llm_val)`, and when `llm_val >= 60 and not guardrails.safety_advisory_detected`, set `fused = max(fused, round(0.85 * llm_val))` (strictly monotonic, no `t1==0` cliff, 100% compatible with `test_risk_calibrator.py`).

---

### WP-8 — SQLite Repository Integrity, Protected Guards, Replay Hardening & Bounded Growth

1. **`backend/app/db/migrations.py` *(new helper, `< 220` lines)* + `backend/app/db/repository.py`:**
   - **Schema & Indexes (`NV-35`, `NV-36`, `NV-41`):**
     - Columns: `cases.redaction_ver INTEGER NOT NULL DEFAULT 0` (current `2`), `telegram_updates.scrubbed INTEGER NOT NULL DEFAULT 0`, `telegram_updates.delivery_attempts INTEGER NOT NULL DEFAULT 0`, `ioc_sightings.label_ver INTEGER NOT NULL DEFAULT 0`, `campaigns.label_ver INTEGER NOT NULL DEFAULT 0`, `block_rules.label_ver INTEGER NOT NULL DEFAULT 0` (current `1`).
     - Indexes: `idx_cases_radar_demo_created`, `idx_cases_redaction_ver`, `idx_cases_created_at`, `idx_ioc_sightings_hits`, `idx_ioc_sightings_demo`, `idx_campaigns_primary_hash`, `idx_block_rules_expires`, `idx_receipt_hashes_created`, `idx_telegram_updates_status_created`, `idx_radar_audit_action_created`.
   - **Batched `init_db()` (ZERO full-table `.fetchall()`, commit per 100-row batch, strictly close connections in `finally:`):**
     - `cases` (`WHERE redaction_ver < 2 OR case_id LIKE 'vs_tg_%' LIMIT 100`): select ALL 10 columns; on `vs_tg_*` rotation, re-insert ALL 10 columns + `redaction_ver = 2` AND cascade `UPDATE cases SET parent_case_id = ? WHERE parent_case_id = ?` (`NV-30`); on all other rows, ALWAYS update `redaction_ver = 2` even when JSON unchanged!
     - `telegram_updates` (`WHERE scrubbed = 0 LIMIT 100`): scrub `reply_text` when non-empty and ALWAYS set `scrubbed = 1`.
     - `ioc_sightings` (`WHERE label_ver < 1 LIMIT 100`) and `campaigns` (`WHERE label_ver < 1 LIMIT 100`) FIRST, THEN `block_rules` (`WHERE label_ver < 1 LIMIT 100`): ALWAYS set `label_ver = 1`.
     - `radar_audit_logs` (`WHERE rule_id IS NOT NULL AND rule_id NOT GLOB 'rule_[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' LIMIT 100`): set `rule_id = NULL`.
     - `receipt_hashes` (`WHERE fingerprint LIKE 'ref:%' LIMIT 100`): migrate to bank-agnostic `ref_h:` with `ON CONFLICT(fingerprint) DO UPDATE SET created_at = MAX(created_at, excluded.created_at)` and delete old `ref:` row.
     - Normal writes (`save_report`, `save_staged_report`, `seed_if_empty`, `add_block_rule`, `save_telegram_update_cache`) always set `redaction_ver = 2` / `label_ver = 1` / `scrubbed = 1` (scrubbing `reply_text` on write!).
   - **Retention pruning (`NV-35`):**
     - Configurable `CaseRepository` init defaults: `max_stored_cases=5000`, `max_stored_ioc_sightings=2000`, `max_stored_receipt_hashes=10000`, `max_stored_telegram_updates=5000`, `receipt_ttl_days=30`, `telegram_update_ttl_days=7`.
     - `ioc_sightings` pruning preserves `is_demo = 1`, `campaign_id IS NOT NULL`, `ioc_hash IN (SELECT primary_ioc_hash FROM campaigns)`, and `ioc_hash IN (SELECT ioc_hash FROM block_rules)`.
     - Orphaned `ioc_edges` pruning deletes ONLY edges where `source_id` OR `target_id` is in NEITHER `ioc_sightings.ioc_hash` NOR `campaigns.campaign_id`.
     - Update the 5 hardcoded `'2026-11-26'` fixture timestamps in `test_security_wp4.py:163,674,678`, `test_case_tokens.py:300`, `test_codex_audit_regressions.py:1063` to dynamic `(datetime.now(UTC) - timedelta(hours=1)).isoformat()` so TTL pruning never becomes a calendar time-bomb!
   - **Protected IOCs & Radar integrity (`NV-28`, `NV-29`, `NV-30`):**
     - Load KB official domains (`vn_scam_kb.json` `official_brands[*].official_domains` + `chinhphu.vn` + `.gov.vn` + bare public suffixes `com.vn`/`gov.vn`/etc.) into a cached frozenset inside `repository.py`.
     - `is_protected_ioc` / `_is_protected_ioc_conn`: expands domain candidates via `_expand_domain_candidates([raw_value])`, checks `protected_demo_iocs` (`IN (...)`) AND official domain suffixes / bare public suffixes! Used in `add_block_rule` (also rejecting empty canonical values), `save_report`, and `save_staged_report`.
     - Shared `_should_ingest_radar_iocs(report)` enforced in BOTH `save_report` AND `save_staged_report`: blocks prompt-injection-only submissions without corroborating threat signals (`url_findings` risk>=40/ssrf, `vietqr_findings` anomaly, `receipt_logic` anomaly, `image_forensics.tamper_score>=35`, `active_block_rule_hit`, or ONNX `scam_probability>=0.65` with `predicted_label != "PROMPT_INJECTION"`).
     - `save_report`: `effective_radar = bool(contributes_to_radar) and not is_demo`; cap sightings BEFORE upsert at `MAX_SIGHTINGS_PER_CASE = 8` (identical in `save_staged_report`); use exported `strip_visual_blobs_copy(live_redacted)` to avoid redundant 2nd `redact_report_pii` pass (`NV-32`).
     - `get_radar_graph`: count cases `WHERE contributes_to_radar = 1 AND is_demo = 0`; prioritize blocked & campaign sightings before `LIMIT 60`; prioritize `primary_ioc`/`associated_ioc` edges before `LIMIT 120`; protect 2.0s short-TTL `_radar_cache` with `threading.Lock` + monotonic `_radar_cache_ver` invalidated on every write!
     - `find_campaign_titles_for_hashes(hashes, limit=2)`: chunked by 500, ordered by `case_count DESC`.
   - **Domain expansion, cross-hash lookup & SQL chunking (`NV-25`, `NV-33`):**
     - `_expand_domain_candidates`: canonicalize host, reject `len(host) > 253` or empty, slice `labels[-(MAX_DOMAIN_PARENT_LEVELS + 3):]` (starting at `0` if sliced, else `1`) so `.com.vn` still yields all 4 parent levels in $O(1)$ time/RAM, deduplicate with `seen: set[str]`.
     - `_bounded_lookup_hashes`: `MAX_LOOKUP_PHONE_HASHES=8`, `MAX_LOOKUP_ACCOUNT_HASHES=8`, `MAX_LOOKUP_CROSS_HASHES=8`, `MAX_LOOKUP_DOMAIN_HASHES=16`, `MAX_LOOKUP_IOC_HASHES=40`. Cross-hash bucket prioritizes phone-shaped `bank_accounts` hashed as `"phone"` first, then `phones` hashed as `"bank_account"`.
     - Chunk all `IN (...)` queries at `_SQL_IN_CHUNK = 500`.
   - **Receipt replay hardening (`NV-31`):**
     - `hash_receipt_ref_fingerprint(self, bank, ref_code)` = `f"ref_h:{self.hash_ioc_value('receipt_ref', ref_code.strip().upper())}"`.
     - Enforce `created_at >= cutoff_iso` (`receipt_ttl_days = 30`) on read; upsert with `ON CONFLICT(fingerprint) DO UPDATE SET created_at = excluded.created_at`.
     - Hamming distance `<= 3` over non-expired `dhash:` rows (`LIMIT 2000`, validating 16 hex chars before `int(..., 16)`).
   - **Telegram delivery attempts & quarantine (`NV-41`):**
     - Implement `record_telegram_delivery_failure` and `claim_telegram_update` `'quarantined'` state exactly per Frozen Contract #2.

---

### WP-9 — Media Executors, Non-Detaching Semaphores, Downscaling & LLM Resilience

1. **`backend/app/core/media_executors.py` *(new, `< 150` lines)* (`NV-34`, `NV-36`):**
   - Dedicated `ThreadPoolExecutor`s (`OCR_EXECUTOR` max 2, `STT_EXECUTOR` max 1, `FORENSICS_EXECUTOR` max 2, `PDF_EXECUTOR` max 2).
   - `BoundedExecutorPool`:
     - Per-event-loop `asyncio.Semaphore` (weak/loop-keyed).
     - Acquires via `await asyncio.wait_for(sem.acquire(), timeout=acquire_timeout_sec)` (real coroutine -> `.close()` safe!).
     - Submits via `try: cf = self._executor.submit(fn, *args, **kwargs)` / `except BaseException: sem.release(); raise`.
     - Attaches `cf.add_done_callback(_release)` where `_release` checks `if not loop.is_closed(): with contextlib.suppress(RuntimeError): loop.call_soon_threadsafe(sem.release)`.
     - Awaits `await asyncio.wait_for(_await_cf(cf, loop), timeout=timeout_sec)` where `_await_cf` is an `async def` coroutine wrapping `asyncio.wrap_future(cf, loop=loop)` (safe if `asyncio.wait_for` is monkeypatched to call `coro.close()`!).

2. **`backend/app/services/ocr/service.py` (`NV-34`):**
   - Use per-instance `BoundedExecutorPool` sharing `OCR_EXECUTOR` bounded to `settings.ocr_max_concurrency`.
   - Return `OcrResult(available=False, status="timeout", error_code="OCR_BUSY")` on `MediaExecutorBusyError`; return `False` in `_should_trigger_gemini_fallback` when `primary_res.error_code == "OCR_BUSY"`.
   - In `extract_batch`: process images in sequential chunks of size `max(1, self._settings.ocr_max_concurrency)` so a legitimate 4-image upload never self-starves!

3. **`backend/app/services/ocr/rapidocr_provider.py` (`NV-34`, keep `< 280` lines):**
   - Downscale decoded `bgr` if `max(h, w) > 2048` (`cv2.INTER_AREA`) before `engine(bgr)`.

4. **`backend/app/services/image_forensics.py` (`NV-34`, keep `< 230` lines):**
   - Transpose EXIF **once** in `analyze_image_forensics`; compute dHash on transposed `rgb`; downscale directly to `<= 2048px` (without full 25 MP `.copy()`) for QR (`_decode_qr_from_bgr`) and to `<= 1600px` for ELA, dropping full-res `rgb` promptly. Also downscale `max(h, w) > 2048` in public `decode_qr_codes(image_bytes)`.

5. **`backend/app/services/local_stt.py` (`NV-34`):**
   - Set Whisper `cpu_threads=2`.

6. **`backend/app/services/llm_resilience.py` *(new, `< 180` lines)* + `backend/app/services/llm_client.py` + `backend/app/services/ocr/gemini_provider.py` (`NV-39`):**
   - Process-wide per-event-loop `asyncio.Semaphore(MAX_CONCURRENT_LLM_CALLS = 6)` acquired AFTER cheap pre-checks (`NO_API_KEY`, `INVALID_BASE_URL`, circuit-open) with `3.0s` acquire timeout -> `LLM_CONCURRENCY_LIMITED`, released in `finally:`.
   - Per-endpoint circuit breaker (threshold `5` consecutive terminal endpoint-wide failed calls `TIMEOUT`/`NETWORK_TRANSPORT_ERROR`/`HTTP_5xx` within `60s` -> open `20s`, 1 half-open probe, reset on success, `reset_llm_circuit_breaker()` exported for tests).
   - Overall deadline `min(60.0, max(timeout_sec * 1.6, timeout_sec + 10.0))`; keep `deadline: float | None = None` optional on `_call_openai_key` and `_call_google_genai_key`.
   - Wrap ALL 3 `client.post(...)` sites in `_call_openai_key` (AND `client.post` in `ocr/gemini_provider.py`) with `async with asyncio.timeout(attempt_timeout):` and catch `except (TimeoutError, httpx.TimeoutException):`. Check circuit breaker in `ocr/gemini_provider.py` too.
   - Memoize base64 image & audio parts ONCE before the retry loop in `_call_openai_key`.
   - Key-only backup failover (`should_failover_backup_key`: True ONLY on `HTTP_401`, `HTTP_403`, `HTTP_429`, `CLIENT_INIT_*`).
   - Cap `INVALID_STRUCTURED_JSON` retries to `<= 1` in BOTH `_call_google_genai_key` and `_call_openai_key`.
   - Jitter (`# noqa: S311`) + remaining-deadline clamping on `Retry-After`, exponential backoff, AND failover cooldown sleeps.

---

### WP-10 — Pipeline & `/analyze` Security Seams

1. **`backend/app/services/pipeline.py`:**
   - `media_prevalidated: bool = False` on `stream`, `run`, `run_ephemeral`; `effective_prevalidated = media_prevalidated and not is_demo_fixture` still enforces non-empty, count, per-file/total byte caps, `detect_canonical_image_mime`, and `detect_audio_format` (fail closed if `None`).
   - Run `analyze_image_forensics` via `run_forensics_bounded` in bounded batches of `<= 2` (or sequentially), catching `(MediaExecutorBusyError, TimeoutError)` cleanly without ever failing open to `SAFE`.
   - Run `run_local_stt` via `run_stt_bounded(..., timeout_sec=15.0)`, treating both `TimeoutError` and `MediaExecutorBusyError` as `stt_timed_out = True`.
   - Prepend `[URL_EXPLICIT]` / `[QR_URLS]` BEFORE `non_ocr_text` in `llm_input_text` (`NV-26` — avoids 6,000-char truncation!).
   - Pass `extra_urls=extra_urls` into `evaluate_guardrails(...)`.
   - Inspect ALL `iocs.urls[:8]` statically, allowing live `enable_network=True` on at most `4` direct user URLs (`NV-26`).
   - Post-redirect & post-sandbox block-rule re-check (`NV-25`): skip backslash-spoofed `uf.final_url` before host extraction, re-query `match_active_block_rules`, merge deduplicated rules, append CRITICAL `fraud_ops_radar` evidence if newly hit.
   - Audio-guarded cloud transcript (`if auds and not local_transcript and llm_res.transcript and llm_res.transcript.strip():`, `NV-27`):
     1. Re-extract `iocs` preserving `vietqr_list` + `receipt_logic.extracted_recipient_account`; re-check block rules.
     2. Static `inspect_url(..., enable_network=False)` on up to 4 new URLs from `llm_res.transcript`; append findings & evidence; update `has_susp_url`.
     3. Re-run `evaluate_guardrails(enriched_text, has_suspicious_url=has_susp_url, extra_urls=extra_urls)` preserving any prior `prompt_injection_detected`; extend `evidence`.
     4. ALWAYS re-run `self.classifier.predict(enriched_text)` + `self.kb.match_playbooks(...)`.
     5. Recompute `tier1_score` via shared `_compute_tier1_score(...)`.
   - Demo Radar isolation (`NV-30`): pass `contributes_to_radar=not is_demo` in `save_report`; filter protected IOCs in `_build_prehashed_iocs`; use `strip_visual_blobs_copy(saved_report)` for `staged_redacted` (`NV-32`).
   - Deferred image-only receipt replay (`NV-31`): Step 3 uses read-only `is_receipt_replayed`; Step 5 `save_report` uses `track_replay=(not is_demo) and bool(imgs) and bool(receipt_logic and receipt_logic.is_receipt_candidate)`; `_build_replay_fingerprints` requires `bool(receipt_dhash)` before emitting `kind="ref"` and calls `self.repo.hash_receipt_ref_fingerprint(...)`.
   - Update `test_security_wp6.py:687-702` (attach receipt PNG + stub OCR + bank-agnostic hash) and `:759-764` (monkeypatch `run_stt_bounded`).

2. **`backend/app/api/v1/analyze.py` (`NV-33`, `NV-34`, keep `<= 280` lines):**
   - Pass `media_prevalidated=True` to `pipeline.run` and `pipeline.stream`.
   - Wrap `_sse_generator()` in `async with asyncio.timeout(120.0), contextlib.aclosing(stream_iter):` + `try / except asyncio.CancelledError: raise / except TimeoutError / except Exception`, emitting safe Vietnamese `event: error` frames (zero raw exception leak, never emitting `event: session` after error).

---

### WP-11 — Edge Rate Limits, PDF/Radar Hardening, Assistant Slot/Stage Fairness & Telegram Resilience

1. **`backend/app/main.py` (`NV-29`, `NV-36`, `NV-40`):**
   - Keep `PROTECTED_SAFE_DEMO_IOCS` exported; add `_load_protected_official_iocs(data_dir)` merging `PROTECTED_SAFE_DEMO_IOCS` with all `vn_scam_kb.json` `official_brands[*].official_domains` (deduped).
   - Add `telegram_webhook_limiter = SlidingWindowRateLimiter(max(300, cfg.rate_limit_per_minute * 6), 60.0)` for `POST /api/v1/bot/telegram`.
   - Add GET limiters respecting low `cfg.rate_limit_per_minute`:
     - `pdf_get_limiter = SlidingWindowRateLimiter(min(20, cfg.rate_limit_per_minute), 60.0)` on `GET /api/v1/cases/*/report.pdf` (with `Vary: X-Case-Access-Token` on 429).
     - `radar_get_limiter = SlidingWindowRateLimiter(min(60, cfg.rate_limit_per_minute), 60.0)` on `GET /api/v1/radar/graph`.
   - Initialize `app.state.pdf_cache = OrderedDict()` (`maxsize=16`).

2. **`backend/app/services/report_pdf.py` & `backend/app/api/v1/cases.py` (`NV-36`):**
   - `report_pdf.py`: add `already_redacted: bool = False`, cap IOCs (`[:8]` + `(+N mục khác)`), cap `matched_playbooks[:8]`, `urgent_steps[:12]`, `summary_vi[:2000]`.
   - `cases.py`: lookup `app.state.pdf_cache` AFTER `verify_web_case_access`; render cache misses via `run_pdf_bounded(generate_incident_pdf, report, already_redacted=True, timeout_sec=15.0)`, returning HTTP 503 with `Retry-After: 2`, `Cache-Control: no-store`, `Vary: X-Case-Access-Token` on `MediaExecutorBusyError` / `TimeoutError`.

3. **`backend/app/api/v1/radar.py` & `backend/app/services/assistant_tools.py` (`NV-36`):**
   - `radar.py`: `await asyncio.to_thread(repo.get_radar_graph)`.
   - `assistant_tools.py` (keep `< 280` lines): replace `repo.get_radar_graph().campaigns` with `repo.find_campaign_titles_for_hashes(list(hashes), limit=2)`.

4. **`backend/app/services/assistant_slots.py` *(new, `< 100` lines)*, `backend/app/services/assistant_service.py` (`< 275` lines), `backend/app/api/v1/assistant.py` (`NV-37`):**
   - `AssistantSlotManager`: global `Semaphore(6)` exposed as `AssistantService._semaphore` (preserving `test_assistant_stream_api.py:585,608,755`), `unauth_sem = Semaphore(2)`, optional per-IP active counter (`client_ip: str | None = None`: cap `2` unauth / `3` auth when `client_ip is not None`, preserving 6-call no-arg test at `test_assistant_stream_api.py:429-430`).
   - `assistant_service.py`: pass `max_url_checks=1 if report is None else 2` to `iter_pre_tools_for_vault` (add optional `max_url_checks: int = MAX_URL_CHECKS_PER_TURN` kwarg in `assistant_tools.py`).
   - `assistant.py`: pass `authenticated=(case_id is not None)` & `client_ip` into `acquire_stream_slot`; pass `owner_key=client_ip` & `media_prevalidated=True` into `stream_ephemeral_evidence`; wrap `super().__call__` in `_SlotGuardedStreamingResponse` with `async with asyncio.timeout(self._outer_timeout_sec):` (default `STREAM_TOTAL_TIMEOUT_SEC + 10.0` optional kwarg on `_guarded_sse_response`) and wrap `aclose()` in `async with asyncio.timeout(2.0):`!

5. **`backend/app/services/assistant_stage.py` *(new, `< 120` lines)* & `backend/app/services/assistant_evidence.py` (`< 230` lines) (`NV-38`, `NV-34`):**
   - Move `StagedEvidenceDraft` + `EphemeralEvidenceStage` (keeping `self._drafts` attribute name) into `assistant_stage.py`, explicitly re-exported via `__all__` in `assistant_evidence.py` (`mypy --strict`).
   - `DEFAULT_STAGE_MAX_ENTRIES = 128`, `MAX_DRAFTS_PER_CASE = 3`, `MAX_DRAFTS_PER_OWNER = 6`, optional `owner_key: str | None = None`.
   - Eviction order: expired -> per-case oldest -> per-owner oldest (when `owner_key is not None`) -> global heaviest-bucket (`f"owner:{d.owner_key}" if d.owner_key else f"case:{d.parent_case_id}"`, tie-breaking by oldest insertion order).
   - Add `owner_key: str | None = None` and `media_prevalidated: bool = False` to `stream_ephemeral_evidence` -> forward to `pipeline.run_ephemeral(..., media_prevalidated=media_prevalidated)` and `evidence_stage.stage(..., owner_key=owner_key)`.

6. **`backend/app/services/telegram_limits.py` *(new, `< 100` lines)*, `backend/app/services/telegram_bot.py` & `backend/app/api/v1/telegram.py` (`NV-40`, `NV-41`, `NV-36`):**
   - `TelegramQuotaGuard` scoped per `AnalysisPipeline` (`WeakKeyDictionary[AnalysisPipeline, TelegramQuotaGuard]`): per-chat (`10/min`), per-sender (`8/min`), heavy-analysis (`4/min`), analysis `Semaphore(4)` (`acquire_timeout=2.0s`). Gate heavy quotas ONLY around actual `pipeline.run` / PDF work (never `/help`, `/start`, `cached`, `mismatch`, `quarantined`, denied callbacks). Always release claim + cancel `renew_task` if rate-limited, returning HTTP 200 `{"ok": True, "delivered": False, "rate_limited": True}`.
   - Define `TelegramPermanentDeliveryError(TelegramDeliveryError)` for HTTP 400/403/404 after HTML->plain fallback.
   - Catch `TelegramPermanentDeliveryError` BEFORE `TelegramDeliveryError`; check `claim_state == "quarantined"` in BOTH `handle_telegram_update` (before `answer_telegram_callback_query`) and `_handle_telegram_pdf_callback`; call `record_telegram_delivery_failure(env.update_id, ..., owner_id=owner_id)` (guarded by `if env.update_id is not None:`) on permanent delivery failure, transient delivery failure, AND unexpected pre-cache exceptions in both message & PDF handlers!
   - Fix `_resolve_demo_id`: `cleaned.isascii() and cleaned.isdigit() and len(cleaned) <= 3`.
   - Use `run_pdf_bounded(generate_incident_pdf, record.report, already_redacted=True, timeout_sec=15.0)` in `_handle_telegram_pdf_callback` (`NV-36`).

---

## Mandatory Verification Gate

Run from repository root:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
```
Require **EXIT 0**: 0 ruff, 0 mypy strict, 100% pytest (all 362 existing + all new WP-7..WP-11 tests), 0 tsc, 100% frontend tests & Next.js build.
