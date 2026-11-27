# VeriShield AI v2.0 — Security Audit Remediation Plan (Groups 1–3: `NV-01`–`NV-24`) — v2 (Post-Review Approved)

> **Source Audit:** `C:\Users\congt\security-audit-skill\verishield-ai\run-1\` (`REPORT.md`, `NEEDS-VALIDATION.md`, `findings.json`)  
> **Scope:** All 24 prioritized `needs_validation` leads across Groups 1–3 (`NV-01` through `NV-24`).  
> **Plan Reviews Incorporated:** Plan Reviewer A (WP-1/2/3 — 4 P0s, 6 P1s, 3 P2s) and Plan Reviewer B (WP-4/5/6 — 5 P0s, 8 P1s, 5 P2s).  
> **Shared Prerequisite Pre-Committed Before Wave 1:** `backend/app/core/url_authority.py` (`has_disallowed_url_backslash`, `strip_single_trailing_dot`, `is_obfuscated_numeric_ip`, `is_strict_ldh_hostname`, `extract_strict_ascii_host`).

---

## Execution Waves & File Ownership (Zero Overlap Within Each Wave)

- **Wave 1 (4 parallel file-disjoint packages):**
  - **WP-1 (`NV-01`, `NV-03`, `NV-05`, `NV-06`, `NV-24`):** `backend/app/core/media_security.py` (new), `backend/app/core/security.py`, `backend/app/services/url_inspector.py`, `backend/app/services/local_stt.py`, `backend/app/services/ocr/rapidocr_provider.py`, `backend/app/services/ocr/gemini_provider.py`, `backend/app/services/llm_client.py` + unit tests (`test_local_media.py`, `test_security_wp1.py`).
  - **WP-2 (`NV-02`, `NV-09`, `NV-05`/`NV-08` sandbox half):** `backend/app/core/http_decompression.py` (new), `backend/app/services/phishing_detonator.py` + unit tests (`test_phishing_detonator_hardening.py`).
  - **WP-3 (`NV-07`, `NV-08`, `NV-11`, `NV-13`):** `deploy/Caddyfile`, `docker-compose.yml`, `docker-compose.prod.yml`, `deploy/.env.prod.example`, `backend/Dockerfile`, `frontend/Dockerfile`, `frontend/next.config.ts` + unit tests (`test_deploy_hardening.py`).
  - **WP-5 (`NV-16`, `NV-18`, `NV-21`, `NV-22`, `NV-05`/`NV-19` assistant halves):** `backend/app/services/assistant_guardrail_patterns.py` (new), `backend/app/services/assistant_guardrails.py`, `backend/app/services/assistant_vault_patterns.py` (new), `backend/app/services/assistant_vault.py`, `backend/app/services/assistant_context.py`, `backend/app/services/assistant_tools.py`, `backend/app/services/guardrails.py` + unit tests (`test_assistant_guardrails.py`, `test_assistant_vault_and_context.py`, `test_assistant_tools.py`, `test_security_wp5.py`).
- **Wave 2 (2 parallel file-disjoint packages after Wave 1 completes):**
  - **WP-4 (`NV-10`, `NV-12`, `NV-14`, `NV-15`, `NV-23`):** `backend/app/config.py`, `backend/app/core/case_tokens.py`, `backend/app/main.py`, `backend/app/api/v1/radar.py`, `backend/app/api/v1/analyze.py`, `backend/app/db/repository.py`, `backend/app/services/telegram_bot.py`, `backend/app/services/ioc_extractor.py`, `backend/app/services/pii_scrubber.py` (new) + updated/new tests (`test_case_tokens.py`, `test_radar_security_and_simulation.py`, `test_telegram_bot.py`, `test_security_wp4.py`).
  - **WP-6 (`NV-04`, `NV-17`, `NV-19`, `NV-20`, `NV-23`/`NV-24`/`NV-03`/`NV-06` pipeline halves):** `backend/app/services/image_forensics.py`, `backend/app/services/risk_calibrator.py`, `backend/app/services/receipt_validator.py`, `backend/app/services/assistant_evidence.py`, `backend/app/services/assistant_service.py`, `backend/app/services/report_pdf.py`, `backend/app/services/pipeline.py`, `backend/app/services/ai_orchestrator.py` + updated/new tests (`test_security_wp6.py`).

---

## Key Post-Review Technical Contracts

### WP-1 (`NV-01`, `NV-03`, `NV-05`, `NV-06`, `NV-24`)
1. **`security.py` (`NV-01`, `NV-05`):**
   - Import `url_authority` helpers in `_parse_url_authority`. Reject `has_disallowed_url_backslash(raw)` before `urlsplit`. Strip at most ONE trailing dot (`strip_single_trailing_dot`). Parse literal IPv4/IPv6 BEFORE IDNA (preserves public IPv6 like `[2606:4700:4700::1111]`). After IDNA encoding (`hostname.encode("idna").decode("ascii").lower()`), strip single trailing dot and RE-RUN internal hostname check (`localhost`, `.localhost`, `.local`, `.internal`), `is_obfuscated_numeric_ip(ascii_host)`, `ipaddress.ip_address(ascii_host)` + `is_public_ip`, AND `is_strict_ldh_hostname(ascii_host)`.
   - In `url_inspector.py`: if `has_disallowed_url_backslash(target_url)` is True, NEVER match `_is_official_domain` — return high-risk `90` with a specific backslash-spoofing Vietnamese reason (and preserve that reason in `inspect_url` instead of overwriting it with the generic internal-IP message!). Also validate post-IDNA host with `extract_strict_ascii_host` before `_is_official_domain`.
2. **`media_security.py` + `security.py` (`NV-03`, `NV-06`):**
   - Create `backend/app/core/media_security.py` (`< 240` lines, re-exported in `security.py`):
     - Add `"audio/flac"`, `"audio/x-flac"` to `_ALLOWED_AUDIO_MIMES`.
     - Fix `validate_upload_bytes` MIME check: if `declared_mime is not None`, strip and extract `clean_mime = declared_mime.split(";", 1)[0].strip().lower()`; reject if `not clean_mime or clean_mime not in allowed_mimes` (blocks `"; image/jpeg"` and `"   "`).
     - `detect_audio_format(data: bytes) -> tuple[str, str] | None`: magic allowlist for WAV (`RIFF....WAVE`), OGG (`OggS`), FLAC (`fLaC`), WebM/Matroska (`\x1a\x45\xdf\xa3`), MP4/M4A (`ftyp` at offset 4), MP3 (`ID3` or valid MPEG frame sync). Reject `#EXTM3U`, `ffconcat`, SDP, etc.
     - `_verify_decodable_audio(data)` + `decode_audio_to_pcm16k(data: bytes) -> np.ndarray`: open `av.open(io.BytesIO(data), mode="r", format=av_fmt, options={"protocol_whitelist": "crypto,data"})`; reject any non-`attached_pic` video stream (`any(not (s.disposition & av.stream.Disposition.attached_pic) for s in container.streams.video)`); require `>= 1` audio stream, `channels <= MAX_AUDIO_CHANNELS`; bound multi-channel samples (`total_channel_samples <= MAX_DECODED_AUDIO_SAMPLES * 2`); resample via `av.AudioResampler(format="s16", layout="mono", rate=16000)` -> 1D `np.float32` `pcm / 32768.0` for in-memory `WhisperModel.transcribe`!
     - Image validation: reject animated/multi-frame images (`getattr(decoded_img, "is_animated", False) or int(getattr(decoded_img, "n_frames", 1) or 1) > 1`). Export `detect_canonical_image_mime(data)` and `normalize_image_for_downstream(data) -> tuple[bytes, str]` (Pillow `exif_transpose` + `convert("RGB")` + re-encode canonical single-frame JPEG for JPEG inputs or PNG otherwise, stripping EXIF/polyglot tails).
   - `rapidocr_provider.py`: when `cv2.imdecode` returns `None`, fall back to Pillow `exif_transpose` -> RGB -> BGR numpy array so single-frame GIF/WebP decodes cleanly.
   - `llm_client.py` & `ocr/gemini_provider.py`: canonicalize every outgoing image via `normalize_image_for_downstream` (magic-derived MIME + stripped single-frame bytes), and canonicalize audio MIME via `detect_audio_format` in `llm_client.py` (`format="wav"/"mp3"/...`, never `"octet-stream"`).
3. **`local_stt.py` (`NV-24`, `NV-03`):**
   - Add `status: Literal["ok", "empty", "disabled", "unavailable", "error"] = "ok"` to `LocalSttResult`.
   - Decode audio strictly in memory via `decode_audio_to_pcm16k(audio_bytes)` (zero `tempfile.NamedTemporaryFile`, ignores untrusted `filename` suffix, closes second unrestricted `av.open` sink, avoids `av==19.0.2` `metadata_errors` crash!).
   - Pass the 1D `np.float32` array directly to `model.transcribe(pcm_f32, language="vi", beam_size=1, vad_filter=True)`.
   - Distinguish `disabled`, `unavailable` (model load error), `error` (decode/transcribe exception), `empty` (`available=True, transcript=""`), `ok`.
   - Update `backend/tests/unit/test_local_media.py:55-73` to use real minimal WAV bytes and assert in-memory `np.ndarray` input (zero temp files).

### WP-2 (`NV-02`, `NV-09`, `NV-05`/`NV-08` sandbox half)
1. **`backend/app/core/http_decompression.py` (`< 140` lines, `NV-09`):**
   - `read_bounded_http_body(resp: httpx.Response, max_body_bytes: int, max_wire_bytes: int | None = None) -> bytes`:
     - Reject stacked encodings (`"," in content_encoding`) or unsupported encodings outside `("", "identity", "gzip", "x-gzip", "deflate")`.
     - If `resp.is_stream_consumed` and `hasattr(resp, "_content")` (preserves `httpx.MockTransport` pre-buffered mocks like `test_codex_audit_regressions.py:671`!): read `resp.content[:max_body_bytes + 1]`, enforce cap.
     - Otherwise stream `resp.aiter_raw(chunk_size=16384)`: enforce `wire_bytes <= max_wire_bytes`; for `gzip`/`x-gzip`/`deflate`, incrementally decompress with `zlib.decompressobj` (`16 + MAX_WBITS` for gzip; `MAX_WBITS` with one-time `-MAX_WBITS` fallback on first-chunk `zlib.error` for raw RFC 1951 deflate), checking `max_length=remaining + 1`, `dec.unconsumed_tail`, and `dec.flush()` against `max_body_bytes`.
2. **`backend/app/services/phishing_detonator.py` (`NV-02`, `NV-05`, `NV-08`, `NV-09`):**
   - `_sanitized_chromium_env() -> dict[str, str]`: portable allowlist (Linux: `PATH`, `HOME=/tmp`, `TMPDIR=/tmp`, `XDG_CACHE_HOME=/tmp`, `XDG_CONFIG_HOME=/tmp`, `PLAYWRIGHT_BROWSERS_PATH`, `LANG`, `LC_ALL`, `TZ`; Windows `os.name == "nt"`: `SYSTEMROOT`, `COMSPEC`, `TEMP`, `TMP`, `LOCALAPPDATA`, `USERPROFILE`, `PATH`, `PLAYWRIGHT_BROWSERS_PATH`). Pass `env=_sanitized_chromium_env()` to `pw.chromium.launch(...)`.
   - Chromium args: add `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, `--disable-features=WebTransport`, `--disable-blink-features=WebTransport`, `--proxy-server=http://127.0.0.1:9`, `--proxy-bypass-list=<-loopback>`.
   - `_DISABLE_DIRECT_BROWSER_EGRESS_JS`: wrap each `Object.defineProperty` in `try { ... } catch (_) {}` blocking `WebSocket`, `EventSource`, `RTCPeerConnection`, `webkitRTCPeerConnection`, `mozRTCPeerConnection`, `WebTransport`, `Worker`, `SharedWorker`, `navigator.sendBeacon`.
   - `_pinned_proxy_route`: allow `route.continue_()` ONLY for `req_url == "about:blank"` and raster `data:image/(png|jpeg|jpg|webp|gif);` (abort `blob:`, `data:image/svg`, `about:srcdoc`, `resource_type in ("worker", "shared_worker", "websocket", "eventsource")`). Track per-session `subrequest_count <= 24` and `total_bytes <= 4_000_000`.
   - `_fetch_via_pinned_client`: preserve exact 4-arg call signature & 4-tuple return; send `Accept-Encoding: identity`; read body via `read_bounded_http_body`; strip `content-security-policy`, `content-security-policy-report-only`, `report-to`, `reporting-endpoints`, `nel` headers; inject `Content-Security-Policy: worker-src 'none'; child-src 'none'; object-src 'none'` on fulfilled HTML responses.
   - `inspect_rendered_dom`: check `has_disallowed_url_backslash` and `extract_strict_ascii_host` on both `visited_url` and `effective_url` before `_host_matches_official` (`NV-05`).

### WP-3 (`NV-07`, `NV-08`, `NV-11`, `NV-13`)
1. **`deploy/Caddyfile` (`NV-07`):**
   - Place raw-URI encoded-separator guard **before** `handle /api/*`:
     ```caddyfile
     @encoded_path_sep expression `{http.request.orig_uri}.split('?')[0].lowerAscii().contains('%2f') || {http.request.orig_uri}.split('?')[0].lowerAscii().contains('%5c') || {http.request.orig_uri}.split('?')[0].contains('\\')`
     handle @encoded_path_sep {
         respond "Bad Request" 400
     }
     ```
   - Remove site-wide `request_body { max_size 22MB }`; place `request_body { max_size 22MB }` strictly inside `handle /api/*` and `request_body { max_size 1MB }` inside `handle` (`frontend:3000`).
2. **`frontend/next.config.ts` & `frontend/Dockerfile` (`NV-07`, `NV-08`):**
   - In `frontend/next.config.ts`: add `images: { unoptimized: true }` and gate `rewrites()` on `process.env.ENABLE_NEXT_API_PROXY !== "false"` (local dev / `npm run build` unchanged; production Docker disables it cleanly!).
   - In `frontend/Dockerfile`: accept `ARG ENABLE_NEXT_API_PROXY=false` + `ENV ENABLE_NEXT_API_PROXY=${ENABLE_NEXT_API_PROXY}` in `builder` before `npm run build`; remove hardcoded `BACKEND_INTERNAL_URL=http://backend:8000` from `runner`; pre-create `/app/.next/cache` owned by `nextjs:nodejs`.
3. **`backend/Dockerfile` (`NV-13`):**
   - Default `ENV UVICORN_FORWARDED_ALLOW_IPS=""` and branch cleanly in `CMD`:
     `if [ -n "${UVICORN_FORWARDED_ALLOW_IPS:-}" ]; then exec uvicorn ... --proxy-headers "--forwarded-allow-ips=${UVICORN_FORWARDED_ALLOW_IPS}"; else exec uvicorn ... --no-proxy-headers; fi`.
4. **`docker-compose.yml`, `docker-compose.prod.yml`, `deploy/.env.prod.example` (`NV-07`, `NV-08`, `NV-11`, `NV-13`):**
   - `docker-compose.yml`: bind `"127.0.0.1:8000:8000"` and `"127.0.0.1:3000:3000"`; forward `CASE_TOKEN_SECRET`, `ONNX_INTRA_THREADS`, `UVICORN_FORWARDED_ALLOW_IPS=${UVICORN_FORWARDED_ALLOW_IPS:-}`; pass `ENABLE_NEXT_API_PROXY: "true"` build arg to `frontend`.
   - `docker-compose.prod.yml`:
     - `backend`: `env_file: !override []`, `read_only: true`, `tmpfs: ["/tmp:rw,noexec,nosuid,mode=1777,size=256m"]`, env `HOME=/tmp`, `TMPDIR=/tmp`, `XDG_CACHE_HOME=/tmp`, `XDG_CONFIG_HOME=/tmp`, required `IOC_HMAC_SECRET=${IOC_HMAC_SECRET:?...}` & `CASE_TOKEN_SECRET=${CASE_TOKEN_SECRET:?...}`, `ONNX_INTRA_THREADS=${ONNX_INTRA_THREADS:-2}`, `UVICORN_FORWARDED_ALLOW_IPS=${UVICORN_FORWARDED_ALLOW_IPS:-172.28.0.0/24}`, `networks: [proxy_backend]` (with note documenting `PLAYWRIGHT_CHROMIUM_SANDBOX=false` residual tradeoff mitigated by scrubbed env + RO rootfs + blackhole proxy + isolated networks).
     - `frontend`: `build: { args: { ENABLE_NEXT_API_PROXY: "false", NEXT_PUBLIC_APP_ENV: ${APP_ENV:-production} } }`, `environment: [ENABLE_NEXT_API_PROXY=false, BACKEND_INTERNAL_URL=]`, `read_only: true`, `tmpfs: ["/tmp:rw,noexec,nosuid,mode=1777,size=64m", "/app/.next/cache:rw,noexec,nosuid,nodev,size=32m,uid=1001,gid=1001"]`, `networks: [proxy_frontend]`.
     - `caddy`: `networks: [proxy_backend, proxy_frontend]`.
     - Networks: `proxy_backend` with IPAM subnet `${PROXY_BACKEND_SUBNET:-172.28.0.0/24}`; `proxy_frontend` with `internal: true`.

### WP-4 (`NV-10`, `NV-12`, `NV-14`, `NV-15`, `NV-23`)
1. **`config.py`, `case_tokens.py`, `main.py` (`NV-10`):**
   - `config.py`: in `APP_ENV=production`, require explicit `IOC_HMAC_SECRET` (`>= 16` chars, `!= pin`), explicit `CASE_TOKEN_SECRET` (`>= 32` chars, `!= pin`, `!= hmac_secret`), and validate `TELEGRAM_WEBHOOK_SECRET` (placeholder/length `>= 24` chars, `!= pin` whenever non-empty; mandatory in `production` when `TELEGRAM_BOT_TOKEN` is set). Remove `SHA-256(ANALYST_PIN)` derivation from `resolved_ioc_hmac_secret` completely (return `self.ioc_hmac_secret.strip()` only).
   - `case_tokens.py`: in `APP_ENV=production`, require explicit `CASE_TOKEN_SECRET` (`>= 32` chars); remove fallback deriving from `IOC_HMAC_SECRET`.
   - `main.py:264-268`: fail closed (`ValueError`) if `cfg.app_env == "production" and not cfg.resolved_ioc_hmac_secret`.
   - Update affected production tests in `test_case_tokens.py` and `test_radar_security_and_simulation.py`.
2. **`repository.py` + `telegram_bot.py` (`NV-12`):**
   - Add `chat_id TEXT`, `sender_user_id TEXT`, `chat_type TEXT`, `update_kind TEXT NOT NULL DEFAULT 'message'` columns (with idempotent `ALTER TABLE` migrations in `init_db`) to `telegram_updates`.
   - In `claim_telegram_update`: compare `(stored_chat, stored_sender, stored_chat_type, stored_kind) == (in_chat, in_sender, in_chat_type, update_kind)` on `completed`, `in_progress`, AND expired-lease reclaim paths — return `("mismatch", None, None)` on mismatch! Preserve metadata columns in `save_telegram_update_cache` when `owner_id is None`.
   - In `telegram_bot.py`:
     - Handle `claim_state == "mismatch"` in BOTH `_handle_telegram_pdf_callback` (`{"ok": True, "delivered": False, "pdf_sent": False, "ignored": True}`) AND `handle_telegram_update` (`{"ok": True, "delivered": False, "ignored": True}`).
     - In `handle_telegram_update`: if `env.chat_id is None` and `claim_state == "cached"`, treat as `"mismatch"`. Replace `get_report(cached_case_id)` with `get_report_with_owner(cached_case_id)` verifying `owner_channel` and `owner_chat_hash`. When `token` is set OR `env.chat_id is None`, omit `reply_text` from the HTTP 200 webhook JSON (and omit `case_id`/`verdict`/`risk_score` when `env.chat_id is None`).
     - Update the 5 `test_telegram_bot.py` tests asserting `res["reply_text"]` under non-empty token to inspect captured `sendMessage["text"]` and assert `"reply_text" not in res`.
3. **`analyze.py`, `ioc_extractor.py`, `repository.py` (`NV-14`, `NV-03`):**
   - `analyze.py`: add `expected_merchant_account` to `_prepare_inputs`; reject `len(text) > 8_000`, `len(url) > 2_048`, `len(expected_merchant_account) > 64` with `HTTP 400`; offload `validate_upload_bytes` via `await asyncio.to_thread(...)`.
   - `ioc_extractor.py`: prepend `extra_urls` BEFORE text-extracted URLs prior to applying `MAX_EXTRACTED_URLS = 8` / `MAX_EXTRACTED_DOMAINS = 8`; cap `phones[:8]`, `bank_accounts[:8]`.
   - `repository.py`: cap `_expand_domain_candidates` to max 4 parent levels per domain and dedupe + cap `count_ioc_hits` & `match_active_block_rules` to `MAX_LOOKUP_IOC_HASHES = 24`.
4. **`radar.py` + `repository.py` (`NV-15`):**
   - `radar.py`: validate `rule_id` against `^rule_[0-9a-f]{10}$`; pass `safe_rule_id` (or `None`) to `record_audit_log`, logger, and DB calls (skip DB lookup when `safe_rule_id is None`).
   - `repository.py`: sanitize `rule_id` inside `record_audit_log`; partition retention (`200` non-`auth_failed` + `50` `auth_failed`); cleanup invalid `rule_id` rows in `init_db`; in `get_radar_graph`, fetch up to 5 `auth_failed` + fill remaining slots up to 20 with non-`auth_failed`, sorted by `created_at DESC`.
5. **`pii_scrubber.py` (new `< 160` lines) + `repository.py` (`NV-23`):**
   - `scrub_persisted_pii(text, known_phones=None, known_accounts=None)`: strip `_INVIS_RE`, redact URL userinfo (`https://user:pass@` -> `https://[CRED_REDACTED]@`) BEFORE email redaction, redact `known_phones` & case/separator-insensitive alphanumeric `known_accounts` (len `>= 6`), redact emails, OTP/PIN/CVV/passwords, 16-digit cards, labeled & 0-prefixed dot-grouped CCCDs (`0(?:0[1-9]|[1-8]\d|9[0-6])(?:\.\d{3}){3}`), URL-encoded digit sequences (`%30`..`%39`), then `scrub_free_text_pii` — strictly idempotent.
   - Use in `redact_report_pii` AND in `init_db` (replacing stale `vs_tg_*` inside `telegram_updates.reply_text` during rotation, then scrubbing all `reply_text` rows).
   - Hash receipt reference fingerprints in `repository.py` via `f"ref_h:{self.hash_ioc_value('receipt_ref', f'{(bank or \"\").strip()}:{ref_code.strip()}')}"` across `claim_receipt_replay`, `is_receipt_replayed`, `save_report`, `save_staged_report` (normalizing legacy `ref:` defensively), and `init_db` migration of legacy `ref:...` rows.

### WP-5 (`NV-16`, `NV-18`, `NV-21`, `NV-22`, `NV-05`/`NV-19` assistant halves)
*(Mandatory modularity extraction: `assistant_guardrail_patterns.py` + `assistant_vault_patterns.py` so every file stays `< 280` lines!)*
1. **`assistant_guardrail_patterns.py` + `assistant_guardrails.py` (`NV-16`, `NV-18`, `NV-19`):**
   - `NV-16`: Remove `"can"`, `"cho"`, `"them"`, `"nua"`, `"thao"`, `"tac"`, `"doi"`, `"giao"`, `"dich"`, `"ngay"`, `"lap"`, `"tuc"` from `_NEG_BRIDGE`; forbid `"phai"` before `"xac"` (`khong phai xac minh/nhan`) and forbid `"xac"`/`"minh"`/`"nhan"` from negating `_HANDOVER_RE` or `_ABS_SAFE_RE`. In `_settle_ok`, reject `(txt.startswith("tien ") and lp.rstrip().endswith(pre))` when `re.search(r"\b(?:da|vua|moi)\s+(?:chuyen|nop|gui|nhan)$", slp)` (excluding `"da lo"`/`"vua lo"`) OR `re.search(r"\bkhach(?:\s+hang)?\b", slp)` OR `re.match(r"^(?:roi|thanh cong|xong)\b", sls)` (verified 0 FPs across all 121 KB chunks!).
   - `NV-18`: Normalize with NFKC inside `_extract_hotlines`; strip 1–3 `*`/`_` with digit lookaround `(?<!\*)(?:(?<!\d)\*{1,3}|\*{1,3}(?!\d))(?!\*)|(?<!_)_{1,3}(?!_)` (preserving `****` and `***` masks between digits); expand `_S`/`_HOTLINE_RE` for `/`, `(1900)`/`(1800)`, and unprefixed `84(?:0)?[35789]|84(?:0)?2\d` normalized via `d.startswith("84") and len(d) in (11, 12)`; remove BOTH colon-skip checks at lines 169–170.
   - `NV-19` (anti-recursion): Export pure non-recursive `check_policy_violations(text: str, *, rag_chunks: list[RetrievedChunk]) -> list[str]` (clause + hotline checks only, NO `_fallback_for`, NO `balance_check`/`epistemic_limit`). Use it in `build_tier0_deterministic_reply` (cap `[:180]`, drop unsafe reasons) and `build_degraded_rag_reply` (screen/cap `summary_vi`).
2. **`assistant_vault_patterns.py` + `assistant_vault.py` (`NV-21`, `NV-22`):**
   - Replace `:\d{1,6}` with `:\d+` in `_PROTO_REL_RE`, `_BARE_IP_RE`, `_URL_SYNTAX_RE` and allow `[/?#]` on `_BARE_IP_RE`.
   - Allow Unicode `[^\W_]` in non-TLD labels of `_HOST` and `_EMAIL_RE` while keeping the TLD ASCII/Punycode `(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})` (zero Vietnamese prose FPs!). IDNA-encode Unicode hosts in `_dns_labels`, require `host.isascii()` before `keep_official`, and fail closed to `_emit(tok, "https://", redact_only=True)` on `_URL_SYNTAX_RE` matches with `has_auth` or `has_sfx` whose IDNA fails.
3. **`assistant_context.py`, `assistant_tools.py`, `guardrails.py` (`NV-05`, `NV-19`, `NV-22`):**
   - `assistant_context.py`: move `manipulation_tactics` and `raw_reasons` (`url_findings.reasons`, `image_forensics.reasons`, `receipt_logic.reasons`) OUT of `_build_system_case_facts` (`[SYSTEM_CASE_FACTS]`) INTO `_build_case_excerpts` inside `<UNTRUSTED_USER_CONTENT>`, and mask `Tên miền '...'` in `url_findings.reasons` (like `assistant_tools.py:114`).
   - `guardrails.py`: use `extract_strict_ascii_host` in `_has_non_official_url` (return `True` on `None`, vetoing advisory on backslash/non-LDH URLs).
   - `assistant_tools.py`: enforce `has_disallowed_url_backslash` + `extract_strict_ascii_host` inside BOTH `_host()` AND `_is_off(h)` AND check `ent.raw_value`/`f.final_url` directly inside `_run_url`.

### WP-6 (`NV-04`, `NV-17`, `NV-19`, `NV-20`, `NV-23`/`NV-24`/`NV-03`/`NV-06` pipeline halves)
1. **`image_forensics.py` (`NV-19`, `NV-06`):**
   - Remove EXIF `0x013B` (Artist PII). Match `_EDITING_SIGNATURES` against `exif.get(0x0131)` (`[:256]`), `img.info["Software"]`/`"Creator"` (`[:256]`), `img.info["XML:com.adobe.xmp"]` (`[:4096]`), and `raw_bytes[:16384]`; return ONLY fixed canonical allowlist label (`_EDITING_LABELS[sig]`, e.g. `"Photoshop"`, `"Paint.NET"`) or `(None, False)` — zero raw EXIF text ever persisted or returned!
   - Add Pillow RGB->BGR fallback in `decode_qr_codes` when `cv2.imdecode` returns `None` (`NV-06`).
2. **`risk_calibrator.py` & `receipt_validator.py` (`NV-17`, `NV-24`):**
   - `risk_calibrator.py`: remove `mode == "merchant"` gate on `has_qr_beneficiary_mismatch`; set `receipt_status = "TAMPER_OR_LOGIC_ANOMALY"` when `has_visual_bill_anomaly=True` even outside `mode='merchant'`; add `stt_failed: bool = False`, `stt_unreadable_audio_only: bool = False` mirroring `ocr_incomplete_without_vision` (both in `advisory_overridden_by_signals` AND cautious floor `32`/`30` + `confidence <= 0.45`).
   - `receipt_validator.py`: iterate ALL matches via `EXPLICIT_RECIPIENT_SPAN_RE.finditer(cleaned)` (skip currency-followed spans; keep `len(candidate_digits) >= 6` for mismatch check, cap `extracted_recipient_account` at `<= 19`, add `risk += 75` at most once across multiple mismatched spans).
3. **`pipeline.py`, `ai_orchestrator.py`, `assistant_evidence.py`, `assistant_service.py`, `report_pdf.py` (`NV-03`, `NV-04`, `NV-06`, `NV-14`, `NV-19`, `NV-20`, `NV-23`, `NV-24`):**
   - `pipeline.py`:
     - Offload `_resolve_media_lists` via `await asyncio.to_thread(self._resolve_media_lists, ...)` and replace image `mime` with `detect_canonical_image_mime(raw_b)` (`NV-03`, `NV-06`).
     - Track `stt_failed` / `stt_unreadable_audio_only` from `LocalSttResult.status` and `TimeoutError`; append warning `EvidenceItem`, set `media_step.status = "warning"`, pass to `calibrate_risk` and `run_gemini_reasoning(..., stt_incomplete=...)` (`NV-24`).
     - Split URL provenance strictly on user `text` + explicit `url` ONLY (`user_direct_extra_urls = [url] if url and url.strip() else []`) so OCR, QR (`URL_QR`/`TEXT_QR`), and STT URLs ALL remain static-only (`NV-04`).
     - Disable live `inspect_url` network probing for ALL `persistence_mode == "ephemeral_private"` requests (even when `allow_external_media_ai=True`) and pass `sanitize_egress_text=(persistence_mode == "ephemeral_private")` to `run_gemini_reasoning` (`NV-20`).
     - Return `comm_hits = 0` when `is_simulation=True` (`NV-14`).
     - Convert `_build_replay_fingerprints` to instance method emitting `f"ref_h:{self.repo.hash_ioc_value('receipt_ref', f'{bank_lbl}:{receipt_logic.reference_code}')}"` (`NV-23`).
   - `ai_orchestrator.py`: accept `sanitize_egress_text: bool = False` (scrubbing `user_text` and `tier1_notes` via `sanitize_llm_egress_text(..., preserve_official_bare_domains=False, preserve_strict_vault_refs=False)` before `build_isolated_prompt`) and `stt_incomplete: bool = False` (cautious offline fallback wording).
   - `assistant_evidence.py`: offload `validate_upload_bytes` via `await asyncio.to_thread(...)`; cap and filter highlights in `build_local_evidence_explanation` via `ag.check_policy_violations` (`NV-19`, `< 280` lines).
   - `assistant_service.py`: include `*(rep.manipulation_tactics[:4])` in `_has_indirect_or_forged_injection` (`NV-19`, keeping `< 280` lines).
   - `report_pdf.py:173`: cap `ev.detail[:300]` for defense-in-depth on legacy rows (`NV-19`).
