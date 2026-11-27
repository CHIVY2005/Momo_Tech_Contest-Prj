# VeriShield AI Assistant ("Trợ lý VeriShield") Implementation Plan (Reviewed & Hardened)

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build **"Trợ lý VeriShield"** — a Context-Aware Fraud Prevention Assistant combining unified case access control (Phase 0), Hybrid E5 INT8 ONNX + BM25 RAG, `RequestEntityVault` + outbound egress sanitization, 3-Tier Pre-Emission Output Safety Gate, dual-protocol streaming with `<think>` filtering, Side Drawer UI (Phase 1 MVP), controlled ref-only verification tools (Phase 2), and local-only-by-default ephemeral supplementary evidence analysis with explicit user persist (Phase 3), followed by `/privacy` & `/technical` synchronization.

**Architecture:** Zero LangChain and zero external Vector DB. Reuses the already-loaded Dual-Head `scam_e5_int8.onnx` session (`predict_and_encode`), NumPy `E_raw` -> startup `E_centered` + Vietnamese accent-insensitive BM25 + RRF, existing `google-genai` + `httpx` CPA dual-protocol transport (Router-Gated Hybrid Transport), existing `consumeUtf8SseStream` SSE infrastructure, and existing `AnalysisPipeline` / `VietQR` / `url_inspector` / `CaseRepository` primitives.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, SQLite WAL, ONNX Runtime (`enable_cpu_mem_arena=False`), `tokenizers`, NumPy, `google-genai`, `httpx`, Next.js 15, React 19, TypeScript (strict), Tailwind CSS v4, `lucide-react`.

**Spec:** [AI_ASSISTANT_RESEARCH.md](file:///D:/Misc/momo-tech-contest-prj/AI_ASSISTANT_RESEARCH.md) (v3) and [AGENTS.md](file:///D:/Misc/momo-tech-contest-prj/AGENTS.md).

---

## Global Constraints

- **Zero Trademark Infringement (`AGENTS.md` Rule 1):** Product/brand/UI strings MUST ONLY use `VeriShield AI` and `Trợ lý VeriShield` — never `"MoMo"`.
- **Zero New Heavy Dependencies (`AGENTS.md` Rules 2, 4):** Do NOT add `torch`, `transformers`, LangChain, Chroma/Qdrant, or non-permissive packages to `backend/requirements.txt` or `frontend/package.json`. Total Git model/index artifacts MUST stay `< 50 MB`.
- **100% Synthetic / Public-Advisory Data (`AGENTS.md` Rule 3):** All new KB SOPs, verification guides, and evaluation datasets MUST be 100% synthetic/public-advisory with zero real PII and zero unverified hotline numbers.
- **Merchant Receipt Honesty & No Absolute Safety (`AGENTS.md` Rule 5):** Assistant MUST NEVER stream unverified receipt/settlement/absolute-safety replies and MUST NEVER confirm funds arrived from a screenshot or declare any transaction "chắc chắn an toàn".
- **Mandatory Outer `<UNTRUSTED_USER_CONTENT>` Tag (`AGENTS.md` Rule 6):** Every LLM prompt wraps all untrusted evidence excerpts, flattened client history (both `user` and `assistant`), and current user message inside exactly ONE `<UNTRUSTED_USER_CONTENT>...</UNTRUSTED_USER_CONTENT>` block.
- **Single Outbound Egress Chokepoint:** `sanitize_llm_egress_text()` runs across all 4 input paths (`message`, `history`, `CASE_EVIDENCE_EXCERPTS`, `tool_output`) AND as a final chokepoint right before wire serialization in BOTH `google_genai` and `openai_compatible` adapters (with `preserve_official_bare_domains=True` ONLY outside `<UNTRUSTED_USER_CONTENT>` and strict masked-preview grammar for vault ref tokens).
- **Modularity & Strict Typing (`AGENTS.md` §3):** Keep each new backend service module `< 280` lines with 1-to-1 unit tests in `backend/tests/unit/`. Pass `ruff`, `mypy --strict`, `pytest`, `tsc --noEmit`, `npm test`, `next build` (`scripts/verify.ps1`).
- **Node `--test` TS Stripping Compatibility:** Any pure TS file under `frontend/src/lib/` imported by `node --test` MUST have zero JSX and MUST use explicit `.ts` extensions on relative value imports (`import type` omits `.ts`).
- **Preserve Uncommitted Docs Refinements:** Working tree contains refined `/privacy` and `/technical` pages and SVGs; extend them cleanly in Task 11 without reverting existing refinements.
- **No Unprompted Push/Deploy:** Do not push to GitHub or deploy to VPS unless explicitly requested.

## Review Focus

1. **Telegram group-chat PDF bypass & callback pre-ack:** Pressing `callback_data="pdf:{case_id}"` from a `group`, `supergroup`, `channel`, missing `chat.type`, or wrong `cb["from"]["id"]` MUST fail closed via `answerCallbackQuery(show_alert=True)` BEFORE any generic ack or `sendMessage`, with zero `sendDocument` calls (Task 2).
2. **Legacy & cross-channel case IDOR:** Calling `GET /api/v1/cases/{case_id}`, `/report.pdf`, or `/assistant/*` with missing/expired/mismatched `X-Case-Access-Token`, or against `legacy_locked` / `telegram_private` / `telegram_group_locked` cases MUST return `HTTP 403` without revealing existence, with `Cache-Control: no-store` & `Vary: X-Case-Access-Token` (Tasks 1, 2, 7, 9, 10).
3. **Outbound wire leakage & IPv6 SSRF URLs:** Raw URL, IPv6 URL (`http://[::ffff:127.0.0.1]/`), integer IP (`http://2130706433/`), defanged URL, raw VietQR, email, CCCD, 16-digit card, or OTP in `message`, `history[]`, `CASE_EVIDENCE_EXCERPTS`, or `tool_output` MUST be redacted on BOTH `google_genai` and `openai_compatible` wire payloads while preserving bare official domains inside `[GROUNDED_KB_CONTEXT]` (Tasks 5, 7, 9).
4. **Tier-2 long incomplete sentence & decimal/domain split:** A 200+ char single sentence without punctuation MUST NOT flush at char 160 — it keeps the entire buffer and promotes to Tier 1 validating `emitted_prefix + buffered_remainder`; periods inside `15.000.000`, `1. `, `.apk`, or `vneid.gov.vn` MUST NOT split sentences (Task 6).
5. **Phase-3 silent media egress, middleware 256 KB cap, & replay blindness:** Uploading an image/audio (`> 256 KB` and `<= 10 MB`) to `POST /api/v1/assistant/chat/evidence/stream` with default `allow_external_media_ai=False` MUST pass middleware size guard, execute **0** calls to Gemini Vision AND **0** calls to Gemini OCR fallback, write **0** rows to all 5 SQLite tables, STILL detect known replayed receipts via `repo.is_receipt_replayed()`, and compute pre-hashed IOCs + raw replay fingerprints BEFORE `redact_report_pii()` (Task 10).

---

## File Map

| Phase | New Files | Modified Files |
| --- | --- | --- |
| **Phase 0** | `backend/app/core/case_tokens.py`<br>`backend/tests/unit/test_case_tokens.py` | `backend/app/config.py`, `deploy/.env.prod.example`, `backend/app/db/repository.py`, `backend/app/services/pipeline.py`, `backend/app/services/scam_classifier.py`, `backend/app/main.py`, `backend/app/api/v1/cases.py`, `backend/app/api/v1/analyze.py`, `backend/app/api/v1/telegram.py`, `backend/app/services/telegram_formatting.py`, `backend/app/services/telegram_media.py`, `backend/app/services/telegram_bot.py`, `scripts/smoke_test_live.py`, `backend/tests/integration/test_api_routes.py`, `backend/tests/unit/test_telegram_bot.py`, `frontend/src/lib/types.ts`, `frontend/src/lib/api.ts`, `frontend/src/components/copilot/ActionCopilotPanel.tsx`, `frontend/src/app/page.tsx`, `frontend/src/lib/__tests__/auditRegressions.test.ts` |
| **Phase 1** | `backend/app/data/kb/incident_response_sops.json`<br>`backend/app/data/kb/verification_guides.json`<br>`scripts/build_assistant_kb_index.py`<br>`backend/app/data/models/assistant_kb_embeddings.npy`<br>`backend/app/data/models/assistant_kb_index.json`<br>`evaluation/assistant_eval/assistant_eval_cases.json`<br>`evaluation/assistant_eval/run_rag_ablation.py`<br>`backend/app/schemas/assistant.py`<br>`backend/app/services/assistant_rag.py`<br>`backend/app/services/assistant_vault.py`<br>`backend/app/services/assistant_context.py`<br>`backend/app/services/assistant_guardrails.py`<br>`backend/app/services/assistant_llm.py`<br>`backend/app/services/assistant_service.py`<br>`backend/app/api/v1/assistant.py`<br>`scripts/verify_assistant_llm.py`<br>`backend/tests/unit/test_assistant_rag.py`<br>`backend/tests/unit/test_assistant_vault_and_context.py`<br>`backend/tests/unit/test_assistant_guardrails.py`<br>`backend/tests/unit/test_assistant_llm_and_stream.py`<br>`backend/tests/integration/test_assistant_stream_api.py`<br>`frontend/src/lib/safeMarkdown.ts`<br>`frontend/src/components/assistant/SafeMarkdown.tsx`<br>`frontend/src/components/assistant/AssistantQuickActions.tsx`<br>`frontend/src/components/assistant/AssistantMessageItem.tsx`<br>`frontend/src/components/assistant/AssistantDrawer.tsx`<br>`frontend/src/lib/__tests__/assistantClient.test.ts` | `backend/app/services/knowledge_base.py`, `backend/app/services/guardrails.py`, `backend/app/api/v1/router.py`, `backend/app/main.py`, `frontend/src/lib/types.ts`, `frontend/src/lib/api.ts`, `frontend/src/components/workbench/VerdictDashboard.tsx`, `frontend/src/app/page.tsx`, `frontend/package.json` |
| **Phase 2** | `backend/app/services/assistant_tools.py`<br>`backend/tests/unit/test_assistant_tools.py`<br>`backend/tests/integration/test_assistant_redteam.py` | `backend/app/services/assistant_service.py`, `frontend/src/components/assistant/AssistantMessageItem.tsx`, `frontend/src/components/assistant/AssistantDrawer.tsx` |
| **Phase 3** | `backend/app/services/assistant_evidence.py`<br>`backend/tests/integration/test_assistant_evidence.py`<br>`frontend/src/components/assistant/AssistantEvidenceCard.tsx` | `backend/app/services/ocr/service.py`, `backend/app/services/pipeline.py`, `backend/app/services/ai_orchestrator.py`, `backend/app/db/repository.py`, `backend/app/api/v1/assistant.py`, `backend/app/main.py`, `frontend/src/lib/types.ts`, `frontend/src/lib/api.ts`, `frontend/src/components/assistant/AssistantDrawer.tsx` |
| **Docs Sync** | — | `frontend/src/app/privacy/page.tsx`, `frontend/src/components/docs/DataLifecycleSvg.tsx`, `frontend/src/app/technical/page.tsx`, `frontend/src/components/docs/SystemArchitectureSvg.tsx` |

---

## Phase 0 — Unified Case Access Control & E5 Encode Foundation

### Task 1: 128-bit `case_id`, HMAC `case_tokens.py`, DB Channel/Demo Columns, & `ScamClassifier.encode_text` / `predict_and_encode`

**Files:**
- Create: `backend/app/core/case_tokens.py`
- Modify: `backend/app/config.py`, `deploy/.env.prod.example`, `backend/app/db/repository.py`, `backend/app/services/pipeline.py`, `backend/app/services/scam_classifier.py`, `backend/app/main.py`
- Test: `backend/tests/unit/test_case_tokens.py`

**Interfaces:**
- Produces (`backend/app/core/case_tokens.py`, `< 150` lines):
  - `CaseOwnerChannel = Literal["web_token", "telegram_private", "telegram_group_locked", "legacy_locked"]`
  - `generate_case_id() -> str` (`f"vs_{secrets.token_hex(16)}"`, 35 chars)
  - `resolve_case_token_secret(settings: Settings) -> str`:
    - Reads `settings.case_token_secret.strip()` first; if unset in `production`, derives domain-separated `HMAC-SHA256(explicit_ioc_hmac, b"verishield-case-token-v1")` ONLY from **explicit** `settings.ioc_hmac_secret.strip()` (NEVER `settings.resolved_ioc_hmac_secret`!), raising `ValueError` in `production` if neither is configured.
    - In `demo`/`development` when unset, returns a fresh 256-bit `secrets.token_hex(32)` (NEVER `""` or `"2026"`).
  - `issue_case_access_token(case_id: str, secret: str, *, ttl_seconds: int = 7200, parent_case_id: str | None = None, now: int | None = None) -> tuple[str, str]`
  - `verify_case_access_token(token: str | None, expected_case_id: str, secret: str, *, now: int | None = None) -> dict[str, Any] | None` (`hmac.compare_digest`, checks `v == 1`, `cid == expected_case_id`, `scope == "case_access"`, `exp > now`)
  - `hash_telegram_private_owner(chat_id: int | str, sender_user_id: int | str, secret: str) -> str`
- Produces (`backend/app/config.py`):
  - `case_token_secret: str = ""`, `onnx_intra_threads: int = Field(default=2, ge=1, le=8)`, `assistant_rate_limit_per_minute: int = Field(default=12, ge=1)`, `assistant_rate_limit_per_hour: int = Field(default=60, ge=1)`
  - Remove early `return self` at `config.py:98` so placeholder/`"2026"` checks on `ioc_hmac_secret` and `case_token_secret` ALWAYS run in every `app_env`, while allowing empty `case_token_secret` in `production` when explicit `ioc_hmac_secret` (>= 16 chars) is set (preserves `test_radar_security_and_simulation.py:68`).
- Produces (`backend/app/db/repository.py`):
  - `@dataclass(frozen=True, slots=True) class StoredCaseRecord`: `report: AnalysisReport`, `owner_channel: CaseOwnerChannel`, `owner_chat_hash: str | None`, `is_demo: bool`, `parent_case_id: str | None`
  - `ALTER TABLE cases` migrations: `owner_channel TEXT NOT NULL DEFAULT 'legacy_locked'`, `owner_chat_hash TEXT`, `parent_case_id TEXT`, `contributes_to_radar INTEGER NOT NULL DEFAULT 1`, `is_demo INTEGER NOT NULL DEFAULT 0`
  - `save_report(..., owner_channel: CaseOwnerChannel = "web_token", owner_chat_hash: str | None = None, parent_case_id: str | None = None, contributes_to_radar: bool = True, is_demo: bool = False) -> AnalysisReport` (gates `ioc_sightings`/`ioc_edges`/`campaigns` writes on `if not already_saved and contributes_to_radar and report.risk_score >= 45`)
  - `get_report_with_owner(case_id: str) -> StoredCaseRecord | None`
  - `get_radar_graph()` counts `SELECT COUNT(*) AS c FROM cases WHERE contributes_to_radar = 1`
  - Replaces all 4 `vs_{uuid4().hex[:12]}` generators (`pipeline.py:709`, `repository.py:600, 987, 1009`) with `generate_case_id()`.
- Produces (`backend/app/services/scam_classifier.py` & `pipeline.py` & `main.py`):
  - `ScamClassifier.__init__(self, model_dir: str, _injected_session: Any | None = None, intra_threads: int = 2)` (wired to `settings.onnx_intra_threads` in `AnalysisPipeline.__init__`)
  - `ScamClassifier.encode_text(text: str, *, prefix: Literal["query", "passage"] = "query") -> np.ndarray | None`
  - `ScamClassifier.predict_and_encode(text: str) -> tuple[ScamClassifierOutput, np.ndarray | None]`
  - `AnalysisPipeline` holds stable `self.case_token_secret: str` (passed from `create_app` or resolved once via `resolve_case_token_secret(settings)` so direct unit-test instantiations share one stable key!).
  - `app.state.case_token_secret: str` + `CORSMiddleware(..., expose_headers=["X-Case-Access-Token"])`.

- [ ] **Step 1: Write failing tests in `backend/tests/unit/test_case_tokens.py`**
  - Verify 128-bit `generate_case_id()` format (`^vs_[0-9a-f]{32}$`), token issue/verify/tamper/expiry/wrong-cid, `resolve_case_token_secret` (rejects placeholders in `demo` & `production`, rejects missing both secrets in `production`, derives cleanly from explicit `ioc_hmac_secret` in `production`, generates distinct ephemeral 64-hex keys in `demo`), legacy SQLite migration defaults to `'legacy_locked'`, `contributes_to_radar=False` writes 0 IOC sightings and does not bump `stats["total_cases"]`, and `ScamClassifier.encode_text` / `predict_and_encode` return unit-norm 384-d `float32` vectors.
- [ ] **Step 2: Run pytest to verify failure**
- [ ] **Step 3: Implement `case_tokens.py`, `config.py`, `deploy/.env.prod.example`, `repository.py`, `pipeline.py`, `scam_classifier.py`, `main.py`**
- [ ] **Step 4: Run targeted tests + `test_scam_classifier.py` (`p50_ms < 35`) + `test_radar_security_and_simulation.py`**

---

### Task 2: Enforce Unified `verify_web_case_access` on `/cases/*`, Token Issuance on `/analyze*`, & Telegram Private-Chat-Only PDF (`sendDocument`)

**Files:**
- Modify: `backend/app/api/v1/cases.py`, `backend/app/api/v1/analyze.py`, `backend/app/api/v1/telegram.py`, `backend/app/services/telegram_formatting.py`, `backend/app/services/telegram_media.py`, `backend/app/services/telegram_bot.py`, `backend/app/services/pipeline.py` (optional `owner_channel`/`owner_chat_hash` params), `scripts/smoke_test_live.py`
- Test: `backend/tests/integration/test_api_routes.py`, `backend/tests/unit/test_telegram_bot.py`

**Interfaces:**
- Consumes: Task 1 (`StoredCaseRecord`, `issue_case_access_token`, `verify_case_access_token`, `hash_telegram_private_owner`, `pipeline.case_token_secret`)
- Produces:
  - `verify_web_case_access(case_id: str, token: str | None, repo: CaseRepository, secret: str) -> StoredCaseRecord` in `backend/app/api/v1/cases.py` (pure helper reused by BOTH `require_case_access` FastAPI dependency AND Tasks 7/10 `/assistant/*`; raises `HTTPException(403)` BEFORE DB existence leak on invalid/missing/expired token OR `record.owner_channel != "web_token"`).
  - `GET /api/v1/cases/{case_id}` and `GET /api/v1/cases/{case_id}/report.pdf` both enforce `require_case_access` and set `Cache-Control: no-store` and `Vary: X-Case-Access-Token`.
  - `POST /api/v1/analyze` sets `X-Case-Access-Token` + `Cache-Control: no-store` when `not is_simulation`.
  - `POST /api/v1/analyze/stream` sets `Cache-Control: no-store, no-cache` and emits `event: session\ndata: {"case_id": ..., "case_access_token": ..., "expires_at": ...}\n\n` after `event: result` when `not is_simulation`.
  - `TelegramEnvelope` (`telegram_formatting.py`) extracts `chat_type: str | None = None` (`chat.get("type")`) and `sender_user_id: int | None = None` (`cb["from"]["id"]` on `callback_query`; `msg["from"]["id"]` on `message`/`edited_message`; never `cb["message"]["from"]`!).
  - `build_verdict_inline_keyboard(case_id: str, public_base_url: str, *, allow_pdf_callback: bool = True) -> dict[str, Any] | None`: Row 1 is `{"text": "📄 Nhận báo cáo bằng chứng (PDF)", "callback_data": f"pdf:{case_id}"}` ONLY when `allow_pdf_callback=True` (zero `/report.pdf` URLs emitted!).
  - `telegram_media.py`: add `show_alert: bool = False` to `answer_telegram_callback_query(...)` and add `send_telegram_document(bot_token, chat_id, filename, pdf_bytes, caption)` using `build_ssrf_pinned_http_client(timeout_sec=15.0)`.
  - `telegram_bot.py`: handle `env.callback_data.startswith("pdf:")` in an **early isolated branch BEFORE generic `answerCallbackQuery` and BEFORE `sendMessage`**: deduplicate via `claim_telegram_update`, verify `env.chat_type == "private"` + `env.sender_user_id is not None` + `record.owner_channel == "telegram_private"` + `hmac.compare_digest(record.owner_chat_hash, hash_telegram_private_owner(...))`, upload via `send_telegram_document` on allow, or reject via `answer_telegram_callback_query(..., show_alert=True)` on group/supergroup/channel/missing `chat.type`/wrong user with 0 `sendDocument` calls. On verdict messages, pass `owner_channel="telegram_private"` + `owner_chat_hash` when private else `owner_channel="telegram_group_locked"`, `owner_chat_hash=None`, `allow_pdf_callback=False` (append short note in group reply that PDF is available in 1-1 private chat).
  - `api/v1/telegram.py`: pass `case_token_secret=request.app.state.case_token_secret` into `handle_telegram_update(...)` (parameter remains optional defaulting to `pipeline.case_token_secret` for backward compat with existing 3-arg tests!).
  - `scripts/smoke_test_live.py`: capture `event: session` token from `/analyze/stream`, verify unauthenticated `GET /cases/{id}` & `/report.pdf` return `403`, and authenticated requests return `200`.

- [ ] **Step 1: Write/update failing tests in `test_api_routes.py` and `test_telegram_bot.py`**
- [ ] **Step 2: Run pytest to confirm failure**
- [ ] **Step 3: Implement `cases.py`, `analyze.py`, `telegram.py`, `telegram_formatting.py`, `telegram_media.py`, `telegram_bot.py`, `pipeline.py`, `smoke_test_live.py`**
- [ ] **Step 4: Run full backend pytest (`pytest backend/tests -q`) + `ruff` + `mypy --strict`**

---

### Task 3: Frontend Case Session Token & Authenticated Blob PDF Download

**Files:**
- Modify: `frontend/src/lib/types.ts`, `frontend/src/lib/api.ts`, `frontend/src/components/copilot/ActionCopilotPanel.tsx`, `frontend/src/app/page.tsx`
- Test: `frontend/src/lib/__tests__/auditRegressions.test.ts`

**Interfaces:**
- Produces:
  - `CaseSessionInfo = { case_id: string; case_access_token: string; expires_at?: string }` (`types.ts`)
  - `analyzeStream(formData, { onTrace?, onResult?, onSession? }, signal?)` (`api.ts`); `!res.body` fallback uses `analyzeSyncWithSession` and invokes `onResult` + `onSession`
  - `analyzeSyncWithSession(formData, signal?) -> Promise<{ report: AnalysisReport; caseAccessToken: string | null }>` (`api.ts`)
  - Pure testable `fetchReportPdfBlob(caseId: string, caseAccessToken: string | null): Promise<{ blob: Blob; filename: string }>` (`api.ts`, sends `X-Case-Access-Token`, throws Vietnamese expiry message on 403/null token) + thin browser wrapper `downloadReportPdf(caseId, caseAccessToken)`
  - `ActionCopilotPanelProps = { report: AnalysisReport; caseAccessToken: string | null }` rendering `<button type="button">` with loading & error alert
  - `page.tsx`: tracks local `let capturedToken: string | null = null` inside `executeAnalysis` so final `setSubmittedSnapshot` NEVER wipes `caseAccessToken`; stabilizes preview `useEffect` dependency on `submittedSnapshot?.imageFiles`.

- [ ] **Step 1: Add failing Node `--test` cases in `frontend/src/lib/__tests__/auditRegressions.test.ts`** (testing `onSession` and `fetchReportPdfBlob` for 200 header, 403, and null token without touching `document`)
- [ ] **Step 2: Run `npm --prefix frontend test` to verify failure**
- [ ] **Step 3: Implement `types.ts`, `api.ts`, `ActionCopilotPanel.tsx`, `page.tsx`**
- [ ] **Step 4: Run `npm --prefix frontend run typecheck && npm --prefix frontend test`**

---

## Phase 1 — MVP "Trợ lý VeriShield"

### Task 4: Curated KB SOPs & Verification Guides, Offline ONNX Indexer (`E_raw`), Hybrid RAG Retriever, & 7-Baseline Ablation Suite

**Files:**
- Create: `backend/app/data/kb/incident_response_sops.json`, `backend/app/data/kb/verification_guides.json`, `scripts/build_assistant_kb_index.py`, `backend/app/data/models/assistant_kb_embeddings.npy`, `backend/app/data/models/assistant_kb_index.json`, `backend/app/services/assistant_rag.py`, `evaluation/assistant_eval/assistant_eval_cases.json`, `evaluation/assistant_eval/run_rag_ablation.py`
- Modify: `backend/app/services/knowledge_base.py` (export public `normalize_vi_search` alias)
- Test: `backend/tests/unit/test_assistant_rag.py`

**Interfaces:**
- Consumes: `ScamClassifier.encode_text` (Task 1), `normalize_vi_search` (`knowledge_base.py`), `vn_scam_kb.json`
- Produces (`backend/app/services/assistant_rag.py`, `< 260` lines):
  - `RetrievedChunk(BaseModel)`, `RagSearchResult(BaseModel)`, `AssistantKnowledgeRetriever` (loads raw unit-norm `E_raw`, computes `mu` & `E_centered` once at startup in RAM; formats NAPAS BINs as `BIN 970436 (Vietcombank)` so `LABELED_ACCOUNT_SPAN_RE` never mangles them; calibrates Scope Gate thresholds `(tau_raw, tau_cent)` from Dev ablation split).

- [ ] **Step 1: Author `incident_response_sops.json` & `verification_guides.json` (100% synthetic/public-advisory, zero unverified hotlines, every chunk `<= 150` tokens)**
- [ ] **Step 2: Implement `scripts/build_assistant_kb_index.py` & generate `assistant_kb_embeddings.npy` (`E_raw`) + `assistant_kb_index.json` (assert `token_len <= 180`, `<unk> < 2%`, total models dir `< 50 MB`)**
- [ ] **Step 3: Write failing tests in `backend/tests/unit/test_assistant_rag.py`**
- [ ] **Step 4: Implement `backend/app/services/assistant_rag.py` + `evaluation/assistant_eval/assistant_eval_cases.json` (Dev + Held-out Test `>= 100` cases) + `run_rag_ablation.py` (`B0..B6`)**
- [ ] **Step 5: Run pytest + `run_rag_ablation.py`, tune calibrated thresholds from `dev` only, verify Held-out Test metrics**

---

### Task 5: `RequestEntityVault`, Unified `sanitize_llm_egress_text()`, & Single `<UNTRUSTED_USER_CONTENT>` `CaseContextBuilder`

**Files:**
- Create: `backend/app/schemas/assistant.py`, `backend/app/services/assistant_vault.py`, `backend/app/services/assistant_context.py`
- Modify: `backend/app/services/guardrails.py` (extend XML tag breakout regex while preserving `untrusted_user_content`)
- Test: `backend/tests/unit/test_assistant_vault_and_context.py`

**Interfaces:**
- Produces (`backend/app/schemas/assistant.py`, `< 100` lines): `AssistantHistoryTurn`, `AssistantChatRequest` (`extra="forbid"`, `sum(history) <= 6000`), `AssistantCitation`
- Produces (`backend/app/services/assistant_vault.py`, `< 260` lines):
  - `RequestEntityVault.extract_from_message(raw_message: str) -> tuple[str, RequestEntityVault]` using **IPv6-aware URL regex** (`https?://(?:\[[0-9a-fA-F:.]+\]|[^\s<>'\"()\[\]{}]+)`) + refang (`hxxp`, `[.]`, `(.)`, `[dot]`) **BEFORE** account extraction (so `http://2130706433/` and `http://[::ffff:127.0.0.1]/` vault as `URL_REF_n`), neutralizing pre-existing `[*_REF_\d+]` across all untrusted inputs.
  - `sanitize_llm_egress_text(text: str, *, preserve_official_bare_domains: bool = False, preserve_strict_vault_refs: bool = False) -> str`:
    - Preserves vault ref tokens **only** when matching strict masked-preview grammar (no `/`, `?`, `:`, spaces, or 6+ consecutive digits).
    - When `preserve_official_bare_domains=True`, exempts **only** bare institutional hostnames matching `vn_scam_kb.json`'s `official_brands[*].official_domains` (no scheme/path/query/userinfo/port); redacts all other URLs & defanged URLs -> `[URL_REDACTED:<masked_domain>]`, raw VietQR -> `[VIETQR_REDACTED]`, OTP/CCCD/cards/email, phones & bank accounts.
  - `sanitize_untrusted_delimiters(text: str) -> str`
- Produces (`backend/app/services/assistant_context.py`, `< 240` lines):
  - `build_assistant_prompt(...) -> tuple[str, str]` omitting raw `case_id` from `[SYSTEM_CASE_FACTS]`, placing `[SYSTEM_CASE_FACTS]`, `[GROUNDED_KB_CONTEXT]`, `[AVAILABLE_USER_ENTITY_REFS]` before exactly ONE `<UNTRUSTED_USER_CONTENT>...</UNTRUSTED_USER_CONTENT>` wrapping sanitized & egress-scrubbed `[CASE_EVIDENCE_EXCERPTS]`, `[CONVERSATION_HISTORY_UNTRUSTED]` (all `user` & `assistant` turns flattened), and `[CURRENT_USER_MESSAGE]`.

- [ ] **Step 1: Write failing tests in `backend/tests/unit/test_assistant_vault_and_context.py`** (including IPv6 `http://[::ffff:127.0.0.1]/`, integer IP `http://2130706433/`, ref-token smuggling `[URL_REF_1 (https://evil.com 0912345678)]` inside `history[]`, preserving bare `vietcombank.com.vn` ONLY when `preserve_official_bare_domains=True`, and asserting `count("<UNTRUSTED_USER_CONTENT>") == 1`)
- [ ] **Step 2: Run pytest to verify failure**
- [ ] **Step 3: Implement `schemas/assistant.py`, `services/assistant_vault.py`, `services/assistant_context.py`, `guardrails.py`**
- [ ] **Step 4: Run pytest to verify pass**

---

### Task 6: 3-Tier Pre-Emission Output Safety Gate (`assistant_guardrails.py`)

**Files:**
- Create: `backend/app/services/assistant_guardrails.py`
- Test: `backend/tests/unit/test_assistant_guardrails.py`

**Interfaces:**
- Produces (`backend/app/services/assistant_guardrails.py`, `< 260` lines):
  - `OutputTier = Literal[0, 1, 2]`, `MAX_TIER2_SENTENCE_CHARS: Final[int] = 160`
  - `ThinkStreamFilter` (stateful `<think>...</think>` chunk-boundary stripper — placed here to keep `assistant_llm.py` `< 250` lines)
  - `classify_output_tier(*, message: str, report: AnalysisReport | None, turn_injection_detected: bool) -> OutputTier`
  - `build_tier0_deterministic_reply(report: AnalysisReport | None, rag_chunks: list[RetrievedChunk]) -> tuple[str, dict[str, str]]`
  - `build_degraded_rag_reply(report: AnalysisReport | None, rag_chunks: list[RetrievedChunk], *, message: str) -> str`
  - `validate_full_reply(*, draft_text: str, report: AnalysisReport | None, rag_chunks: list[RetrievedChunk], require_balance_check: bool, require_epistemic_limit: bool) -> tuple[bool, list[str], str]` (5 layers: NFC/`fold_vi_ascii`, clause-level polarity denylist without lookbehind bugs, positive inclusion invariant mirroring `analysis.py:161-172`, T8 hotline blocker normalizing digit separators `[\s.\-–—]` against `rag_chunks`, fail-closed deterministic fallback)
  - `Tier2SentenceGate`: splits ONLY at real sentence boundaries `(?:(?<!\d)\.(?=\s|$)|[!?](?=\s|$)|\n)` (avoiding `15.000.000`, `1. `, `.apk`, `vneid.gov.vn`); **NEVER flushes an incomplete sentence at `MAX_TIER2_SENTENCE_CHARS`** — holds entire buffer and promotes to Tier 1 validating `emitted_prefix + buffered_remainder` at EOF!

- [ ] **Step 1: Write failing unit tests in `backend/tests/unit/test_assistant_guardrails.py`** (including `15.000.000`/`vneid.gov.vn`/`.apk` non-split, 210-char sentence promotion without flush, cross-sentence `emitted_prefix + buffered_remainder` check, spaced hotline `"1900 999 999"`, accented/unaccented paraphrases, no false positive on *"chỉ có thể giao hàng sau khi kiểm tra số dư"*, and split `<think>...</think>` chunks)
- [ ] **Step 2: Run pytest to verify failure**
- [ ] **Step 3: Implement `backend/app/services/assistant_guardrails.py`**
- [ ] **Step 4: Run pytest to verify pass**

---

### Task 7: Dual-Protocol Streaming LLM Adapter (`assistant_llm.py`), `assistant_service.py`, `POST /api/v1/assistant/chat/stream`, & Dual-Window Rate Limiting

**Files:**
- Create: `backend/app/services/assistant_llm.py`, `backend/app/services/assistant_service.py`, `backend/app/api/v1/assistant.py`, `scripts/verify_assistant_llm.py`
- Modify: `backend/app/api/v1/router.py`, `backend/app/main.py`
- Test: `backend/tests/unit/test_assistant_llm_and_stream.py`, `backend/tests/integration/test_assistant_stream_api.py`

**Interfaces:**
- Produces (`backend/app/services/assistant_llm.py`, `< 240` lines):
  - `AssistantLlmUnavailableError(RuntimeError)`
  - `apply_final_wire_egress_chokepoint(user_prompt: str) -> str`: splits at `<UNTRUSTED_USER_CONTENT>` — applies `sanitize_llm_egress_text(..., preserve_official_bare_domains=True, preserve_strict_vault_refs=True)` ONLY on trusted prefix and `preserve_official_bare_domains=False, preserve_strict_vault_refs=True` inside `<UNTRUSTED_USER_CONTENT>` (full strict mode if delimiter absent).
  - `stream_assistant_llm(settings, *, system_instruction: str, user_prompt: str, max_output_tokens: int = 700, timeout_sec: float = 25.0) -> AsyncIterator[str]` (both `openai_compatible` & `google_genai` with `AutomaticFunctionCallingConfig(disable=True)`, backup-key failover, `ThinkStreamFilter`, `SAFETY_BLOCKED` handling).
- Produces (`backend/app/services/assistant_service.py`, `< 260` lines):
  - `AssistantService(settings, repo, retriever, classifier)` reusing `pipeline.classifier` (NO second ONNX session!); `Semaphore(6)` with `asyncio.wait_for(..., timeout=2.0)` -> `429`; bounded LRU `OrderedDict[str, int]` (`max 1024`) enforcing `20 turns/case` -> `429`; `45s` total stream timeout; read-only case-detail/KB helpers; full Tier 0 / Tier 1 / Tier 2 + Tier-1 RAG fallback.
- Produces (`backend/app/main.py` & `backend/app/api/v1/assistant.py`):
  - `SlidingWindowRateLimiter(..., window_seconds: float = 60.0)` + `CompositeRateLimiter` checking BOTH `12/min` and `60/hour` BEFORE recording timestamp; routes all `path.startswith("/api/v1/assistant/")` to `assistant_limiter`.
  - `POST /api/v1/assistant/chat/stream` runs `verify_web_case_access` + turn-cap + semaphore check synchronously **BEFORE** returning `StreamingResponse` (sets `Cache-Control: no-store`).

- [ ] **Step 1: Write failing tests in `test_assistant_llm_and_stream.py` (asserting wire payloads on BOTH mock `httpx` CPA and mock `google_genai` have 0% raw PII/URL/IPv6/VietQR leakage while preserving official bare domain in trusted KB prefix) and `test_assistant_stream_api.py` (auth 403, rate limit 429, 20-turn cap 429, OOD scope refusal, merchant Tier 0/1 `safety_notice`, offline `degraded_mode=True` HTTP 200)**
- [ ] **Step 2: Run pytest to verify failure**
- [ ] **Step 3: Implement `assistant_llm.py`, `assistant_service.py`, `api/v1/assistant.py`, `scripts/verify_assistant_llm.py`, `router.py`, `main.py`**
- [ ] **Step 4: Run pytest + `ruff` + `mypy --strict`**

---

### Task 8: Frontend "Trợ lý VeriShield" Side Drawer, Pure-TS `safeMarkdown.ts` & Context Quick Actions

**Files:**
- Create: `frontend/src/lib/safeMarkdown.ts`, `frontend/src/components/assistant/SafeMarkdown.tsx`, `frontend/src/components/assistant/AssistantQuickActions.tsx`, `frontend/src/components/assistant/AssistantMessageItem.tsx`, `frontend/src/components/assistant/AssistantDrawer.tsx`, `frontend/src/lib/__tests__/assistantClient.test.ts`
- Modify: `frontend/src/lib/types.ts`, `frontend/src/lib/api.ts`, `frontend/src/components/workbench/VerdictDashboard.tsx`, `frontend/src/app/page.tsx`, `frontend/package.json`

**Interfaces:**
- Produces:
  - `parseSafeMarkdownBlocks(markdown: string)` in pure-TS `frontend/src/lib/safeMarkdown.ts` (zero JSX/React; tested directly by `node --test`)
  - `streamAssistantChat(payload, accessToken, handlers, signal?)` in `frontend/src/lib/api.ts` (uses `.ts` relative imports; sends `X-Case-Access-Token`)
  - `VerdictDashboardProps = { report: AnalysisReport; onOpenAssistant?: (initialPrompt?: string) => void }`
  - `AssistantDrawer` + `AssistantMessageItem` + `AssistantQuickActions` strictly gated inside `{report && (...)}` in `page.tsx` (zero DOM when `report === null`; resets drawer closed on new analysis/manual edit/clear demo; truthful *"Xóa hội thoại"* tooltip; pinned `MERCHANT_HONESTY_BANNER`; `Escape` close & WCAG 2.2 focus).

- [ ] **Step 1: Write failing Node `--test` cases in `frontend/src/lib/__tests__/assistantClient.test.ts` (testing `../safeMarkdown.ts` XSS neutrality + `streamAssistantChat` SSE parsing & header)** and register in `frontend/package.json` `"test"` script
- [ ] **Step 2: Run `npm --prefix frontend test` to verify failure**
- [ ] **Step 3: Implement `safeMarkdown.ts`, `SafeMarkdown.tsx`, `AssistantQuickActions.tsx`, `AssistantMessageItem.tsx`, `AssistantDrawer.tsx`, `types.ts`, `api.ts`, `VerdictDashboard.tsx`, `page.tsx`**
- [ ] **Step 4: Run `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build`**

---

## Phase 2 — Controlled Ref-Only Verification Tools & Red-Team Suite

### Task 9: `assistant_tools.py` (`check_url_safety`, `inspect_vietqr_payload`, `lookup_ioc_reputation`) + Router Pre-Tool + Red-Team Suite

**Files:**
- Create: `backend/app/services/assistant_tools.py`, `backend/tests/unit/test_assistant_tools.py`, `backend/tests/integration/test_assistant_redteam.py`
- Modify: `backend/app/services/assistant_service.py`, `frontend/src/components/assistant/AssistantMessageItem.tsx`, `frontend/src/components/assistant/AssistantDrawer.tsx`

**Interfaces:**
- Produces (`backend/app/services/assistant_tools.py`, `< 260` lines):
  - `ALLOWED_ASSISTANT_TOOLS: Final[frozenset[str]]` (`get_case_evidence_detail`, `search_fraud_knowledge`, `check_url_safety`, `inspect_vietqr_payload`, `lookup_ioc_reputation`)
  - Strict `extra="forbid"` ref-only Pydantic models (`CheckUrlSafetyArgs`, `InspectVietQrArgs`, `LookupIocArgs`)
  - `execute_controlled_tool(...)`: resolves ref from `RequestEntityVault` (or returns `REF_NOT_IN_CURRENT_TURN`); `check_url_safety` masks `domain`/`final_domain` via `mask_ioc`, omits raw `url`/`final_url`, NO Playwright; passes entire output through `sanitize_llm_egress_text()` capped at `1800` chars.
  - `run_pre_tools_for_vault(...)`: max `3` total calls, max `2` URL checks/turn, wired into `AssistantService.stream_chat` emitting `tool_status` SSE chips.

- [ ] **Step 1: Write failing unit & red-team tests (`test_assistant_tools.py`, `test_assistant_redteam.py` — covering IDOR, indirect OCR injection, fake `[URL_REF_1]` spoofing, IPv6/integer/defanged SSRF, masked `"19****01"` rejection, and 0 mutations on `block_rules` & `radar_audit_logs`)**
- [ ] **Step 2: Run pytest to verify failure**
- [ ] **Step 3: Implement `assistant_tools.py`, wire pre-tools into `assistant_service.py`, and render `tool_status` chips in `AssistantDrawer.tsx` / `AssistantMessageItem.tsx`**
- [ ] **Step 4: Run pytest + frontend typecheck/tests**

---

## Phase 3 — Local-Only Ephemeral Supplementary Evidence + Explicit Persist

### Task 10: `persistence_mode="ephemeral_private"` + `allow_external_media_ai=False` Default + `EphemeralEvidenceStage` + Explicit Persist & Drawer Attachment UI

**Files:**
- Create: `backend/app/services/assistant_evidence.py`, `backend/tests/integration/test_assistant_evidence.py`, `frontend/src/components/assistant/AssistantEvidenceCard.tsx`
- Modify: `backend/app/services/ocr/service.py`, `backend/app/services/pipeline.py`, `backend/app/services/ai_orchestrator.py`, `backend/app/db/repository.py`, `backend/app/api/v1/assistant.py`, `backend/app/main.py`, `frontend/src/lib/types.ts`, `frontend/src/lib/api.ts`, `frontend/src/components/assistant/AssistantDrawer.tsx`

**Interfaces:**
- Produces:
  - `OcrOrchestrator.extract_batch(..., allow_gemini_fallback: bool = True)` (`ocr/service.py`: when `False`, never invokes `_gemini_fallback_fn`)
  - `run_gemini_reasoning(..., local_only: bool = False)` (`ai_orchestrator.py`: when `local_only=True`, sets `llm_error="LOCAL_ONLY_PRIVACY_MODE"` and skips external LLM cleanly)
  - `PersistenceMode = Literal["ephemeral_private", "persist_private_case", "persist_and_radar"]` + `allow_external_media_ai: bool = True` + `EphemeralAnalysisBundle(live_report, staged_redacted_report, prehashed_iocs, replay_fingerprints)` via `pipeline.run_ephemeral(...)` (computes pre-hashed IOCs + raw `replay_fingerprints` BEFORE `redact_report_pii()`, uses read-only `repo.is_receipt_replayed()`, writes 0 SQLite rows, and when `allow_external_media_ai=False` disables BOTH Gemini OCR fallback AND `run_gemini_reasoning` passing zero image/audio bytes out!)
  - `EphemeralEvidenceStage` (`assistant_evidence.py`, `< 220` lines): LRU `64`, TTL `15 min`, stores stripped `staged_redacted_report`, `parent_case_id`, `parent_is_demo`, `prehashed_iocs`, `replay_fingerprints` (0 raw PII in RAM)
  - `repo.save_staged_report(...)`: re-keys `case_id = child_case_id`, writes `cases` with `parent_case_id`, `owner_channel="web_token"`, `contributes_to_radar=contribute_to_radar`, and updates `ioc_sightings`/`ioc_edges`/`campaigns`/`receipt_hashes` ONLY when `contribute_to_radar=True` (and `risk_score >= 45` for graph)
  - `SecurityAndLimitsMiddleware` (`main.py`): sets `evidence_limit_bytes = cfg.max_upload_bytes + MULTIPART_ENVELOPE_OVERHEAD_BYTES` for `path == "/api/v1/assistant/chat/evidence/stream"`, keeping 256 KB on JSON routes
  - `POST /api/v1/assistant/chat/evidence/stream` (REQUIRES valid `case_id` + `X-Case-Access-Token` verified BEFORE `StreamingResponse`; default `allow_external_media_ai="false"`) & `POST /api/v1/assistant/evidence/{draft_id}/persist` (atomic pop, verifies parent token, forces `contribute_to_radar=False` if `parent_is_demo`, returns `child_case_id` + `child_case_access_token`)
  - Frontend `AssistantEvidenceCard.tsx` + attachment controls in `AssistantDrawer.tsx` (unchecked opt-in checkbox *"Cho phép gửi ảnh/ghi âm bổ sung tới AI bên ngoài"*, unchecked Radar opt-in checkbox disabled when `!can_contribute_radar`, *"Lưu hồ sơ bổ sung & tải PDF"* using child token + `downloadReportPdf`).

- [ ] **Step 1: Write failing tests in `backend/tests/integration/test_assistant_evidence.py`** (including >256 KB PNG passing middleware guard, `0` Gemini LLM calls & `0` Gemini OCR fallback calls when `allow_external_media_ai="false"`, `0` new rows across all 5 SQLite tables, `REPLAYED_RECEIPT` still detected, parent demo case blocking `contribute_to_radar=True`, atomic single-use `/persist`, and `GET /cases/{child_case_id}/report.pdf` succeeding ONLY with `child_case_access_token` and failing `403` with parent token)
- [ ] **Step 2: Run pytest to verify failure**
- [ ] **Step 3: Implement `ocr/service.py`, `ai_orchestrator.py`, `pipeline.py`, `repository.py`, `assistant_evidence.py`, `api/v1/assistant.py`, `main.py`, and Frontend attachment/persist UI**
- [ ] **Step 4: Run backend & frontend tests**

---

## Phase 4 — Documentation Synchronization & Final Verification Gate

### Task 11: Sync `/privacy`, `/technical`, & Architecture SVGs + Run Full `scripts/verify.ps1` + RAG Ablation + Playwright E2E Verification

**Files:**
- Modify: `frontend/src/app/privacy/page.tsx`, `frontend/src/components/docs/DataLifecycleSvg.tsx`, `frontend/src/app/technical/page.tsx`, `frontend/src/components/docs/SystemArchitectureSvg.tsx`

- [ ] **Step 1: Update `/privacy` (01, 02, 04, 05, 06, 07, 08) & `DataLifecycleSvg.tsx`** matching exact implemented behavior across Tasks 1–10 (preserving all prior refinements).
- [ ] **Step 2: Update `/technical` (01, 02, 05, 09, 14, 15, 16) & `SystemArchitectureSvg.tsx`** with verified RAG ablation numbers from Task 4 and implemented security controls without exposing internal thresholds/regexes.
- [ ] **Step 3: Run mandatory verification gate `powershell -ExecutionPolicy Bypass -File scripts/verify.ps1`** (confirm ALL checks green: `ruff`, `mypy --strict`, `pytest`, `tsc --noEmit`, `npm test`, `next build`).
- [ ] **Step 4: Run Playwright Desktop (`1440×900`) & Mobile (`390×844`) visual & functional E2E check** on `/`, `Trợ lý VeriShield`, `/privacy`, `/technical`.
