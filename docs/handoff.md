# Tài liệu Bàn giao Kỹ thuật (Handoff) — VeriShield AI v2.0

> **Thời điểm bàn giao:** `2026-11-28` · **Nhánh active:** `feat/verishield-v2` @ `1bfc688`  
> **Thay đổi mới nhất:** Pull fast-forward 28 commit (`272f470..1bfc688`) từ `origin/feat/verishield-v2`.

---

## 1. Trạng thái Git & Môi trường Cục bộ

- **Nhánh Git:**
  - `feat/verishield-v2` (HEAD): `1bfc688` (`build: enforce LF line endings for Linux-executed files via .gitattributes`), khớp `origin/feat/verishield-v2`.
  - `v3`: đang trỏ tại commit cũ `272f470` (chưa merge `1bfc688`).
  - `main`: `63764ab` (`add docs`).
- **Git Stash bảo toàn sửa đổi trước đó:**
  - `stash@{0}` (`wip-v3-local-edits-before-pull`) chứa các chỉnh sửa MVP Web Demo trước lúc pull trên nhánh cũ (`health.py`, `onnx_session.py`, `pipeline.py`, `test_api_routes.py`, `page.tsx`, `VietQrCard.tsx`, `PhishingSandboxCard.tsx`, `BlockRuleManager.tsx`, `DemoScenarioBar.tsx`, `api.ts`, `render_pdfs.py`, `slides/index.html`, `README.md`, `deploy/.env.prod.example`). Lưu ý không `pop` đè trực tiếp vì `feat/verishield-v2` đã refactor lớn các file Frontend và Pipeline; chỉ nhặt có chọn lọc các phần còn phù hợp (như `ORT_ENABLE_BASIC` ở `onnx_session.py` hoặc thanh `%` Slide 8).
- **Tệp chưa theo dõi (Untracked):** `docs/Goals.md`, `docs/handoff.md`, `docs/Lessons.md` (tài liệu làm việc nội bộ; lưu ý `scripts/package_submission.py` dùng `git ls-files -z` nên sẽ không tự đưa file untracked vào `.zip`).
- **Lưu ý môi trường local:** Sau khi pull `1bfc688`, `frontend/package.json` có thêm `lenis` (`^1.3.29`) và `motion` (`^14.14.0`) — cần chạy `npm.cmd ci` trong `frontend/` trước khi chạy test/build. Ngoài ra `submission/dist/` vẫn đang giữ 2 file PDF cũ render ngày `2026-11-26 20:53:46` từ trước đợt cập nhật Assistant/OCR/Motion.

---

## 2. Bản đồ Kiến trúc Codebase Hiện tại (`1bfc688`)

### 2.1. Backend (`backend/app/`)
- **Entry & Middleware ([main.py](file:///d:/HOCTAP/repo/Momo_Tech_Contest_Prj/backend/app/main.py), [config.py](file:///d:/HOCTAP/repo/Momo_Tech_Contest_Prj/backend/app/config.py)):**
  - `SecurityAndLimitsMiddleware` (ASGI thuần): giới hạn streaming byte theo route (`/api/v1/analyze*` `2*max_upload_bytes+64KB`, `/api/v1/assistant/chat/evidence/stream` `max_upload_bytes+64KB`, các POST khác `256KB`), sliding-window rate limiter (kép 12/phút + 60/giờ cho Assistant, 300/phút cho Telegram, 15/phút cho `/radar/block-rules`, 20/phút PDF, 60/phút Radar GET), gắn Security Headers và `expose_headers=["X-Case-Access-Token"]`.
  - `Settings` kiểm tra fail-closed các bí mật khi `APP_ENV=production` (`ANALYST_PIN >= 8`, `IOC_HMAC_SECRET >= 16`, `CASE_TOKEN_SECRET >= 32`, `TELEGRAM_WEBHOOK_SECRET >= 24`, cấm dùng PIN demo `2026` ngoài `APP_ENV=demo`).
- **API v1 (`backend/app/api/v1/`):**
  - `health.py`: `GET /api/v1/health` (báo trạng thái SQLite WAL, ONNX, OCR provider, Whisper STT, LLM, Telegram bot URL), `GET /api/v1/demos`.
  - `analyze.py`: `POST /api/v1/analyze` & `POST /api/v1/analyze/stream` — nhận đa ảnh (`<= 4`), đa audio (`<= 2`), `is_simulation`, cấp `X-Case-Access-Token` (qua header hoặc SSE `event: session`, trừ khi `is_simulation=true`).
  - `cases.py`: `GET /api/v1/cases/{case_id}` & `GET /api/v1/cases/{case_id}/report.pdf` (bắt buộc `X-Case-Access-Token` đúng kênh `owner_channel == "web_token"`, PDF LRU cache 16 mục, timeout 15s trả `503 Retry-After: 2`).
  - `assistant.py`: `POST /api/v1/assistant/chat/stream`, `POST /api/v1/assistant/chat/evidence/stream` (phân tích tạm thời trên RAM), `POST /api/v1/assistant/evidence/{draft_id}/persist` (lưu hồ sơ con & cấp token con).
  - `radar.py`: `GET /api/v1/radar/graph`, `POST /api/v1/radar/block-rules`, `POST /api/v1/radar/block-rules/{rule_id}/revoke`, `POST /api/v1/radar/block-rules/reset` (đều ghi `radar_audit_logs`, bảo vệ domain chính thức `HTTP 409`).
  - `telegram.py`: `POST /api/v1/bot/telegram` (kiểm tra `X-Telegram-Bot-Api-Secret-Token`).
- **Core Bảo mật (`backend/app/core/`):**
  - `case_tokens.py` (ID 128-bit `vs_<32hex>`, token HMAC-SHA256 TTL 2h, hash sở hữu Telegram riêng tư).
  - `security.py` & `url_authority.py` (chặn ký tự ẩn, userinfo, IP obfuscated, mọi IP non-public, gắn chặt IP socket `_PinnedPublicNetworkBackend`).
  - `http_decompression.py` (đọc stream tối đa 16 KiB/chunk chống zip/gzip bomb, `SharedByteBudget` 4MB cho sandbox).
  - `media_security.py` & `media_executors.py` (magic bytes, pixel cap 25M, loại bỏ GIF/WebP động, chuẩn hóa bỏ EXIF/polyglot, PyAV decode audio an toàn; 4 `BoundedExecutorPool` cho OCR/STT/Forensics/PDF).
  - `onnx_session.py` (`enable_cpu_mem_arena=False`, `enable_mem_pattern=False`).
- **Lưu trữ (`backend/app/db/`):**
  - `migrations.py` & `repository.py`: 9 bảng SQLite WAL (`cases`, `ioc_sightings`, `ioc_edges`, `campaigns`, `block_rules`, `radar_audit_logs`, `protected_demo_iocs`, `receipt_hashes`, `telegram_updates`), migration theo lô 100 dòng, rotation ID cũ `vs_tg_*`, chống replay Hamming dHash `<= 3` & `ref_h:`, chặn đầu độc Radar từ prompt injection, giữ tỉa dữ liệu định kỳ, cache đồ thị 2s.
- **Dịch vụ AI, OCR, Pháp y & Assistant (`backend/app/services/`):**
  - `pipeline.py`: điều phối 4 chặng SSE; tách riêng URL chỉ xuất hiện trong OCR/QR/STT (`enable_network=False`, không nổ Playwright); xử lý `ephemeral_private` / `persist_private_case` / `persist_and_radar`.
  - `ocr/`: `RapidOcrOnnxProvider` (`ppocrv5_latin` mặc định, fallback `gemini_provider.py`, có `mineru_provider.py` chỉ dùng benchmark offline).
  - `scam_classifier.py` + `knowledge_base.py`: dùng chung `scam_e5_int8.onnx` (`34.30 MB`, 7 lớp + vector 384 chiều) + `vn_scam_kb.json` (`20` kịch bản, `18` BIN, `17` thương hiệu).
  - `assistant_*` (12 module): `assistant_rag.py` (`121` chunk, RAM mean-centering + BM25 + RRF + Scope Gate), `assistant_vault.py` (`RequestEntityVault` + `_ShieldBox`), `assistant_tools.py` (5 tool read-only chỉ nhận `*_REF_*`), `assistant_guardrails.py` (bộ lọc `<think>` + cổng 3 tầng `Tier 0/1/2`), `assistant_service.py`, `assistant_llm.py`, `assistant_evidence.py`, `assistant_stage.py`, `assistant_slots.py`.
  - `llm_client.py`, `llm_resilience.py`, `ai_orchestrator.py`, `risk_calibrator.py`, `action_copilot.py`, `image_forensics.py`, `receipt_validator.py`, `vietqr_parser.py`, `local_stt.py`, `pii_scrubber.py`, `report_pdf.py`, `telegram_*.py`.

### 2.2. Frontend (`frontend/src/`)
- **4 Route App Router:**
  - `/`: `DemoScenarioBar`, `InputWorkbench` + `MultimodalComposer` (gộp chế độ tự suy luận Option A, dán ảnh `Ctrl+V`, đa ảnh/audio), `LiveTracePanel`, `VerdictDashboard`, `WalletPreTransferSim` (30s), `EvidenceTabs` (5 tab), `ActionCopilotPanel` (PDF bằng `fetch` + `X-Case-Access-Token`), `AssistantDrawer` + `SafeMarkdown`.
  - `/radar`: `IocGraphSvg` (khung `radarLayout.ts` spatial hash `O(N)`, imperative `rAF` zoom/pan, tooltip `translate3d`, bảng thay thế), `CampaignQueue`, `CampaignDetailDrawer`, `BlockRuleManager`, `RuleActionModal`, `ApiPlaygroundCard` (`is_simulation=true`).
  - `/technical` & `/privacy`: Trang tài liệu tương tác dùng `DocsShell`, sơ đồ SVG có `DrawOnView`, và `SiteFooter` (`FooterTelegramLink`).
- **Motion UX (`components/motion/`, `lib/motion/`):** `Lenis` (`^1.3.29`) + `Motion` (`^14.14.0`, `LazyMotion` `domAnimation`) + `AnimatedNumber` + `SpotlightGroup` + `DrawOnView`; có `frontendLicenses.test.ts` khóa chặt chỉ cho phép thư viện license mở an toàn.

### 2.3. Đánh giá, Triển khai & Kiểm thử
- **3 Bộ Benchmark (`evaluation/`):**
  - 40 ca chính (`results.json`): `Precision/Recall/F1 = 1.0`, `Advisory FPR = 0.0`, `ONNX P50 = 10ms`, `E2E P50 = 7.18s` (chạy trên `gemini-4-hydrogen`).
  - Assistant RAG (`rag_ablation_results.json`, 159 ca — 97 held-out): chế độ `B6` đạt `R@3 = 98.4%`, `OOD Reject = 100%`, `FRR = 1.56%`.
  - OCR (`ocr_benchmark/results.json`, 25 ảnh): `PP-OCRv5 Latin use_cls=False` đạt `Exact CER 0.1096`, `ASCII CER 0.0294`, `p50 = 733.5 ms`, `12.14 MB`, `336.2 MB` Peak RSS.
- **Deploy (`deploy/`, `docker-compose*.yml`, `backend/Dockerfile`, `frontend/Dockerfile`):**
  - 3 container (`backend` `2200m`, `frontend` `512m`, `caddy` `256m`), `read_only: true`, `cap_drop: ALL`, mạng tách biệt, pre-bake Whisper `tiny` + RapidOCR PP-OCRv5 trong image Backend, `.gitattributes` ép `LF` cho script Linux.
- **Kiểm thử:** `52` file test Backend (`365` test functions) + `8` file test Frontend (`node --test`).

---

## 3. Các Điểm Lệch & Tồn đọng Cần Xử lý (Ưu tiên Từ Cao đến Thấp)

1. **[Cao] Tài liệu nộp bài (`submission/`) chưa khớp trạng thái code `1bfc688`:**
   - `slides/index.html`, `guide/index.html`, `video-script-3min.md` vẫn giữ mô tả "chuyển giữa 3 chế độ Cá nhân/Chủ cửa hàng/Ví" (giao diện `/` đã đổi sang `MultimodalComposer` tự suy luận), chưa cập nhật **Trợ lý VeriShield RAG**, **PP-OCRv5**, **Radar 120 FPS**, còn dùng một số từ khóa cũ trái `TERMINOLOGY.md` (`Pháp y...`, `Khóa làm nguội 30s`, `Fraud Ops`, `1-Chạm`, lộ `in_active_call`/`HTTP 409`), và `submission/dist/*.pdf` vẫn là bản build từ 26/11.
2. **[Cao] `onnx_session.py` (`ORT_ENABLE_ALL`) vs `onnxruntime 1.32.0` trên Windows:**
   - Khi kiểm thử trước lúc pull với `onnxruntime 1.32.0`, `ORT_ENABLE_ALL` làm `advisory_probability` của `scam_e5_int8.onnx` lệch xuống `0.5666` (rớt ngưỡng `>= 0.60` trong `test_scam_classifier.py`), còn `ORT_ENABLE_BASIC` khôi phục `0.7156` và nhanh hơn (`10ms`). Cần kiểm tra lại ngay trên `backend/.venv` sau khi pull và áp dụng `ORT_ENABLE_BASIC` nếu tái diễn.
3. **[Trung bình] Đồng bộ môi trường & dữ liệu Benchmark trước khi render PDF cuối:**
   - Chạy `npm.cmd ci` tại `frontend/` để cài `lenis` + `motion`.
   - `evaluation/results.json` được chạy từ `2026-11-26T10:02Z` với `gemini-4-hydrogen` (trước khi nâng OCR & WP-1..WP-11); cần chạy lại bằng model production thật trước khi render PDF cuối.
4. **[Trung bình] Độ phủ Smoke Test & Cạnh nhỏ trong Pipeline / UI / Telegram:**
   - `scripts/smoke_test_live.py` chưa có bước kiểm thử `/api/v1/assistant/chat/stream`.
   - `pipeline.py` đang bỏ qua `transfer_amount` (`_ = transfer_amount` ở dòng 355); `_resolve_media_lists` bỏ qua `image_bytes` nếu `image_items` có phần tử.
   - `EvidenceTabs.tsx`: tab `receipt` luôn truyền `report.image_forensics` (ảnh đầu) thay vì `activeForensics` khi tải nhiều ảnh, và chưa gắn `key={report.case_id}` nên tab đang chọn giữ nguyên khi đổi ca.
   - `AssistantDrawer.tsx`: `detectEvidenceAttachmentKind` chưa chặn `image/svg+xml` giống `composerUtils.ts` và auto-scroll xuống cuối mỗi token delta; các modal/drawer trên `/radar` (`CampaignDetailDrawer`, `RuleActionModal`, `ApiPlaygroundCard`) chưa có Tab focus-trap; `IocGraphSvg` fullscreen chưa gọi `useScrollLock`.
   - `phishing_detonator.py`: nếu redirect xảy ra ở đúng chặng thứ 5 (`MAX_SANDBOX_REDIRECT_HOPS`), vòng lặp thoát trước khi load `final_hop`.
   - `telegram_bot.py`: khi webhook trả lại từ cache (`claim_state == "cached"`) cho `/start`/`/demo`, `custom_markup` không được lưu nên mất bàn phím inline; `repository.py` lấy tối đa 8 IOC theo thứ tự `phones -> bank_accounts -> domains` nên >8 SĐT sẽ che mất domain/STK phía sau.
