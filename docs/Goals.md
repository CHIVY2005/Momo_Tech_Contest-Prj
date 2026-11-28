# Mục Tiêu & Tiến Độ Dự Án — VeriShield AI v2.0

> **Cập nhật:** `2026-11-28` · **Nhánh hiện tại:** `v3` (đã đồng bộ từ `feat/verishield-v2` @ `7e30ea0` + mock tests & báo cáo đánh giá PDF)  
> **Hiến pháp & Quy chế:** [AGENTS.md](../AGENTS.md) · [docs/momo.md](momo.md) · [docs/PROPOSAL.md](PROPOSAL.md) · [Báo cáo Đánh giá & Cải thiện (PDF)](VeriShield_AI_Danh_Gia_Va_Cai_Thien_Du_An.pdf)

---

## 1. Mục tiêu Cốt lõi & Ràng buộc Cuộc thi

- **Chủ đề:** *Imagine the Future Workspace (Human Centered. AI Powered)* — kết hợp trọn vẹn cả 3 nhánh **Chống lừa đảo**, **An ninh mạng**, và **Trợ lý AI**.
- **Sản phẩm trực tuyến Zero-Login:** `https://verishield.joiboi.app` (`/` kiểm tra đa phương thức & ngăn chặn trước chuyển tiền, `/radar` trung tâm giám sát gian lận khép kín, `/technical`, `/privacy`, `/api/docs`), kèm **Telegram Bot** (`@verishield...`) chuyển tiếp tin nhắn/ảnh/ghi âm.
- **Các bất biến bắt buộc (`AGENTS.md`):**
  1. Không dùng `"MoMo"` trong tên sản phẩm/giao diện/gói phần mềm (**VeriShield AI**).
  2. Chỉ dùng thư viện/mô hình giấy phép mở sạch (`MIT`, `Apache-2.0`, `BSD`, `ISC`, `LGPL-3.0`, `Bitstream Vera`) — cấm `AGPL-3.0` / research-only.
  3. 100% dữ liệu tổng hợp (synthetic) / trích cảnh báo công khai, không PII thật.
  4. Tách biệt tuyệt đối môi trường huấn luyện (`training/`) khỏi runtime (`backend/requirements.txt` không chứa `torch`/`transformers`; ONNX CPU `enable_cpu_mem_arena=False`, `enable_mem_pattern=False`, model `< 50 MB`).
  5. **Merchant Receipt Honesty Guardrail:** Ảnh biên lai không bao giờ được kết luận tiền đã vào tài khoản (`SAFE` vẫn là `UNVERIFIED_SCREENSHOT` + cảnh báo đối chiếu số dư thực tế / Loa thông báo).
  6. **Cổng kiểm định bắt buộc:** `scripts/verify.ps1` / `scripts/verify.sh` (`ruff` + `mypy --strict` + `pytest` + `tsc --noEmit` + `npm test` + `next build`).
- **Mốc thời gian cứng:**
  - **18:00 ngày 03/12/2026 (mục tiêu nội bộ) · 23:59:59 ngày 03/12/2026 (hạn chót):** Nộp đủ 4 hạng mục & **đóng băng tuyệt đối** mã nguồn, slide và bản deploy.
  - **08/12/2026:** Công bố Top 5 Vòng Chung kết.
  - **11/12/2026:** Thi Chung kết trực tiếp tại TP.HCM (slide không được sửa sau khi nộp; duy trì server live đến hết ngày thi).

---

## 2. Những Hạng mục Đã Hoàn thành (Tính đến `2026-11-28`)

- [x] **Backend 3 Tầng & Pháp y 4 Lớp (`FastAPI` + `SQLite WAL`):**
  - Pipeline bất đồng bộ SSE 4 chặng (`media_forensics` → `cyber_guardrails` → `onnx_and_kb` → `multimodal_calibration`) hỗ trợ đa ảnh (tối đa 4) và đa audio (tối đa 2).
  - Mô hình riêng `intfloat/multilingual-e5-small` (MIT) đóng băng + MLP 7 lớp, cắt tỉa `36.000` token Việt–Anh, lượng tử hóa thành `scam_e5_int8.onnx` (`34.30 MB`, `Test INT8 Macro-F1 = 0.9314`, `P50 = 10 ms` trên CPU).
  - Giải mã EMVCo TLV & `CRC-16/CCITT-FALSE` NAPAS VietQR (18 BIN), pháp y ảnh ELA + EXIF + dHash replay, kiểm tra logic nghiệp vụ biên lai VN, `faster-whisper` (`tiny` INT8) STT nội bộ.
- [x] **Module OCR Chuẩn hóa (`backend/app/services/ocr/`):**
  - Chọn **RapidOCR v3 PP-OCRv5 Latin ONNX (`use_cls=False`, `Apache-2.0`)** làm mặc định sau thực nghiệm 25 ảnh (`Exact CER 0.1096`, `ASCII CER 0.0294`, `p50 = 733.5 ms`, `12.14 MB`, `0` FP trên biên lai), pre-bake vào Docker image (`/app/ocr_cache`) + Gemini OCR fallback có giới hạn.
- [x] **Trợ lý VeriShield RAG (`assistant_*`):**
  - Chỉ mục `121` chunk (`40` SOP/hướng dẫn + `81` `vn_scam_kb`), truy hồi Hybrid RRF (`B6`: `R@3 = 98.4%`, `OOD Reject = 100%`, `FRR = 1.56%` trên `97` ca held-out), `RequestEntityVault`, Cổng an toàn đầu ra 3 tầng (`Tier 0/1/2`) chặn hallucination & số hotline không có căn cứ, và Phase-3 kiểm tra bằng chứng bổ sung tạm thời trên RAM (15 phút, `allow_external_media_ai=false` mặc định) + lưu hồ sơ con theo yêu cầu.
- [x] **Gia cố An ninh mạng Toàn diện (`NV-01..NV-41` / `WP-1..WP-11`):**
  - ID vụ việc 128-bit + token HMAC-SHA256 `X-Case-Access-Token` + khóa kênh Web vs Telegram riêng tư; chống SSRF/DNS Rebinding gắn chặt IP socket (`httpx` + Playwright); chống decompression bomb theo từng chunk; kiểm tra magic bytes & PyAV audio; băm IOC bằng HMAC-SHA256 (`IOC_HMAC_SECRET`); chống Prompt Injection đầu độc `/radar`; phân vùng slot SSE & giới hạn tốc độ kép.
- [x] **Telegram Bot Đa phương thức (`telegram_*`):**
  - Hỗ trợ ảnh, ghi âm, tài liệu ảnh/audio, `/start`, `/help`, `/demo`, `/call`, `/bill`, nút inline callback, lease `180s` chống xử lý trùng lặp, và gửi PDF riêng tư 1-1 qua `callback_data="pdf:{case_id}"`.
- [x] **Frontend Next.js 15 Đầy đủ 4 Trang & Motion UX (`frontend/`):**
  - `/` (`MultimodalComposer` thống nhất nhận dán ảnh `Ctrl+V`/kéo thả, `VerdictDashboard`, `WalletPreTransferSim` 30s, 5 tab bằng chứng, `ActionCopilotPanel`, `AssistantDrawer` + `SafeMarkdown` không `dangerouslySetInnerHTML`).
  - `/radar` (đồ thị SVG tối ưu `O(N)` spatial hash đạt `98–120 FPS`, `0` chồng lấn ở 500 nút, tooltip không gây re-render, `CampaignDetailDrawer`, `RuleActionModal`, `ApiPlaygroundCard`).
  - `/technical`, `/privacy`, footer thống nhất & hiệu ứng chuyển động chỉ dùng thư viện `MIT` (`lenis`, `motion`) tuân thủ `prefers-reduced-motion` và WCAG 2.2.
- [x] **Bộ Kiểm thử & Chuốt Câu chữ UX (`7e30ea0` → hiện tại):**
  - Đồng bộ đủ 7 nhãn phân loại `SCAM_LABELS` (`SAFE_NORMAL..PROMPT_INJECTION`) ở cả Backend fallback (`ai_orchestrator.py`) và Frontend (`copy.ts`), sửa mốc thanh rủi ro `VerdictDashboard` (`0–24 / 25–54 / 55–79 / 80–100`), tách thẻ Radar `SAFE` vs có rủi ro, bỏ mô tả nội bộ `gemini-4-hydrogen` trên `/technical` và sửa mâu thuẫn `"ẩn danh"` vs `"che giấu/giả danh hóa"` trên `/privacy`.
  - Đạt **52 tệp kiểm thử Backend** (419/425 pass trên `.venv` Windows; 6 ca fail thuộc môi trường local thiếu `rapidocr` và `onnxruntime 1.32.0`), **9 tệp kiểm thử Frontend** (`60/60` test pass gồm [workbenchAndChatMock.test.ts](../frontend/src/lib/__tests__/workbenchAndChatMock.test.ts)), và **4/4 kịch bản E2E Chromium thật** qua [scripts/test_web_mock_e2e.py](../scripts/test_web_mock_e2e.py).
  - Xuất báo cáo đánh giá tổng thể bám sát đề bài cuộc thi tại [docs/VeriShield_AI_Danh_Gia_Va_Cai_Thien_Du_An.pdf](VeriShield_AI_Danh_Gia_Va_Cai_Thien_Du_An.pdf) (qua [scripts/generate_assessment_pdf.py](../scripts/generate_assessment_pdf.py)).

---

## 3. Checklist Việc Còn Lại Trước Hạn Nộp (`28/11 → 03/12/2026`)

- [x] **Cài đặt gói Frontend (`npm.cmd ci`) & Kiểm định Build/Test/Lint:** `tsc --noEmit`, `60/60` `npm test`, `next build` (8/8 route tĩnh), `4/4` Playwright mock E2E, `ruff` & `mypy --strict` (71 file) đều đã đạt.
- [ ] **Đồng bộ Môi trường Backend & Cổng `verify.sh` (Docker Linux):**
  - Cài đủ `rapidocr` hoặc chạy `bash scripts/verify.sh` trong container Linux giống VPS thật; đánh giá chuyển `ORT_ENABLE_BASIC` trong `onnx_session.py` nếu môi trường runtime dùng `onnxruntime 1.32.0`.
- [ ] **Đồng bộ Tài liệu Nộp bài (`submission/`) theo Chuẩn Mới Nhất:**
  - Cập nhật `submission/slides/index.html`, `submission/guide/index.html`, và `submission/video-script-3min.md` theo quy chuẩn thuật ngữ `TERMINOLOGY.md` / `UX_COPY_AUDIT.md`, phản ánh đúng giao diện **Multimodal Composer thống nhất** (đã bỏ 3 nút chế độ cũ), **Trợ lý VeriShield RAG**, **PP-OCRv5**, **đồ thị `/radar` 120 FPS**, và số liệu mới nhất; làm động các thanh `%` trên Slide 8 và `{{ADV_FPR}}` trên Slide 1.
- [ ] **Làm mới Benchmark & Xuất PDF Cuộc thi:**
  - Cấu hình `backend/.env` với model chính thức dùng trên production (ví dụ `gemini-2.5-flash`), chạy lại `evaluation/run_benchmark.py --require-live-llm` để cập nhật `evaluation/results.json` khớp bản deploy.
  - Chạy `python submission/render_pdfs.py` tạo `submission/dist/VeriShield_AI_Slides_10p.pdf` (đúng `10` trang) & `VeriShield_AI_UserGuide_1p.pdf` (đúng `1` trang A4), kiểm tra mắt và quét thử QR trên điện thoại.
- [ ] **Triển khai Production VPS & Kiểm thử Trực tuyến:**
  - Chuẩn bị `deploy/.env.prod` (thiết lập `APP_ENV=demo` + `ANALYST_PIN=2026` cho môi trường chấm thi công khai hoặc thông số theo HDSD, đủ `IOC_HMAC_SECRET`, `CASE_TOKEN_SECRET`, `TELEGRAM_WEBHOOK_SECRET`), chạy `bash deploy/deploy_vps.sh`.
  - Mở rộng/chạy `scripts/smoke_test_live.py` (nên kiểm tra thêm `/api/v1/assistant/chat/stream`), kiểm tra trên trình duyệt ẩn danh Desktop + 4G Mobile, và đặt monitor uptime 5 phút/lần đến hết **11/12/2026**.
- [ ] **Quay Video Demo (≤ 3 phút MP4) & Đóng gói `.zip`:**
  - Quay trực tiếp trên `https://verishield.joiboi.app` (`02:45–02:55`, 1080p `.mp4`).
  - Chạy `python scripts/package_submission.py` tạo `submission/dist/verishield-ai-source.zip` (chỉ đóng gói file đã commit trong Git), giải nén kiểm tra lại từ đầu.
- [ ] **Nộp Bài Sớm Trước 18:00 Ngày 03/12/2026 & Đóng Băng Hệ Thống:**
  - Tải đủ 4 hạng mục lên `techday.momo.vn`, chụp biên nhận nộp bài, tuyệt đối không sửa code/slide/deploy đè sau hạn chót.
