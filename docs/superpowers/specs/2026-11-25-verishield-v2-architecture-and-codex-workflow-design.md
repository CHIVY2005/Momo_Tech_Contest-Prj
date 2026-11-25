# VeriShield AI v2.0 — Thiết Kế Kiến Trúc, Cấu Trúc Monorepo & Quy Trình Phối Hợp Antigravity × Codex

- **Ngày lập:** 26/11/2026
- **Cuộc thi mục tiêu:** MoMo Tech Contest 2026 (*Imagine the Future Workspace — Human Centered. AI Powered*)
- **Các mốc cố định:** Đăng ký đội thi trước `23:59:59, 27/11/2026` · Nộp bài & đóng băng hệ thống trước `18:00, 03/12/2026` (hạn chót `23:59:59, 03/12/2026`) · Vòng Chung kết TechDay `11/12/2026`
- **Hạ tầng triển khai:** `https://verishield.joiboi.app` chạy 24/7 trên VPS Ubuntu truyền thống (**2–4 vCPU · 4–8 GB RAM**, Singapore/Việt Nam); tận dụng **Docker Agentic Platform (`8–16 vCPU`) / Colab** cho tác vụ huấn luyện nhanh mô hình ONNX.
- **Mô hình phát triển:** **Antigravity** trực tiếp triển khai toàn bộ mã nguồn, bộ sinh PDF nộp bài, chạy thực nghiệm 40 ca với API key thật và deploy lên VPS; **Codex CLI** chạy cục bộ ngay trong thư mục repo để review độc lập từng Task.

---

## 1. Mục Đích & Định Vị Chiến Lược (Intent & The Why)

### 1.1. Giải bài toán "Phút thứ 01–88" thay vì lặp lại "Phút thứ 89"
Các siêu ứng dụng thanh toán tại Việt Nam hiện đã có hệ thống chấm điểm giao dịch nội ứng dụng, gắn nhãn tài khoản nhận (Xanh/Vàng/Đỏ) và sinh trắc học khuôn mặt tại **"Phút thứ 89"** (thời điểm người dùng bấm nút chuyển tiền). Tuy nhiên, hơn 90% vụ chiếm đoạt hiện nay là **lừa đảo thao túng tâm lý (Authorised Push Payment — APP Scam)** diễn ra từ **Phút thứ 01 đến Phút thứ 88** bên ngoài ví điện tử: qua tin nhắn Zalo/SMS Brandname giả mạo NAPAS, mã QR bị dán đè tại quầy, biên lai chuyển khoản giả gửi cho tiểu thương, website phishing viết bằng SPA/JS né trình quét tĩnh, hoặc cuộc gọi giả danh Công an/Viện Kiểm sát thúc ép chuyển tiền vào tài khoản rác mới mở.

**VeriShield AI v2.0** được xây dựng để:
1. **Bảo vệ người dùng cá nhân & tiểu thương ở Phút 01–88 đến Phút 89:** Điều tra đa phương thức (văn bản, URL động, ảnh chat, mã VietQR, biên lai chuyển khoản, ghi âm cuộc gọi) với bằng chứng vật lý & mật mã kiểm chứng được, kết hợp can thiệp hành vi (**Khóa làm nguội 30 giây** khi phát hiện đang nghe điện thoại `in_active_call`).
2. **Hiện thực hóa "Future Workspace" cho đội ngũ Fraud Ops / SecOps Fintech (`/radar`):** Gom tự động các chỉ báo xâm nhập (IOC đã ẩn danh PII) từ người dùng và Telegram Bot thành cụm chiến dịch lừa đảo, cho phép chuyên viên bấm **1-Click Duyệt & Phát lệnh Chặn** để bảo vệ toàn hệ thống trong `< 10ms` (*"Một người báo cáo, triệu người được bảo vệ"*).

### 1.2. Tối ưu riêng cho cặp `Antigravity (Builder) × Codex CLI (Reviewer)`
Để Codex CLI chạy trực tiếp trong repo Windows đạt chất lượng review cao nhất:
- Đồng bộ tuyệt đối tài liệu đặc tả với mã nguồn để triệt tiêu lỗi *spec drift*.
- Khóa cứng hợp đồng kiểu tĩnh (`Pydantic v2` + `mypy` + `ruff` + `TypeScript strict`), giới hạn mỗi module dịch vụ nhỏ gọn (`~150–280 dòng`) ánh xạ 1–1 với file unit test.
- Đặt `AGENTS.md` và `scripts/verify.ps1` tại gốc repo làm cổng kiểm định tự động sau mỗi Task.

---

## 2. Mục Tiêu, Phi Mục Tiêu & Điều Cấm Kỵ (Goals, Non-Goals & Anti-Goals)

### 2.1. Mục tiêu bắt buộc (Goals)
- **Trực tuyến không ma sát 24/7 trên `https://verishield.joiboi.app` (VPS 8 vCPU / 16 GB RAM):** Bấm vào dùng ngay không cần đăng nhập; chịu tải mượt 30–50 người quét QR trải nghiệm đồng thời ngay trên sân khấu Chung kết TechDay; có sẵn **5 kịch bản 1-Click Demo thời sự VN** + tải tệp thật của BGK + **Telegram 1-Tap Forward Bot**.
- **Kiến trúc Lai Neuro-Symbolic 3 Tầng tận dụng tối đa sức mạnh 8 vCPU / 16 GB RAM:**
  - **Tầng 1 — Local Deterministic Security, Forensics & Multi-Engine CPU AI (Chạy độc lập 100% kể cả khi đứt Internet/LLM ngoài):**
    1. **Active Block Rules (`< 10ms`)** từ không gian Fraud Ops `/radar`.
    2. **Guardrails (`guardrails.py`):** Chống báo động giả trên tin khuyến cáo chính thống & bẫy Adversarial Prompt Injection.
    3. **Dual-Head `multilingual-e5-small` INT8 ONNX (`MIT License`, cắt từ vựng VI+EN còn `~35 MB`, `< 15ms` trên 8 vCPU):** Trả đồng thời xác suất 7 lớp lừa đảo và vector ngữ nghĩa 384 chiều. *(Nhờ VPS 8 vCPU / 16 GB RAM, có thể huấn luyện/tái tạo model trực tiếp trên VPS hoặc Colab trong vài phút mà không bị lệ thuộc GPU ngoài).*
    4. **Local Vietnamese OCR & Bounding-Box Geometry (`RapidOCR` PP-OCRv4 ONNX, `Apache-2.0`, `~100ms`):** Đọc chữ tiếng Việt và tọa độ khung bao `[x, y, w, h]` từng dòng ngay ở Tầng 1 $\rightarrow$ đo toán học độ lệch cỡ chữ/thẳng hàng trên Fake Bill và giúp hệ thống **vẫn đọc được ảnh chat/bill 100% khi Gemini gặp sự cố**.
    5. **Local Fast Call Transcription (`faster-whisper` INT8, `MIT License`, `~1s` trên 8 vCPU):** Chuyển ngữ trực tiếp file ghi âm cuộc gọi tiếng Việt để đẩy `transcript` tức thì lên luồng SSE và đảm bảo phân tích âm thanh không bao giờ chết khi đứt API ngoài.
    6. **Giải mã EMVCo VietQR TLV + CRC-16/CCITT-FALSE (`vietqr_parser.py`)** & **Trích xuất IOC Việt Nam (`SHA-256` + `mask_ioc`)**.
    7. **Kiểm tra URL & Buồng Cô lập Phishing Động (`url_inspector.py` + `phishing_detonator.py`):** Kết hợp kiểm tra tĩnh (SSRF/DNS Guard, IDN Punycode/Homoglyph, RDAP, URLhaus) với **Headless Chromium Sandbox (Playwright giới hạn 3s, chặn mọi IP nội bộ ở tầng mỗi request mạng)** để mở trang phishing viết bằng JS/SPA, phát hiện form thu thập OTP/mật khẩu/tải `.apk` ẩn và chụp ảnh bằng chứng an toàn cho BGK/chuyên viên xem mà không cần tự bấm link độc.
    8. **4 Lớp Kiểm chứng Biên lai (`image_forensics.py` + `receipt_validator.py`):** Bản đồ nhiệt ELA + EXIF + mã băm `dHash` chống gửi lại bill cũ + đo độ lệch dòng/cỡ chữ từ hộp bao `RapidOCR` + kiểm tra mã FT/BIN/thời gian/STK chủ shop.
  - **Tầng 2 — Deep Multimodal Grounded Reasoning (`Gemini 2.5 Flash`):** Đối chiếu **20 kịch bản lừa đảo Việt Nam** (gồm mạo danh SMS NAPAS 11/2026), thẩm định sâu ngữ cảnh hội thoại/hình ảnh/giọng nói thúc ép, hợp nhất điểm rủi ro 3 tín hiệu (`0–100`) kèm cơ chế tự động rơi về `degraded_mode` giàu thông tin (dùng kết quả `E5 ONNX` + `RapidOCR` + `faster-whisper` + `Playwright` + `KB`) trả HTTP 200 nếu API ngoài lỗi.
  - **Tầng 3 — Action Copilot & Closed-Loop Fraud Ops:** Khóa làm nguội 30s (`in_active_call`) trên Ví mô phỏng, câu chất vấn ngược 1 chạm, Thẻ Gia đình, **Hồ sơ Tố giác PDF tiếng Việt**, và không gian `/radar` gom chiến dịch + duyệt luật chặn 1 chạm có cách ly phiên chấm thi.
- **Tự động hóa trọn gói Thực nghiệm & Bộ Hồ sơ PDF Chung kết:**
  - Chạy thực nghiệm thật **Benchmark 40 ca tiếng Việt & Red-Team** với `GEMINI_API_KEY` thật, xuất `evaluation/results.json` và biểu đồ chuẩn.
  - Xây dựng bộ sinh tự động HTML/CSS $\rightarrow$ PDF chất lượng trình chiếu (qua Playwright Chromium) cho **Slide thuyết trình (`<= 10 trang PDF`)** và **Hướng dẫn sử dụng (`<= 1 trang A4 PDF` kèm QR trực tiếp tới `https://verishield.joiboi.app`)**, đảm bảo số liệu trên Slide khớp 100% với `evaluation/results.json`.

### 2.2. Phi mục tiêu (Non-Goals)
- Không xây dựng eKYC nhận diện khuôn mặt / chống Deepfake video khuôn mặt.
- Không kết nối vào hệ thống hạch toán ngân hàng thật.
- Không bắt người dùng/BGK tạo tài khoản hay đăng nhập.

### 2.3. Điều cấm kỵ (Anti-Goals)
1. **Không chạy LLM sinh văn bản cỡ lớn (7B/8B như Ollama) trên CPU của VPS 8 vCPU:** *(Quyết định kỹ thuật quan trọng)* Chạy LLM 7B trên CPU mất 30–60 giây/câu trả lời và làm nghẽn toàn bộ 8 nhân khi có 2–3 Giám khảo bấm cùng lúc. Tài nguyên 8 vCPU / 16 GB RAM chỉ dành cho các mô hình chuyên biệt tốc độ mili-giây (`E5 ONNX`, `RapidOCR ONNX`, `faster-whisper INT8`) và buồng cô lập `Playwright`; phần lập luận ngôn ngữ sâu dùng `Gemini 2.5 Flash` bất đồng bộ (`~1.5–2.5s`).
2. **Không bao giờ phán ảnh chụp biên lai là "Tiền đã về an toàn":** Luôn gắn `receipt_verification_status = "UNVERIFIED_SCREENSHOT"` và cảnh báo đối chiếu biến động số dư / Loa thông báo cho mọi ảnh biên lai chưa đối soát sổ cái, kể cả khi `risk_score <= 24`.
3. **Không dùng tài nguyên sai bản quyền** (loại bỏ hoàn toàn `uitnlp/visobert` *research-only* và `phobert` `AGPL-3.0`; chỉ dùng `MIT` / `Apache-2.0` / `BSD`) và **không chứa chữ `"MoMo"`** trong tên sản phẩm/tên đội.
4. **Không để nhiễm bẩn dữ liệu giữa các Giám khảo** trên `/radar` và **không bao giờ để lộ SSRF qua Headless Browser** (mọi sub-request trong Playwright đều phải đi qua bộ lọc IP công khai trước khi kết nối).

---

## 3. Kiến Trúc Hạ Tầng Trên VPS `8 vCPU / 16 GB RAM` (`verishield.joiboi.app`)

```text
                       [Internet HTTPS (HTTP/2 & HTTP/3)]
                                       │
                        verishield.joiboi.app (Port 443)
                                       ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  Container 1: Caddy 2 Reverse Proxy                                        │
│  • Auto TLS Let's Encrypt · Security Headers · Gzip/Zstd                   │
│  • /api/* -> backend:8000 (flush_interval -1 cho SSE · max_body 11MB)      │
│  • /*     -> frontend:3000                                                 │
└──────────────────┬───────────────────────────────────────┬─────────────────┘
                   ▼                                       ▼
┌─────────────────────────────────────────┐ ┌────────────────────────────────┐
│  Container 2: Backend FastAPI           │ │  Container 3: Frontend Next.js │
│  (6 vCPU limit · 8 GB RAM limit)        │ │  (2 vCPU · 2 GB RAM)           │
│  • E5 Dual-Head INT8 ONNX (~35MB, 12ms) │ │  • Next.js 15 Standalone       │
│  • RapidOCR PP-OCRv4 ONNX (~100ms)      │ │  • Workbench + Wallet 30s Sim  │
│  • faster-whisper INT8 (~1s Vietnamese) │ │  • Closed-Loop Radar Graph     │
│  • VietQR CRC-16 + 4-Layer Forensics    │ └────────────────────────────────┘
│  • Gemini 2.5 Flash Async + Fallback    │
│  • SQLite WAL (/data/verishield.db)     │
└──────────────────┬──────────────────────┘
                   │ Nội bộ RPC / Context cô lập (mem_limit: 2GB, no-new-privileges)
                   ▼
┌─────────────────────────────────────────┐
│  Sandboxed Chromium Phishing Detonator  │
│  • Playwright Headless (timeout 3.0s)   │
│  • Route-level DNS/IP SSRF Blocker      │
│  • Bắt DOM OTP/Password/.apk & Chụp ảnh │
└─────────────────────────────────────────┘
```

- **Phân bổ tài nguyên trên 16 GB RAM:** Toàn bộ hệ thống khi chạy tải cao chỉ tiêu thụ **~3.0 – 4.5 GB RAM**, còn dư hơn **11 GB RAM** cho page cache OS và hàng chục kết nối đồng thời, đồng thời cho phép chạy trực tiếp `training/train_export_e5_onnx.py` ngay trên chính VPS (hoặc Colab) khi cần huấn luyện lại mà không ảnh hưởng dịch vụ!

---

## 4. Các Phương Án Đã Cân Nhắc (Approaches Considered)

| Phương án | Tóm tắt kỹ thuật | Đánh đổi | Quyết định |
| :--- | :--- | :--- | :--- |
| **Phương án 1 (Nâng cấp cho VPS 8C/16G): VeriShield AI v2.0 Full Local-First Cascade + Cloud Multimodal** | Dùng `multilingual-e5-small` (`MIT`, cắt từ vựng còn `~35 MB`) + `RapidOCR ONNX` + `faster-whisper INT8` + `VietQR CRC-16` + `Playwright Phishing Detonator` ở Tầng 1, kết hợp `Gemini 2.5 Flash` ở Tầng 2 và tự động xuất PDF Slide/HDSD. | Nhiều thành phần tích hợp hơn bản cơ bản, cần giữ kỷ luật tách nhỏ module. | **ĐÃ CHỌN** — Tận dụng triệt để 8 vCPU / 16 GB RAM mà không làm chậm hệ thống; sống khỏe 100% trên cả Văn bản, Ảnh, Âm thanh, URL động ngay cả khi mất API ngoài. |
| **Phương án 2: Chạy LLM 7B/8B cục bộ (Ollama) trên VPS 8 vCPU** | Thay Gemini bằng mô hình 7B chạy CPU. | Độ trễ vọt lên 30–60 giây/yêu cầu, nghẽn CPU khi chấm thi song song. | Loại bỏ. |
| **Phương án 3: Giữ nguyên bản v0.1.0 (`uitnlp/visobert` + ELA đơn thuần)** | Không có OCR/STT/Browser cục bộ, vướng giấy phép *research-only*. | Rủi ro pháp lý và mù hoàn toàn với ảnh/audio khi LLM ngoài quá tải. | Loại bỏ. |

---

## 5. Thiết Kế Kỹ Thuật Chi Tiết

### 5.1. Cấu trúc Thư mục Monorepo Chuẩn Hóa

```text
momo-tech-contest-prj/
├── AGENTS.md                           # "Hiến pháp" cho Antigravity & Codex CLI (bất biến bảo mật, giới hạn dòng, lệnh verify)
├── README.md                           # Tài liệu nộp bài chuẩn thể lệ (link live, cách chạy, OSS/AI licenses, synthetic data)
├── CHANGELOG.MD
├── LICENSE                             # MIT License
├── .gitignore
├── docker-compose.yml                  # Chạy kiểm thử đầy đủ local / BGK
├── docker-compose.prod.yml             # Chạy production trên VPS 8C/16G (Caddy HTTPS + Backend + Frontend)
│
├── deploy/
│   ├── Caddyfile                       # HTTPS verishield.joiboi.app, SSE flush_interval -1, Security Headers
│   ├── .env.prod.example
│   └── deploy_vps.sh                   # Script tự động build, healthcheck & smoke-test trên VPS
│
├── docs/
│   ├── momo.md
│   ├── Brief.md
│   ├── PROPOSAL.md                     # Đặc tả sản phẩm cập nhật đồng bộ v2.0
│   ├── IMPLEMENTATION_PLAN.md          # Kế hoạch Task-by-Task cho Antigravity code & Codex CLI review
│   └── superpowers/specs/
│       └── 2026-11-25-verishield-v2-architecture-and-codex-workflow-design.md
│
├── backend/
│   ├── Dockerfile                      # python:3.12-slim + Playwright Chromium + ffmpeg-lite + non-root user
│   ├── pyproject.toml                  # Cấu hình pytest, ruff, mypy nghiêm ngặt
│   ├── requirements.txt                # Runtime (onnxruntime, rapidocr-onnxruntime, faster-whisper, playwright, google-genai...)
│   ├── requirements-dev.txt            # pytest, pytest-asyncio, ruff, mypy, respx
│   ├── .env.example
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py                   # Pydantic Settings (API keys, feature toggles cho CI nhẹ vs VPS full)
│   │   ├── main.py                     # FastAPI app factory, lifespan nạp sẵn ONNX, middlewares
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── common.py               # Enums, TraceStep, EvidenceItem, ExtractedIOCs
│   │   │   ├── forensics.py            # VietQRInfo, UrlFinding, SandboxInspection, ImageForensicsResult, ReceiptLogicResult
│   │   │   ├── analysis.py             # ScamClassifierOutput, ActionBundle, AnalysisReport, DemoScenario
│   │   │   └── radar.py                # BlockRule, CreateBlockRuleRequest, RadarGraphResponse
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── security.py             # SSRF IP/DNS validator (dùng chung cho httpx & Playwright), upload guard, PIN/Bot auth
│   │   │   └── onnx_session.py         # Cấu hình chuẩn ONNX Runtime (enable_cpu_mem_arena=False, intra_threads=4)
│   │   ├── db/
│   │   │   ├── __init__.py
│   │   │   └── repository.py           # SQLite WAL: cases, ioc_sightings, receipt_hashes, block_rules (TTL + protected demo)
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── guardrails.py           # Safety Advisory filter + Adversarial Prompt-Injection trap
│   │   │   ├── scam_classifier.py      # Pruned E5 Dual-Head INT8 ONNX (~35MB): 7-class + 384-d L2 embedding
│   │   │   ├── local_ocr.py            # RapidOCR ONNX wrapper: trích xuất văn bản TV + bounding boxes đo lệch dòng
│   │   │   ├── local_stt.py            # faster-whisper INT8 wrapper: chuyển ngữ cuộc gọi TV nhanh + graceful skip
│   │   │   ├── ioc_extractor.py        # SĐT/STK/URL/Brand VN + SHA-256 + mask_ioc
│   │   │   ├── vietqr_parser.py        # Giải mã EMVCo TLV + NAPAS Tag 38 + kiểm tra toán học CRC-16/CCITT-FALSE
│   │   │   ├── url_inspector.py        # IDN Punycode/Homoglyph + safe redirect trace + RDAP/URLhaus
│   │   │   ├── phishing_detonator.py   # Playwright Headless Sandbox (route-level SSRF block, bắt form OTP/.apk, chụp ảnh)
│   │   │   ├── image_forensics.py      # ELA JPEG 90% + phương sai 16x16 + EXIF + dHash + OpenCV QR
│   │   │   ├── receipt_validator.py    # Logic FT/BIN/Timestamp + lệch hình học từ local_ocr + STK chủ shop + Replay check
│   │   │   ├── knowledge_base.py       # Hybrid Retriever (384-d cosine + BM25-lite fallback) trên 20 playbooks VN
│   │   │   ├── risk_calibrator.py      # Hàm thuần hợp nhất điểm 3 tín hiệu, sàn/trần bảo mật & Merchant Guardrail
│   │   │   ├── ai_orchestrator.py      # Gemini 2.5 Flash async client (Safety settings, <UNTRUSTED_USER_CONTENT>, fallback)
│   │   │   ├── action_copilot.py       # 30s Cooling-Off, Counter-Replies, Family Card, Merchant Balance Warning
│   │   │   ├── report_pdf.py           # Xuất Hồ sơ Tố giác PDF tiếng Việt (fpdf2 + DejaVuSans.ttf)
│   │   │   ├── telegram_bot.py         # Webhook Telegram 1-Tap Forward Bot
│   │   │   └── pipeline.py             # Điều phối bất đồng bộ 3 tầng & phát sự kiện SSE TraceStep thời gian thực
│   │   ├── api/v1/                     # router.py, health.py, analyze.py, cases.py, radar.py, telegram.py
│   │   └── data/                       # vn_scam_kb.json, demo_scenarios.json, seed_iocs.json, demo_media/, fonts/, models/
│   └── tests/
│       ├── conftest.py
│       ├── unit/                       # Kiểm thử đơn vị 1-1 cho mọi module (mock mạng/trình duyệt chạy < 5s)
│       └── integration/                # test_api_routes.py, test_sse_stream.py, test_security_redteam.py
│
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   ├── next.config.ts
│   └── src/
│       ├── app/                        # `/` (Workbench + Ví mô phỏng 30s) & `/radar` (Fraud Ops Workspace)
│       ├── components/                 # workbench/, evidence/ (có thêm PhishingSandboxCard), wallet/, copilot/, radar/
│       └── lib/                        # types.ts, api.ts, sse.ts
│
├── training/
│   ├── requirements-train.txt
│   ├── generate_vn_dataset.py          # Sinh >= 3.500 mẫu tiếng Việt hợp pháp 7 lớp
│   └── train_export_e5_onnx.py         # Fine-tune E5 -> Cắt gọn từ vựng VI+EN -> Xuất INT8 ONNX (~35MB) + embeddings KB
│
├── evaluation/
│   ├── dataset_vn_benchmark.json       # 40 ca tiếng Việt & Red-Team
│   ├── run_benchmark.py                # Chạy benchmark thật xuất evaluation/results.json & biểu đồ SVG/PNG
│   └── README.md
│
├── scripts/
│   ├── verify.ps1                      # Lệnh kiểm định chuẩn trên Windows cho Antigravity & Codex CLI
│   ├── verify.sh                       # Lệnh kiểm định trên Linux/VPS
│   └── package_submission.py           # Đóng gói tệp verishield-ai-source.zip sạch tuyệt đối (< 60MB, không chứa .env)
│
└── submission/
    ├── slides/                         # Bản thiết kế HTML/CSS chuẩn 16:9 (10 trang) nhúng trực tiếp số liệu từ evaluation/results.json
    ├── guide/                          # Bản thiết kế HTML/CSS chuẩn 1 trang A4 kèm mã QR live https://verishield.joiboi.app
    ├── render_pdfs.py                  # Dùng Playwright xuất `VeriShield_AI_Slides_10p.pdf` & `VeriShield_AI_UserGuide_1p.pdf` + kiểm tra đúng số trang!
    └── video-script-3min.md            # Kịch bản chi tiết từng giây quay sản phẩm chạy thật (2:45)
```

### 5.2. Cắt gọn Từ vựng Mô hình ONNX (`~35 MB`) — Sạch Git & Gọn File `.zip`
- Mô hình gốc `intfloat/multilingual-e5-small` (`MIT License`) chứa bảng từ vựng 250.002 token của 100 ngôn ngữ (`~96 MB` chỉ riêng ma trận nhúng).
- Trong `training/train_export_e5_onnx.py`, sau khi fine-tune 7 lớp, script tự động lọc giữ lại toàn bộ token Tiếng Việt + Tiếng Anh + chữ số/ký tự ASCII/biểu tượng phổ biến (`~38.000 token`), xây lại `tokenizer.json` tương ứng và lượng tử hóa động sang INT8:
  - Dung lượng `scam_e5_int8.onnx` giảm từ `~118 MB` xuống còn **`~35 MB`** (`tokenizer.json` `~2.5 MB`).
  - Commit trực tiếp vào Git không vướng giới hạn `100 MB` của GitHub, đóng gói trọn vào `verishield-ai-source.zip` để BGK giải nén chạy offline ngay không cần tải thêm trọng số ngoài.

### 5.3. Quy trình Phối hợp `Antigravity (Builder) ↔ Codex CLI (Reviewer)`
1. Ở Task đầu tiên, Antigravity khởi tạo `AGENTS.md` và `scripts/verify.ps1` quy định mọi bất biến kiến trúc & an ninh mạng.
2. Ở từng Task tiếp theo:
   - Antigravity viết unit/integration test trước $\rightarrow$ cài đặt code sạch kiểu tĩnh $\rightarrow$ chạy pass `powershell -ExecutionPolicy Bypass -File scripts/verify.ps1` $\rightarrow$ tạo commit rõ ràng.
   - Bạn chạy `codex` CLI ngay trong thư mục repo để review commit vừa tạo.
   - Bạn chuyển kết quả review của Codex cho Antigravity xác minh và xử lý dứt điểm trước khi sang Task kế tiếp.

---

## 6. Tổng Hợp Các Quyết Định Kỹ Thuật Đã Chốt (Summary of Calls Made)

1. **Đã cập nhật theo xác nhận của bạn:**
   - Antigravity trực tiếp chạy thực nghiệm 40 ca bằng API key thật trong `.env` và trực tiếp triển khai/kiểm thử lên VPS `verishield.joiboi.app` khi bạn cấp kết nối.
   - Antigravity xây dựng luôn hệ thống HTML/CSS + `submission/render_pdfs.py` (Playwright) tự động kết xuất **Slide PDF (`<= 10 trang`)** và **HDSD PDF (`<= 1 trang A4` có QR)** kèm kiểm tra cứng giới hạn số trang.
2. **Các quyết định kỹ thuật do Antigravity đề xuất cho cấu hình VPS 8 vCPU / 16 GB RAM (bạn kiểm tra khi duyệt):**
   - Bổ sung 3 engine cục bộ siêu tốc vào Tầng 1: **`RapidOCR ONNX`** (đọc chữ + đo lệch khung bao Fake Bill trong `~100ms`), **`faster-whisper INT8`** (chuyển ngữ ghi âm tiếng Việt trong `~1s`), và **`Playwright Phishing Detonator`** (cô lập mở link phishing động trong `<= 3s` có khóa chặn SSRF từng request, bắt form OTP/`.apk` và chụp ảnh bằng chứng).
   - **Không** chạy LLM sinh văn bản 7B/8B trên CPU để tránh nghẽn 30–60 giây/request; giữ `Gemini 2.5 Flash` cho tầng lập luận sâu (`~2s`).
   - Cắt từ vựng mô hình `multilingual-e5-small` (`MIT`) về Tiếng Việt + Tiếng Anh để file `scam_e5_int8.onnx` chỉ nặng `~35 MB`, vừa vặn trong Git và file `.zip` nộp bài.
