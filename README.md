# VeriShield AI v2.0

**Không gian Điều tra Lừa đảo Đa phương thức, Chốt chặn Phút 89 & Trung tâm Điều hành Fraud Ops Khép kín**

> *Imagine the Future Workspace (Human Centered. AI Powered)* — Tổ hợp tích hợp cả 3 chủ đề: **Chống lừa đảo**, **An ninh mạng** và **Trợ lý AI**.

- **Trải nghiệm Trực tuyến (Zero-Login, dùng ngay):** `https://verishield.joiboi.app`
- **Không gian Điều hành Fraud Ops Khép kín:** `https://verishield.joiboi.app/radar`
- **Tài liệu OpenAPI / Swagger:** `https://verishield.joiboi.app/api/docs`

---

## 1. Tóm tắt Vấn đề & Giá trị Cốt lõi

Phần lớn các vụ lừa đảo tài chính tại Việt Nam diễn ra ở **"Phút 01 đến Phút 88"** bên ngoài ứng dụng thanh toán (tin nhắn SMS mạo danh NAPAS/ngân hàng kèm tên miền đồng hình Punycode, cuộc gọi giả danh Công an/Viện Kiểm sát yêu cầu cài `.apk`, ảnh biên lai chuyển khoản chỉnh sửa gửi qua Zalo cho chủ cửa hàng, hoặc bẫy lừa quét mã VietQR để "nhận tiền hoàn"). Khi nạn nhân mở ví xác nhận chuyển tiền ở **"Phút 89"**, họ đã rơi vào trạng thái hoảng loạn tâm lý nên các dòng chữ cảnh báo tĩnh thường bị bỏ qua.

**VeriShield AI v2.0** giải quyết trọn vẹn vòng đời này cho **3 nhóm người dùng**:

1. **Người dùng cá nhân (`personal` & `wallet_transfer`):**
   - Thẩm định đa phương thức (Văn bản, URL, Ảnh chụp màn hình/QR, File ghi âm cuộc gọi) với luồng tiến trình thời gian thực (`SSE`).
   - **Chốt chặn Phút 89 (`30s Cooling-Off Lock`):** Kết hợp tín hiệu ngữ cảnh `in_active_call` (đang nghe điện thoại khi chuyển tiền) với đồng hồ làm nguội 30 giây và bộ câu hỏi phá vỡ thao túng tâm lý.
   - **Action Copilot:** Gợi ý câu phản hồi cắt đuôi kẻ gian 1-Click, tin nhắn *Lá chắn Gia đình* và xuất hồ sơ pháp y tố giác `.pdf` tiếng Việt.
2. **Chủ hộ kinh doanh / Cửa hàng (`merchant`):**
   - **Pháp y Biên lai 4 Lớp:** Giải mã khung EMVCo TLV & kiểm tra mã `CRC-16/CCITT-FALSE` chuẩn NAPAS VietQR, phân tích bản đồ nhiệt sai số nén `ELA`, kiểm tra phương sai chiều cao khung chữ `RapidOCR`, đối soát mã giao dịch/thời gian/tài khoản thụ hưởng và chống gửi lại biên lai cũ (`dHash` replay).
   - **Nguyên tắc Trung thực Tuyệt đối:** Ngay cả khi ảnh biên lai không có dấu hiệu cắt ghép (`SAFE`), hệ thống luôn gắn nhãn `UNVERIFIED_SCREENSHOT` kèm cảnh báo bắt buộc đối chiếu biến động số dư thực tế / Loa thông báo trước khi giao hàng.
3. **Đội ngũ Vận hành Chống Gian lận Fintech (`/radar`):**
   - Đồ thị liên kết chiến dịch & cụm IOC (`SĐT`, `STK`, `Domain`) đã được băm `SHA-256` và che dấu PII ngay từ tầng lưu trữ.
   - **1-Click Ecosystem Block (`TTL 30 phút` + bảo vệ IOC sạch `HTTP 409`):** Biến một ca cảnh báo đơn lẻ thành quy tắc chặn tức thì trên toàn hệ thống, kiểm chứng trực tiếp ngay tại **API Playground**.

---

## 2. Kiến trúc Kỹ thuật 3 Tầng & Kết quả Thực nghiệm (40 Ca Tiếng Việt)

```
[Người dùng / Chủ shop / Ví / Bot Telegram]
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ TẦNG 1: DETERMINISTIC CYBERSECURITY & CUSTOM ONNX (< 50ms nội bộ)      │
│ • Chống SSRF gắn chặt IP công cộng đến tầng socket (httpx + Playwright) │
│ • Giải mã EMVCo VietQR CRC-16 · Pháp y ảnh ELA + EXIF + dHash + OCR     │
│ • Mô hình riêng: pruned multilingual-e5-small INT8 ONNX (34.25 MB, 11ms)│
│ • Guardrails nhận diện khuyến cáo chính thống & bẫy Prompt Injection     │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ Dữ liệu bọc trong <UNTRUSTED_USER_CONTENT>
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ TẦNG 2: SUY LUẬN ĐA PHƯƠNG THỨC LINH HOẠT (OpenAI-Compatible / Gemini)  │
│ • Hỗ trợ song song CLIProxyAPI (OpenAI-compatible) & Google Gemini SDK  │
│ • Timeout, Retry-After (HTTP 429), Backup-Key Failover & Degraded Mode  │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ TẦNG 3: HIỆU CHUẨN 3 TÍN HIỆU, ACTION COPILOT & FRAUD OPS (/radar)      │
│ • Sàn điểm bảo mật cứng · Khóa làm nguội 30s · SQLite WAL · Báo cáo PDF │
└─────────────────────────────────────────────────────────────────────────┘
```

### Số liệu Benchmark Thực tế (`evaluation/results.json` — 40 ca tổng hợp tiếng Việt & Red-Team)

| Chỉ số Thực nghiệm | Kết quả Đo Thực tế | Ghi chú |
| --- | --- | --- |
| **Precision / Recall / F1** | **`1.0000` / `1.0000` / `1.0000`** | Đúng `40/40` ca (`28` ca lừa đảo/tấn công, `12` ca sạch) |
| **Tỷ lệ Báo động giả trên Tin Khuyến cáo (`Advisory FPR`)** | **`0.0000` (`0%`)** | `5/5` tin khuyến cáo chính thống đều được xếp `SAFE` (`2–3/100`) |
| **Tỷ lệ Chặn Tấn công `Prompt Injection`** | **`1.0000` (`100%`)** | Chặn toàn bộ kỹ thuật thoát thẻ XML & ghi đè điểm số |
| **Tỷ lệ Phát hiện `Fake Bill` & Bẫy `VietQR`** | **`1.0000` (`100%`)** | Bắt trọn lỗi sửa số tiền, sai STK nhận, sai CRC-16 |
| **Dung lượng & Độ trễ `scam_e5_int8.onnx` (CPU)** | **`34.25 MB` · `P50 = 11 ms` (`P95 = 13 ms`)** | Cắt tỉa từ vựng Việt–Anh (`36.000` token), không cần PyTorch |
| **Model Suy luận Đa phương thức Thực tế** | `gemini-4-hydrogen` (`40/40` ca, `0` lỗi API) | Độ trễ toàn trình `E2E P50 = 7.17s` |

---

## 3. Hướng dẫn Chạy Nhanh (Docker hoặc Thủ công)

### Cách 1: Chạy bằng Docker Compose (Khuyên dùng)

```bash
# 1. Sao chép file cấu hình mẫu và điền khóa API của bạn (tùy chọn — nếu để trống hệ thống tự chạy chế độ Tầng 1 nội bộ)
cp backend/.env.example backend/.env

# 2. Khởi chạy toàn bộ Backend (cổng 8000) & Frontend (cổng 3000)
docker compose up --build
```

Sau khi khởi chạy, mở trình duyệt tại `http://localhost:3000` (hoặc `/radar` tại `http://localhost:3000/radar`). Mã PIN mặc định cho Giám khảo thử tính năng Khóa 1-Click trên `/radar` là **`2026`**.

### Cách 2: Chạy Thủ công trong Môi trường Phát triển

**Yêu cầu:** Python `3.11+` và Node.js `20+`.

```powershell
# Terminal 1 — Khởi chạy Backend FastAPI
cd backend
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt -r requirements-dev.txt
copy .env.example .env
# (Điền GEMINI_API_KEY vào backend/.env; hỗ trợ cả Google AI Studio hoặc cổng OpenAI-compatible qua LLM_PROVIDER & GEMINI_BASE_URL)
.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 2 — Khởi chạy Frontend Next.js 15
cd frontend
npm install
npm run dev
```

### Chạy Cổng Kiểm định Tự động (`ruff` + `mypy --strict` + `pytest` + `tsc` + `node --test` + `next build`)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
```

---

## 4. Danh mục Tài sản Có sẵn, Thư viện Mã nguồn mở & Công cụ AI (Tuân thủ Quy chế)

### 4.1. Mô hình AI & Trọng số Cơ sở
| Thành phần | Nguồn gốc | Giấy phép | Mục đích sử dụng |
| --- | --- | --- | --- |
| `intfloat/multilingual-e5-small` | Microsoft / HuggingFace | `MIT` | Backbone huấn luyện tinh chỉnh bộ phân loại 7 lớp & nhúng ngữ nghĩa tiếng Việt (`scam_e5_int8.onnx` `34.25 MB`) |
| `RapidOCR` (`PP-OCRv4` ONNX) | RapidAI / PaddleOCR | `Apache-2.0` | Trích xuất văn bản & tọa độ dòng chữ nội bộ trên biên lai |
| `faster-whisper` (`CTranslate2`) | SYSTRAN | `MIT` | Gỡ băng giọng nói cuộc gọi nội bộ dự phòng |
| `Gemini` / OpenAI-Compatible API | Google GenAI / CLIProxyAPI | API Thương mại | Suy luận giải thích đa phương thức Tầng 2 (có chế độ dự phòng Tầng 1 khi không cấu hình khóa) |

### 4.2. Thư viện Mã nguồn mở chính
- **Backend Python:** `FastAPI` (`MIT`), `Pydantic v2` (`MIT`), `Uvicorn` (`BSD-3-Clause`), `HTTPX` (`BSD-3-Clause`), `ONNX Runtime` (`MIT`), `Tokenizers` (`Apache-2.0`), `OpenCV-Headless` (`Apache-2.0`), `Pillow` (`MIT-CMU`), `NumPy` (`BSD-3-Clause`), `Playwright` (`Apache-2.0`), `fpdf2` (`LGPL-3.0`), phông chữ `DejaVuSans.ttf` (`Bitstream Vera`).
- **Frontend Web:** `Next.js 15` (`MIT`), `React 19` (`MIT`), `TypeScript` (`Apache-2.0`), `Tailwind CSS v4` (`MIT`), `Lucide Icons` (`ISC`).

### 4.3. Công cụ AI Hỗ trợ Phát triển & Cam kết Dữ liệu / Pháp lý
- **Công cụ hỗ trợ lập trình & kiểm định mã nguồn:** Google Antigravity & OpenAI Codex CLI (rà soát bảo mật và kiểm thử tự động).
- **Cam kết Dữ liệu & Nhãn hiệu:** 100% dữ liệu huấn luyện, 5 kịch bản Demo, danh mục IOC mồi và 40 ca Benchmark là **dữ liệu tổng hợp (synthetic)** hoặc trích lọc cấu trúc từ thông báo cảnh báo công khai — hoàn toàn không chứa dữ liệu cá nhân thật (PII). Tên sản phẩm và thương hiệu dự thi (`VeriShield AI`) tuân thủ nghiêm ngặt quy định sở hữu trí tuệ.
