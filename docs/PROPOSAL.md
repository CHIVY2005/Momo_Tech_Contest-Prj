# PROPOSAL & ĐẶC TẢ THIẾT KẾ SẢN PHẨM (v2.0)
## VeriShield AI — Trợ lý AI Đa phương thức Điều tra Bằng chứng & Phòng vệ Lừa đảo Giao dịch Số

> **Cuộc thi:** MoMo Tech Contest (TechDay 2026)  
> **Chủ đề lớn:** *Imagine the Future Workspace (Human Centered. AI Powered)*  
> **Nhánh chủ đề dự thi:** Kết hợp tự nhiên **3 trụ cột** `Trợ lý AI` + `Chống lừa đảo` + `An ninh mạng` trên một luồng bảo vệ giao dịch thống nhất  
> **Tên miền trực tuyến:** `https://verishield.joiboi.app`  
> **Ngày cập nhật v2.0:** 26/11/2026 · **Hạn đăng ký:** 23:59:59, 27/11/2026 · **Hạn nộp bài:** 23:59:59, 03/12/2026 · **Chung kết:** 11/12/2026

---

## 1. Tóm tắt Điều hành (Executive Summary)

Các siêu ứng dụng tài chính tại Việt Nam hiện đã làm rất tốt việc chấm điểm hành vi giao dịch nội ứng dụng, gắn nhãn tài khoản nhận (Xanh/Vàng/Đỏ) và xác thực sinh trắc học tại **"Phút thứ 89"** — khoảnh khắc người dùng nhấn nút chuyển tiền. Tuy nhiên, hơn 90% thiệt hại lừa đảo hiện nay là **thao túng tâm lý (Authorised Push Payment — APP Scam)** diễn ra từ **Phút thứ 01 đến Phút thứ 88** bên ngoài ví điện tử: qua tin nhắn Zalo/SMS Brandname mạo danh NAPAS, website phishing viết bằng SPA/JS, mã QR bị dán đè tại quầy, biên lai Fake Bill gửi cho tiểu thương, hoặc cuộc gọi giả danh Công an thúc ép chuyển tiền vào tài khoản rác mới mở.

**VeriShield AI** lấp đầy khoảng trống **Phút 01–88 $\rightarrow$ Phút 89** cho người dùng cá nhân và tiểu thương, đồng thời cung cấp **Không gian làm việc Khép kín cho Đội ngũ Fraud Ops / SecOps Fintech (`/radar`)** để hiện thực hóa phương châm *"Một người báo cáo, triệu người được bảo vệ"* chỉ với 1 cú nhấp chuột.

Hệ thống vận hành theo kiến trúc **Lai Neuro-Symbolic 3 Tầng (Local-First Multi-Engine Cascade + Cloud Multimodal)**:
1. **Tầng 1 — Deterministic Security, 4-Layer Forensics & Dual-Head ONNX (`< 60ms` văn bản / `< 150ms` ảnh trên CPU, 0 phụ thuộc GPU runtime):**
   - **Bảo mật Mạng & Buồng Cô lập Phishing Động:** Chặn SSRF/DNS Rebinding, bắt giả mạo tên miền IDN Punycode/Homoglyph, giải mã toán học chuẩn **EMVCo VietQR TLV + CRC-16/CCITT-FALSE**, và kích hoạt **Headless Chromium Sandbox (`Playwright` giới hạn 3s)** để mở trang phishing động, bắt form thu thập OTP/mật khẩu/tải `.apk` ẩn kèm ảnh chụp bằng chứng an toàn.
   - **Mô hình AI Tự huấn luyện Sạch Pháp lý (`intfloat/multilingual-e5-small`, `MIT License`, ONNX INT8 `~35 MB`):** Fine-tune trên 3.500+ mẫu tổng hợp tiếng Việt, cắt gọn bảng từ vựng VI+EN để vừa phân loại 7 lớp rủi ro vừa xuất vector ngữ nghĩa 384 chiều trong `< 20ms` trên CPU.
   - **OCR & Chuyển ngữ Cục bộ + Kiểm chứng Biên lai 4 Lớp:** Kết hợp **`RapidOCR` (PP-OCRv4 ONNX)** đo độ lệch khung bao chữ số, **`faster-whisper` INT8** chuyển ngữ cuộc gọi tiếng Việt tức thời, bản đồ nhiệt **ELA + EXIF + mã băm `dHash` chống gửi lại bill cũ**, kiểm tra nghiệp vụ mã giao dịch FT/BIN/thời gian/STK chủ shop và **Rào chắn Trung thực Tiểu thương** (không bao giờ kết luận ảnh chụp màn hình là "tiền đã về" khi chưa đối soát số dư).
2. **Tầng 2 — Deep Multimodal Grounded Reasoning (`Gemini 2.5 Flash` / Cổng OpenAI-Compatible như `CLIProxyAPI`):**
   - Thẩm định sâu ngữ cảnh hội thoại, hình học biên lai, sắc thái giọng nói thúc ép đối chiếu với **20 kịch bản lừa đảo Việt Nam** (bao gồm chiến dịch SMS giả mạo NAPAS tháng 11/2026), hợp nhất điểm rủi ro hiệu chuẩn 3 tín hiệu (`0–100`) và tự động chuyển sang `degraded_mode` giàu thông tin nếu API ngoài quá tải.
3. **Tầng 3 — Multi-Touchpoint Action Copilot & Closed-Loop Fraud Ops:**
   - Hỗ trợ **Web Workbench**, **Telegram 1-Tap Forward Bot**, **Mô phỏng Ví Điện Tử** tự bật **Khóa làm nguội 30 giây (`in_active_call`)**, xuất **Hồ sơ Tố giác PDF tiếng Việt**, và không gian `/radar` gom cụm IOC ẩn danh + duyệt luật chặn 1 chạm có cơ chế cách ly an toàn giữa nhiều Giám khảo.

---

## 2. Giải quyết Triệt để Khoảng trống của Giải pháp Hiện tại

| Giải pháp hiện có | Lỗ hổng cốt lõi | Đột phá của VeriShield AI v2.0 |
| :--- | :--- | :--- |
| Chấm điểm giao dịch nội ví ở "Phút thứ 89" | Không thấy quá trình thao túng ở Phút 01–88 trên Zalo/SMS/cuộc gọi; kẻ gian dùng tài khoản rác mới tinh chưa bị gắn nhãn Đỏ. | Nối trực tiếp bằng chứng ngoài ví (tin nhắn, QR, cuộc gọi, link) thành **tín hiệu tiền giao dịch** + **Khóa làm nguội 30s (`in_active_call`)**. |
| Chatbot LLM đơn thuần ("LLM Wrapper") | Ảo giác, dính Prompt Injection, mù trước mã VietQR thanh toán và trang phishing SPA, sập hoàn toàn khi đứt API ngoài. | **Local-First Cascade**: `E5 Dual-Head ONNX` + `VietQR CRC-16` + `RapidOCR` + `faster-whisper` + `Playwright Sandbox` chạy độc lập với kiểm chứng toán học. |
| Công cụ soi Fake Bill đơn giản dựa vào ELA/EXIF | Web tạo Fake Bill hiện đại xuất thẳng từ HTML5 Canvas (không có vết cắt ghép ELA, không có EXIF); Zalo nén lại xóa sạch metadata. | **4-Layer Honest Receipt Forensics**: ELA/EXIF + Đo lệch khung bao chữ `RapidOCR` + `dHash` chống dùng lại bill cũ + Logic FT/BIN/STK chủ shop + Rào chắn bắt buộc kiểm tra số dư. |

---

## 3. Kiến trúc Kỹ thuật Tổng thể

- **Thiết kế chi tiết & Cấu trúc Monorepo:** Xem tại [2026-11-25-verishield-v2-architecture-and-codex-workflow-design.md](superpowers/specs/2026-11-25-verishield-v2-architecture-and-codex-workflow-design.md).
- **Kế hoạch triển khai từng Task TDD:** Xem tại [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

### Danh mục 11 Endpoint API (`backend/app/api/v1/`)
| Endpoint | Method | Chức năng |
| :--- | :--- | :--- |
| `/api/v1/health` | `GET` | Trạng thái dịch vụ, SQLite WAL, E5 ONNX, RapidOCR, faster-whisper & Gemini |
| `/api/v1/demos` | `GET` | Danh sách 5 kịch bản 1-Click Demo thời sự VN cho Ban Giám Khảo |
| `/api/v1/analyze` | `POST` | Phân tích đồng bộ (`mode`, `text`, `url`, `image`, `audio`, `demo_id`, `in_active_call`, `transfer_amount`, `expected_merchant_account`) |
| `/api/v1/analyze/stream` | `POST` | Phân tích đẩy từng bước `TraceStep` thời gian thực qua SSE (`text/event-stream`) |
| `/api/v1/bot/telegram` | `POST` | Webhook Telegram 1-Tap Forward Bot (xác thực `X-Telegram-Bot-Api-Secret-Token`) |
| `/api/v1/cases/{case_id}` | `GET` | Chi tiết hồ sơ vụ việc đã ẩn danh hóa PII |
| `/api/v1/cases/{case_id}/report.pdf` | `GET` | Xuất Hồ sơ Trình báo Tố giác PDF tiếng Việt (`fpdf2` + `DejaVuSans.ttf`) |
| `/api/v1/radar/graph` | `GET` | Đồ thị IOC ẩn danh, chiến dịch đang nổi & các Block Rules hiệu lực |
| `/api/v1/radar/block-rules` | `POST` | Chuyên viên duyệt 1 chạm ban hành Block Rule (TTL 30 phút, bảo vệ kịch bản mẫu) |
| `/api/v1/radar/block-rules/{rule_id}/revoke` | `POST` | Chuyên viên thu hồi từng Block Rule riêng lẻ theo `rule_id` |
| `/api/v1/radar/block-rules/reset` | `POST` | Khôi phục trạng thái mẫu sạch trên `/radar` cho lượt chấm mới |

---

## 4. Tuân thủ Thể lệ, Bản quyền & Bảo vệ Dữ liệu Cá nhân

1. **Nhãn hiệu (Điều 6.5):** Tên sản phẩm (**VeriShield AI**) và tên miền (`verishield.joiboi.app`) hoàn toàn độc lập, không chứa thương hiệu của BTC hay bên thứ ba.
2. **Sạch bản quyền Mã nguồn mở & Mô hình AI (Điều 12.5, 28, 31):** Chỉ sử dụng các mô hình và thư viện có giấy phép thương mại/mở rõ ràng (`intfloat/multilingual-e5-small` `MIT`, `faster-whisper` `MIT`, `rapidocr-onnxruntime` `Apache-2.0`, `FastAPI` `MIT`, `Next.js` `MIT`, `onnxruntime` `MIT`, `Playwright` `Apache-2.0`, `fpdf2` `LGPL-3.0`, `DejaVuSans` `Bitstream Vera`).
3. **Dữ liệu Huấn luyện & Kiểm thử Hợp pháp 100% (Điều 12.4):** Toàn bộ 3.500+ mẫu huấn luyện, 5 kịch bản demo, 40 ca benchmark và dữ liệu khởi tạo `/radar` là **dữ liệu tổng hợp (synthetic)** dựa trên các cảnh báo công khai của Bộ Công an / NAPAS; không chứa PII người thật; mọi SĐT/STK hiển thị trên giao diện đều được băm `SHA-256` và che giữa (`mask_ioc`).
4. **Vận hành Trực tuyến & Đóng băng sau Hạn nộp (Điều 10.4 & 31.4):** Triển khai HTTPS ổn định qua Caddy + Docker Compose trên VPS riêng (`https://verishield.joiboi.app`), hoàn tất nộp bài và đóng băng toàn bộ mã nguồn/slide/hạ tầng trước **18:00 ngày 03/12/2026**, duy trì hoạt động xuyên suốt qua **11/12/2026**.

---

## 5. Cấu trúc 10 Slide Thuyết trình Chuẩn Chung Kết (`Slide PDF ≤ 10 Trang`)

1. **Slide 1 — Trang bìa:** **VeriShield AI** — *Trợ lý AI Đa phương thức & Không gian Phòng vệ Giao dịch Số Trước Khi Tiền Rời Ví* (`Trợ lý AI` · `Chống lừa đảo` · `An ninh mạng`).
2. **Slide 2 — Bài toán "Phút thứ 01 đến Phút thứ 88":** Vì sao hơn 90% nạn nhân tự tay chuyển tiền vào tài khoản rác mới mở trước khi hệ thống nội ví ở Phút 89 kịp phát hiện.
3. **Slide 3 — Lỗ hổng của Chatbot thông thường & Công cụ soi ảnh cũ:** Ảo giác, dính Prompt Injection, mù trước mã VietQR thanh toán, trang phishing SPA và biên lai giả dựng từ Web Canvas.
4. **Slide 4 — Hành trình Đa điểm chạm Không Ma sát:** Web Workbench · Telegram 1-Tap Forward Bot · Ví Mô Phỏng (tín hiệu `in_active_call` + Khóa làm nguội 30s "Kiểm trước tin sau").
5. **Slide 5 — Kiến trúc Local-First Cascade 3 Tầng:** `Pruned E5 Dual-Head ONNX (<20ms)` + `VietQR CRC-16` + `RapidOCR` + `faster-whisper` + `Playwright Sandbox` kết hợp `Gemini 2.5 Flash`.
6. **Slide 6 — Chiều sâu An ninh mạng & Pháp y 4 Lớp:** Giải mã toán học EMVCo VietQR, cô lập trang phishing bắt form OTP/`.apk`, đo hình học Fake Bill chống nén Zalo & Rào chắn Trung thực Tiểu thương.
7. **Slide 7 — Future Workspace cho Đội ngũ Fraud Ops (`/radar`):** Luồng *"Một người báo cáo → AI gom cụm chiến dịch → Chuyên viên duyệt chặn 1 chạm → Miễn dịch toàn hệ thống <10ms"* *(kèm QR dùng thử live `verishield.joiboi.app`)*.
8. **Slide 8 — Thực nghiệm Định lượng & Red-Team Benchmark (40 Ca VN):** Confusion Matrix của mô hình ONNX tự huấn luyện, F1-score, `0%` báo động giả trên tin ngân hàng thật, `100%` chặn SSRF/Prompt Injection, độ trễ thực tế.
9. **Slide 9 — Hiệu quả Kinh tế & Khả năng Tích hợp Siêu Ứng Dụng:** Tầng lọc ONNX CPU `~35 MB` tiết kiệm >80% chi phí gọi LLM đám mây và giảm thời gian xử lý sự cố cho đội vận hành Fintech.
10. **Slide 10 — Tổng kết & Trải nghiệm Trực tiếp:** Ba cam kết cốt lõi (*Không ma sát · Kiểm chứng toán học không ảo giác · Khép kín bảo vệ cộng đồng*) + QR Web & Telegram Bot.
