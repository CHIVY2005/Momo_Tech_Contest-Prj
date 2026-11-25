# PROPOSAL & ĐẶC TẢ THIẾT KẾ SẢN PHẨM
## VeriShield AI — Trợ lý AI Đa phương thức Điều tra Bằng chứng & Phòng vệ Lừa đảo Giao dịch Số

> **Cuộc thi:** MoMo Tech Contest (Techday 2026)  
> **Chủ đề lớn:** *Imagine the Future Workspace (Human Centered. AI Powered)*  
> **Nhánh chủ đề dự thi:** Kết hợp tự nhiên **3 trụ cột** `Trợ lý AI` + `Chống lừa đảo` + `An ninh mạng` trên một luồng bảo vệ giao dịch thống nhất  
> **Cấu trúc đội ngũ:** 02 thành viên (**01 Chuyên gia AI & Multimodal Forensics** · **01 Chuyên gia Security & Web Fullstack**)  
> **Ngày lập:** 25/11/2026 · **Hạn nộp bài:** 23:59:59, 03/12/2026 · **Chung kết (Techday):** 11/12/2026

---

## 1. Tóm tắt Điều hành (Executive Summary)

**VeriShield AI** là một **hệ sinh thái trợ lý AI bảo vệ giao dịch số hoạt động trực tuyến thời gian thực**, đóng vai trò **"lớp phòng vệ thông minh ngay trước khi tiền rời ví"** dành cho người dùng cá nhân và tiểu thương tại Việt Nam, đồng thời cung cấp **Không gian làm việc Khép kín cho Đội ngũ Fraud Ops / SecOps Fintech (Closed-Loop Fintech Workspace)** để chặn đứng chiến dịch lừa đảo trên toàn hệ thống chỉ với 1 chạm.

Khác biệt hoàn toàn với các chatbot hỏi-đáp thông thường dễ ảo giác và dễ bị qua mặt, VeriShield AI kết hợp **chuyên môn kép AI Tự huấn luyện + An ninh mạng (Two-Stage Cascade & Hybrid Neuro-Symbolic Security Architecture)** qua 3 tầng:
1. **Tầng 1 — Deterministic Security, 3-Layer Fake-Bill Forensics & Custom Fine-Tuned `VisoBERT` (`< 80ms` trên CPU):**
   - **Lớp Bảo mật Mạng & Guardrails:** Giải mã QR, truy vết chuyển hướng URL an toàn (chống SSRF/DNS Rebinding), bắt giả mạo tên miền thương hiệu bằng **IDN Punycode / Homoglyph & Typosquatting**, tra tuổi tên miền (RDAP) & nguồn phishing (URLhaus), chặn **Adversarial Prompt Injection**, và lọc thông báo an toàn chính thống chống báo động giả.
   - **Lớp Pháp y Ảnh 3 tầng (Chống ảnh nén qua Zalo/Messenger):** (1) Phân tích vật lý Error Level Analysis (**ELA**) + phương sai cục bộ + chữ ký EXIF/XMP; (2) Kiểm tra hình học & typography chữ số bằng Thị giác máy tính; (3) Xác thực logic nghiệp vụ biên lai ngân hàng Việt Nam (`receipt_validator.py`: chuẩn mã giao dịch FT/Napas, thời gian hợp lệ, đầu số BIN/STK).
   - **Mô hình AI Tự huấn luyện Nội bộ (`VisoBERT` 7-Class INT8 ONNX):** Được đội ngũ tự sinh bộ dữ liệu tổng hợp tiếng Việt 3.500+ mẫu và fine-tune riêng cho bài toán tài chính VN, lượng tử hóa ONNX chạy trực tiếp trên CPU (`< 35ms`, `~100 MB`, không tốn GPU production) giúp sàng lọc rủi ro tức thì kể cả với tin nhắn không dấu, teencode hay lách luật.
2. **Tầng 2 — Deep Multimodal AI Reasoning & Vietnam Scam Knowledge Base (`Gemini 2.5 Flash`):**
   - Thực hiện OCR ảnh chat lộn xộn, kiểm tra hình học Fake Bill, chuyển ngữ ghi âm cuộc gọi (`transcript`), và đối chiếu cơ sở tri thức **16 kịch bản lừa đảo phổ biến tại Việt Nam** → lập luận có dẫn chứng kèm **Điểm rủi ro hiệu chuẩn đa tín hiệu (`0–100`)**.
3. **Tầng 3 — Multi-Touchpoint Action Copilot & Closed-Loop Fraud Ops:**
   - **Đa điểm chạm không ma sát (Zero-Habit Friction):** Hỗ trợ song song **Web Workbench**, **Telegram Bot Chuyển tiếp 1 chạm (1-Tap Forward Bot)** cho người lớn tuổi/chủ shop, và **Chế độ Mô phỏng Ví Điện Tử** tự động kích hoạt **Khóa làm nguội cảm xúc 30 giây (Psychological Cooling-Off)** khi phát hiện tín hiệu *"Đang trong cuộc gọi + Chuyển người lạ / Rủi ro cao"*.
   - **Hành động tức thì & Vòng lặp Fintech Workspace:** Sinh câu chất vấn ngược 1 chạm, tạo Thẻ Cảnh báo Gia đình, xuất **Hồ sơ Tố giác PDF tiếng Việt**, gom cụm trên **IOC Threat Radar** và cho phép chuyên viên Fintech bấm **"1-Click Duyệt & Kích hoạt Chặn Toàn Hệ Thống"** (`< 10ms` cho mọi giao dịch kế tiếp).

---

## 2. Bài toán Thực tế & Khoảng trống Hiện tại (Problem Statement)

### 2.1. Nỗi đau tại điểm chạm thanh toán số Việt Nam
- **Người dùng cá nhân & người lớn tuổi** thường bị kẻ gian thao túng tâm lý qua cuộc gọi/Zalo (giả danh Công an/Viện Kiểm sát/VNeID, giả shipper, việc nhẹ lương cao, khóa SIM, dụ quét QR hay cài file `.apk`). Khi đang hoảng loạn hoặc vừa nghe điện thoại vừa mở app chuyển tiền, họ không kịp nhận ra rủi ro và cũng không biết tự mở web kiểm tra.
- **Tiểu thương & chủ shop online** liên tục thiệt hại vì **Fake Bill chuyển khoản**; đáng ngại hơn, ảnh gửi qua Zalo/Messenger thường bị nén lại và xóa sạch EXIF, khiến các thuật toán soi ảnh đơn giản mất tác dụng.
- **Đội ngũ Risk / Fraud Ops / CSKH tại Fintech** cần chuyển từ phản ứng thụ động sang mô hình **"Future Workspace"**: gom tự động các phản ánh rời rạc thành chiến dịch đường dây và đẩy luật chặn tức thời bảo vệ toàn bộ người dùng trước khi dòng tiền bị tẩu tán.

### 2.2. Tại sao các giải pháp hiện có thất bại?
| Giải pháp hiện có | Lỗ hổng cốt lõi | Đột phá của VeriShield AI |
|---|---|---|
| Tra cứu danh sách đen SĐT/STK thủ công | Kẻ gian thay tài khoản rác (mule account) và domain mới mỗi ngày → tra cứu luôn chậm hơn kẻ lừa đảo. | Bắt trực tiếp **ngữ nghĩa thao túng (`VisoBERT`) + dấu vết kỹ thuật 3 tầng** ngay trên STK/link mới xuất hiện lần đầu, đồng thời đồng bộ luật chặn khép kín. |
| Chatbot LLM đơn thuần ("ChatGPT wrapper") | Ảo giác, chậm/đắt khi mở rộng triệu người dùng, mù trước Fake Bill nén qua Zalo, dễ dính **Prompt Injection**, dễ báo nhầm tin nhắn cảnh báo thật của ngân hàng. | **Two-Stage Cascade**: Model tự train **`VisoBERT` ONNX (`< 35ms`)** + **3-Layer Fake-Bill Forensics** + **URL/SSRF/Punycode Guard** gác cổng độc lập; VLM làm tầng giải thích & xử lý đa phương thức. |
| Web kiểm tra rời rạc & Cảnh báo tĩnh | Người lớn tuổi đang nghe cuộc gọi lừa đảo không nhớ mở web; cảnh báo chữ chung chung không ngăn được cú bấm xác nhận chuyển tiền. | **Đa điểm chạm & Can thiệp hành vi**: **Telegram Bot Forward 1 chạm** + Tín hiệu **`in_active_call` kích hoạt Khóa làm nguội 30s** trên Ví mô phỏng + Câu chất vấn ngược + PDF tố giác. |

---

## 3. Chiến lược Chốt Top 5 Vòng Chung Kết (Winning Strategy)

Theo Điều 18 & 19 của Thể lệ, mỗi bài dự thi được ít nhất **03 Giám khảo chấm độc lập** để chọn **Top 5 vào Chung kết** theo 3 tiêu chí. VeriShield AI được thiết kế tối ưu hóa điểm số ở cả 3 trụ cột:

1. **Tối đa hóa điểm *Sáng tạo* (Two-Stage Cascade AI + Cybersecurity + Closed-Loop Fintech):**
   - Sở hữu **mô hình `VisoBERT` 7 lớp tự fine-tune & lượng tử hóa ONNX INT8** chạy thẳng trên server CPU (không phải thin API wrapper), kết hợp **Pháp y ảnh Fake Bill 3 tầng chống nén Zalo**, **IDN Punycode/SSRF Guard**, **Adversarial Prompt-Injection Defense**, và **Khóa làm nguội 30s**.
2. **Tối đa hóa điểm *Chất lượng & Mức độ hoàn thiện* (Trải nghiệm "30 giây thuyết phục BGK"):**
   - **Zero-Friction Live Access:** Bấm link dùng ngay không cần đăng nhập; có sẵn **5 kịch bản 1-Click Demo thực tế** (gồm cả Prompt Injection và tin nhắn ngân hàng thật chống báo động giả) + **Telegram Bot Forward 1 chạm** + khả năng **tải lên dữ liệu thật của chính Giám khảo**.
   - **Minh bạch thời gian thực:** Hiển thị **Live Agent Security Trace (SSE Streaming)** từng bước chạy model tự train (`VisoBERT`), quét mạng, soi ELA và lập luận đa phương thức.
   - **Đánh giá định lượng chuẩn khoa học:** Bộ **40 ca kiểm thử tiếng Việt & Red-Team Security Benchmark** (bao gồm cả ảnh Fake Bill đã nén lại chuẩn Zalo) với biểu đồ F1-score, Confusion Matrix và độ trễ thực tế.
   - **Chịu lỗi cao 24/7:** Có cơ chế chuyển sang `degraded_mode` (dùng **`VisoBERT` ONNX + Tầng 1 Security + VN Scam KB**) nếu API ngoài quá tải — không bao giờ lỗi HTTP 500 trong suốt kỳ chấm thi 03/12 → 11/12/2026.
3. **Tối đa hóa điểm *Tiềm năng tác động* (Khép kín vòng lặp Fintech Workspace ↔ Người dùng cuối):**
   - Khớp 100% chủ đề *"Imagine the Future Workspace"*: minh họa trọn vẹn vòng đời **Người dùng/Bot phát hiện → AI gom chiến dịch trên Fraud Ops Workspace (`/radar`) → Chuyên viên Fintech duyệt chặn 1 chạm (`POST /api/v1/radar/block-rules`) → Mọi giao dịch kế tiếp trên Ví điện tử được bảo vệ tức thì**.

---

## 4. Kiến trúc Kỹ thuật & Thiết kế Hệ thống (Technical Design Spec)

### 4.1. Sơ đồ Kiến trúc Tổng thể

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                 ĐA ĐIỂM CHẠM NGƯỜI DÙNG & ĐỘI NGŨ FINTECH                    │
│  [Web Workbench]  [Ví Điện Tử Mô Phỏng: in_active_call + 30s Cooling-Off]    │
│  [Telegram 1-Tap Forward Bot]   [Fintech Fraud Ops Workspace (/radar)]       │
└───────────────────────────────────────┬──────────────────────────────────────┘
                                        │ HTTPS (Multipart / JSON / Webhook / SSE)
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     BACKEND SECURITY & AI API (FastAPI)                      │
│  [Security Middleware: CORS · Upload Cap 10MB · Rate Limit · Sec Headers]    │
│                                                                              │
│  ┌──────── TIER 1: DETERMINISTIC SECURITY, 3-LAYER FORENSICS & VISOBERT ───┐ │
│  │ 1. Active Block Rule Lookup (<10ms): Chặn ngay STK/SĐT/Domain đã duyệt  │ │
│  │ 2. Guardrails: Safety Advisory Filter + Adversarial Prompt-Injection Trap│ │
│  │ 3. Fine-Tuned VisoBERT 7-Class INT8 ONNX (<35ms CPU): Phân loại sắc thái│ │
│  │ 4. IOC Extractor: VN Phone, Bank Account, URL, Brand + SHA-256 & Masking│ │
│  │ 5. URL & QR Inspector: OpenCV QR -> SSRF/DNS Guard -> IDN Punycode &    │ │
│  │    Homoglyph/Typosquatting -> Redirect Trace -> RDAP Age & URLhaus      │ │
│  │ 6. 3-Layer Fake Bill: Layer 1 (ELA+EXIF) + Layer 3 (FT/BIN/Time Logic)  │ │
│  └────────────────────────────────────┬────────────────────────────────────┘ │
│                                       ▼                                      │
│  ┌────────────── TIER 2: MULTIMODAL AI & VN SCAM KNOWLEDGE ────────────────┐ │
│  │ 1. Vietnam Scam KB Retriever (16 Playbooks đặc thù VN + Merchant mode)  │ │
│  │ 2. Gemini 2.5 Flash: OCR Chat + Layer 2 Bill Typography/Geometry Check  │ │
│  │    + Audio STT Transcript + Grounded Evidence Reasoning                 │ │
│  │ 3. 3-Signal Calibrated Risk Fusion (Tier1 + VisoBERT + Gemini) & Fallback│ │
│  └────────────────────────────────────┬────────────────────────────────────┘ │
│                                       ▼                                      │
│  ┌───────────── TIER 3: ACTION COPILOT & CLOSED-LOOP FRAUD OPS ────────────┐ │
│  │ 1. Pre-Transfer Intervention (30s Cooling-Off + in_active_call trigger) │ │
│  │ 2. Smart Counter-Replies (1-click) & Family Shield Card                 │ │
│  │ 3. Incident Report PDF (fpdf2 + DejaVuSans.ttf Unicode tiếng Việt)      │ │
│  │ 4. SQLite IOC Threat Graph + 1-Click Block Rule Broadcast (/radar)      │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.2. Đặc tả Chi tiết 3 Tầng Xử lý & Các Nâng cấp Trọng tâm

#### Tầng 1 — Deterministic Security, 3-Layer Forensics & `VisoBERT` ONNX (`backend/app/services/`)
1. **`guardrails.py` — Chống Báo động giả & Phòng thủ Prompt Injection:**
   - **`detect_safety_advisory(text, has_suspicious_url)`:** Nhận diện tin nhắn khuyến cáo an toàn chính thống của ngân hàng/ví/cơ quan nhà nước khi không đi kèm link độc hại hay mệnh lệnh chuyển tiền/gửi OTP.
   - **`detect_prompt_injection(text)`:** Chuẩn hóa Unicode NFC, loại bỏ ký tự ẩn zero-width, bắt các mẫu tiêm lệnh điều khiển AI bằng tiếng Việt & tiếng Anh. Khi phát hiện: bật `prompt_injection_detected = True`, gắn bằng chứng `CRITICAL`, khóa sàn điểm rủi ro `>= 75`.
2. **`visobert_classifier.py` — Mô hình `VisoBERT` Tự Fine-tune 7 Lớp (`uitnlp/visobert`, MIT License):**
   - Huấn luyện riêng (trong thư mục `training/`) trên bộ **3.500+ mẫu tổng hợp & dữ liệu mở hợp pháp tiếng Việt** chia thành 7 lớp ngữ nghĩa:
     - `SAFE_NORMAL` (giao dịch/trò chuyện bình thường)
     - `SAFE_ADVISORY` (khuyến cáo bảo mật chính thống)
     - `SCAM_IMPERSONATION` (giả công an/VNeID/ngân hàng/shipper/khóa SIM)
     - `SCAM_TASK_INVEST_LOAN` (CTV làm nhiệm vụ/đầu tư lãi khủng/cho vay đóng phí)
     - `SCAM_PHISHING_APK_OTP` (link/QR giả mạo/cài `.apk`/lấy OTP & sinh trắc học)
     - `SCAM_URGENT_BORROW` (mạo danh người thân vay tiền khẩn cấp)
     - `PROMPT_INJECTION` (tiêm lệnh đánh lừa hệ thống AI)
   - Xuất sang **ONNX INT8 (`~100 MB`)**, chạy suy luận CPU qua `onnxruntime` trong **`< 35ms`**, trả về xác suất từng lớp và `visobert_scam_score` (`0–100`). Nếu thiếu file model trong môi trường test nhẹ, tự động chuyển sang trạng thái skipped an toàn.
3. **`ioc_extractor.py` — Trích xuất Thực thể Việt Nam & Bảo vệ PII:**
   - Trích xuất SĐT VN (`03/05/07/08/09`, `+84`), Số tài khoản ngân hàng theo ngữ cảnh (không nhầm với số tiền `2.500.000`), URL/domain và 20+ thương hiệu lớn VN.
   - Băm `SHA-256` để tra cứu trùng lặp và **Active Block Rules** trong `< 10ms`; áp dụng `mask_ioc` che ký tự giữa (`091****678`, `1903****6201`) trước khi hiển thị công khai.
4. **`url_inspector.py` — Kiểm tra QR & URL Chuẩn An ninh mạng:**
   - Giải mã QR từ ảnh bằng `cv2.QRCodeDetector()`.
   - **SSRF & DNS Rebinding Guard:** Chỉ cho phép `http`/`https`; phân giải DNS kiểm tra mọi IP đích và mọi bước redirect — chặn tuyệt đối IP loopback (`127.0.0.0/8`, `::1`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud metadata (`169.254.0.0/16`).
   - **IDN Punycode / Homoglyph & Typosquatting:** Giải mã `xn--...`, ánh xạ ký tự đồng hình (`0/o`, `1/l`, Cyrillic lookalikes) về dạng ASCII chuẩn trước khi so sánh với danh sách tên miền chính thức VN trong `vn_scam_kb.json`; kiểm tra chuỗi redirect tối đa 5 hop, tuổi domain qua `RDAP` (`< 30 ngày`) và tra cứu danh sách mã độc `URLhaus`.
5. **Hệ thống Phát hiện Fake Bill 3 Tầng (Chống ảnh bị nén qua Zalo/Messenger):**
   - **Lớp 1 (`image_forensics.py` — Vật lý):** Tính bản đồ nhiệt **ELA (Error Level Analysis)** JPEG 90%, đo độ lệch phương sai cục bộ trên lưới 16×16 phát hiện vùng số tiền/tên bị cắt ghép, và quét chữ ký phần mềm chỉnh sửa trong EXIF/XMP/PNG (`Photoshop`, `Canva`, `PicsArt`, `Photopea`, `GIMP`).
   - **Lớp 2 (Tier 2 VLM — Hình học & Typography):** Gemini Vision kiểm tra thẳng hàng pixel giữa các chữ số, phông chữ bất nhất, khoảng trắng bất thường hoặc sai quy chuẩn dấu phân cách hàng nghìn của biên lai ngân hàng Việt Nam.
   - **Lớp 3 (`receipt_validator.py` — Logic Nghiệp vụ Ngân hàng VN):** Kiểm tra hợp lệ mã tham chiếu giao dịch (`FT...` / mã Napas), phát hiện thời gian trên biên lai mâu thuẫn thực tế (giờ tương lai hoặc biên lai cũ tái sử dụng), định dạng số tiền/tài khoản phi lý — vẫn bắt được Fake Bill ngay cả khi ảnh bị Zalo/Messenger nén lại xóa hết EXIF.

#### Tầng 2 — Multimodal AI Reasoning & 3-Signal Risk Calibration (`knowledge_base.py`, `ai_orchestrator.py`)
1. **Cơ sở tri thức 16 Kịch bản Lừa đảo Việt Nam (`vn_scam_kb.json`):** Bao phủ đầy đủ 16 thủ đoạn phổ biến nhất tại Việt Nam kèm chiến thuật tâm lý, dấu hiệu nhận biết và mẫu câu đối chất.
2. **Gemini 2.5 Flash Multimodal Orchestrator:** Nhận văn bản/ảnh/ghi âm cuộc gọi (`audio` chuyển ngữ `transcript` tiếng Việt trực tiếp), bọc nội dung không tin cậy trong thẻ `<UNTRUSTED_USER_CONTENT>` chống Visual & Text Prompt Injection, kết hợp kết quả Tầng 1 + `VisoBERT` + Top-3 Playbooks để xuất JSON chuẩn hóa.
3. **Công thức Hiệu chuẩn Điểm Rủi ro 3 Tín hiệu (`calibrate_risk_score`):**
   - **Active Block Rule Hit:** Nếu STK/SĐT/Domain khớp luật chặn đang hoạt động từ Fraud Ops → khóa ngay `final_score >= 95` (`CRITICAL_SCAM`).
   - **Safety Advisory Cap:** Nếu `safety_advisory_detected == True` và không có URL độc/Fake Bill/Prompt Injection/Block Rule → khóa trần `<= 20` (`SAFE`).
   - **Hard Security Floors:** `prompt_injection_detected == True` → sàn `>= 75`; Domain giả mạo thương hiệu / Punycode / URLhaus → sàn `>= 80`; Lỗi logic nghiệp vụ biên lai nghiêm trọng / ELA tamper cao → sàn `>= 70`.
   - **Kết hợp đa tín hiệu:**
     - Chế độ đầy đủ (Tier 1 + `VisoBERT` + Gemini): `final_score = round(0.30 * tier1_score + 0.35 * visobert_score + 0.35 * gemini_score)` (cộng tối đa `+10` điểm ngữ cảnh nếu `in_active_call == True` và chuyển người nhận mới khi đã có dấu hiệu nghi vấn).
     - Chế độ dự phòng (`degraded_mode = True` khi API ngoài lỗi/429/timeout): `final_score = round(0.45 * tier1_score + 0.55 * visobert_score)`.
   - **4 Mức phán quyết:** `0–24` (`SAFE`) · `25–54` (`SUSPICIOUS`) · `55–79` (`HIGH_RISK`) · `80–100` (`CRITICAL_SCAM`).

#### Tầng 3 — Multi-Touchpoint Action Copilot & Closed-Loop Fraud Ops (`action_copilot.py`, `report_pdf.py`, `database.py`, `telegram_bot.py`)
1. **Can thiệp Trước Chuyển tiền (`PreTransferIntervention`):** Khi `risk_score >= 55` (hoặc có ngữ cảnh `in_active_call == True` kèm `risk_score >= 35`), bật lớp chắn **30 giây làm nguội cảm xúc** kèm danh sách câu hỏi kiểm chứng bắt buộc trên màn hình Ví điện tử mô phỏng.
2. **Telegram 1-Tap Forward Bot (`POST /api/v1/bot/telegram`):** Người dùng chỉ cần Forward tin nhắn, ảnh chụp chat, ảnh Fake Bill, hoặc ghi âm sang Bot Telegram của VeriShield AI để nhận kết quả phân tích + câu phản đòn trong 3–5 giây mà không cần mở trình duyệt.
3. **Câu chất vấn ngược, Thẻ Cảnh báo Gia đình & Hồ sơ PDF Tiếng Việt (`fpdf2` + `DejaVuSans.ttf`):** Cung cấp câu phản hồi 1 chạm, thẻ gửi người thân qua Zalo và xuất file PDF tố giác chuẩn Unicode.
4. **Closed-Loop Fintech Fraud Ops Workspace (`/radar` + `POST /api/v1/radar/block-rules`):** Đồ thị SQLite gom các vụ việc trùng IOC thành **Chiến dịch Lừa đảo Mới**; chuyên viên Fintech bấm **"1-Click Duyệt & Phát lệnh Chặn"** để kích hoạt quy tắc bảo vệ toàn hệ thống tức thì.

### 4.3. Danh mục 9 REST & Streaming API (`backend/app/main.py`)
| Endpoint | Method | Chức năng |
|---|---|---|
| `/api/v1/health` | `GET` | Kiểm tra sức khỏe dịch vụ, SQLite, trạng thái `VisoBERT ONNX` & Gemini API |
| `/api/v1/demos` | `GET` | Danh sách 5 kịch bản 1-Click Demo thực tế cho Ban Giám Khảo |
| `/api/v1/analyze` | `POST` | Phân tích đồng bộ (`mode`, `text`, `url`, `image`, `audio`, `demo_id`, `in_active_call`, `transfer_amount`) |
| `/api/v1/analyze/stream` | `POST` | Phân tích kèm **SSE Streaming** đẩy từng bước `TraceStep` thời gian thực |
| `/api/v1/bot/telegram` | `POST` | Webhook tiếp nhận tin nhắn/ảnh/voice Forward 1 chạm từ Telegram Bot |
| `/api/v1/cases/{case_id}` | `GET` | Truy xuất chi tiết hồ sơ vụ việc đã phân tích |
| `/api/v1/cases/{case_id}/report.pdf` | `GET` | Tải xuống Hồ sơ Trình báo Tố giác định dạng PDF tiếng Việt |
| `/api/v1/radar/graph` | `GET` | Lấy đồ thị IOC ẩn danh, các chiến dịch đang nổi & danh sách Block Rules |
| `/api/v1/radar/block-rules` | `POST` | Chuyên viên Fintech duyệt 1 chạm ban hành Block Rule cho STK/SĐT/Domain |

---

## 5. Tuân thủ Thể lệ, Bảo mật & Sở hữu Trí tuệ (Compliance Matrix)

| Quy định tại `Brief.md` & `the-le-cuoc-thi.pdf` | Thiết kế tuân thủ của VeriShield AI |
|---|---|
| **Điều 6.5 (Nhãn hiệu):** Không xâm phạm nhãn hiệu bên thứ ba. | Tên đội và tên sản phẩm (**VeriShield AI**) độc lập hoàn toàn, không chứa thương hiệu của BTC hay bên thứ ba. |
| **Điều 12.4 (Bảo vệ dữ liệu cá nhân):** Khai báo rõ nguồn dữ liệu & căn cứ sử dụng trong `README.md`. | Toàn bộ dữ liệu huấn luyện `VisoBERT` (3.500+ mẫu), kịch bản demo, benchmark 40 ca và IOC khởi tạo là **dữ liệu tổng hợp (synthetic)** hoặc trích cảnh báo công khai của cơ quan chức năng VN + dữ liệu mở có giấy phép hợp lệ; không chứa PII thật; mọi IOC hiển thị công khai đều ẩn danh hóa. |
| **Điều 12.5, 28.1, 28.3, 28.4 & 31.1 (Tính nguyên bản):** Phát triển mới & khai báo đầy đủ OSS/AI. | Toàn bộ mã nguồn được phát triển mới 100% trong thời gian cuộc thi. `README.md` liệt kê đầy đủ thư viện mã nguồn mở kèm license (`uitnlp/visobert` MIT, FastAPI, Next.js, ONNX Runtime, OpenCV, Pillow, fpdf2, `DejaVuSans.ttf`), script tự huấn luyện và các công cụ AI đã dùng. |
| **Điều 10.4 & 31.4 (Vận hành trực tuyến & Đóng băng sau hạn nộp):** | Triển khai HTTPS ổn định trên Vercel + Render kèm giám sát uptime 24/7 đến hết **11/12/2026**. Đóng băng tuyệt đối mã nguồn, slide và môi trường chạy trực tuyến trước **23:59:59 ngày 03/12/2026**. |

---

## 6. Cấu trúc 10 Slide Thuyết trình Chuẩn Vòng Chung Kết (PDF ≤ 10 Trang)

> *Lưu ý: Slide nộp ngày 03/12 không được chỉnh sửa và sẽ dùng trực tiếp để thuyết trình tại Chung kết Techday ngày 11/12.*

1. **Slide 1 — Trang bìa:** **VeriShield AI** — *Lá chắn & Trợ lý AI Đa phương thức Bảo vệ Giao dịch Số Trước Khi Tiền Rời Ví* · Chủ đề (`Trợ lý AI` · `Chống lừa đảo` · `An ninh mạng`) · Thông tin đội 2 thành viên.
2. **Slide 2 — Khoảng trống "10 Giây Định Mệnh":** Thiệt hại lừa đảo chuyển khoản & Fake Bill tiểu thương tại Việt Nam; vì sao người lớn tuổi không tự mở web tra cứu khi đang hoảng loạn trong cuộc gọi.
3. **Slide 3 — Lỗ hổng của Giải pháp Hiện tại:** Vì sao "AI Chatbot thông thường" thất bại (Ảo giác thiếu kiểm chứng · Mù trước Fake Bill nén qua Zalo · Dính Prompt Injection · Tốn GPU không gác cổng được hàng triệu giao dịch).
4. **Slide 4 — Giải pháp VeriShield AI (Đa điểm chạm Không Ma sát):** Hành trình bảo vệ qua **Web Workbench**, **Telegram Forward Bot 1 chạm**, và **Lớp chắn Ví Điện Tử (30s Cooling-Off + `in_active_call`)**.
5. **Slide 5 — Kiến trúc Two-Stage Cascade (AI Tự huấn luyện + Cybersecurity):** Sơ đồ luồng **Fine-tuned `VisoBERT` 7-Class ONNX (`< 35ms`)** + **3-Layer Fake-Bill Forensics** + **URL/SSRF/IDN Security Engine** + **Gemini 2.5 Flash**.
6. **Slide 6 — Chiều sâu Công nghệ & An ninh mạng:** Minh họa trực quan (1) Fine-tune `VisoBERT` hiểu tiếng Việt không dấu/lách luật, (2) 3 lớp bắt Fake Bill chống nén Zalo, (3) Phòng thủ Prompt Injection & SSRF/Punycode.
7. **Slide 7 — Vòng lặp Khép kín "Future Workspace" & Trải nghiệm Thực tế:** Minh họa luồng **Bot/Người dùng báo → AI gom chiến dịch trên `/radar` → Chuyên viên Fintech duyệt chặn 1 chạm → Miễn dịch toàn hệ thống** *(kèm link & QR để BGK quét dùng thử ngay)*.
8. **Slide 8 — Thực nghiệm Định lượng & Red-Team Benchmark:** Đường cong huấn luyện & Confusion Matrix của **`VisoBERT`**, kết quả đo trên **40 ca kiểm thử tiếng Việt** (Precision, Recall, F1, 0% báo động giả trên tin ngân hàng thật, 100% chặn Prompt Injection & Fake Bill nén Zalo, độ trễ ONNX `< 35ms`).
9. **Slide 9 — Tiềm năng Tác động & Triển khai Quy mô Siêu Ứng Dụng:** Tối ưu chi phí nhờ tầng Cascade ONNX (`< 35ms`/CPU) cho phép bảo vệ 30M+ người dùng và giảm 80% thời gian điều tra cho đội ngũ Fraud Ops Fintech.
10. **Slide 10 — Tổng kết & Cam kết:** Ba giá trị cốt lõi (*Chủ động không ma sát · Kiểm chứng 3 lớp không ảo giác · Khép kín bảo vệ toàn hệ sinh thái*) + Link dùng thử Web & Bot Telegram.
