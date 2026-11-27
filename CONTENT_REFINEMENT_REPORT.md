# VeriShield AI — Báo cáo rà soát & chuẩn hóa nội dung `/technical` và `/privacy` (`CONTENT_REFINEMENT_REPORT.md`)

Tài liệu này ghi nhận đầy đủ các thay đổi về biên tập ngôn ngữ, độ chính xác kỹ thuật/thực nghiệm, rà soát mức độ công bố thông tin bảo mật (Security Disclosure Review), đối chiếu giấy phép mã nguồn mở, các hạng mục cần chủ dự án xác nhận và các vấn đề bảo mật/quyền riêng tư cần xử lý trong các task kỹ thuật riêng biệt.

---

## 1. Phạm vi tệp đã chỉnh sửa

| Tệp | Mục đích chỉnh sửa |
|---|---|
| [`frontend/src/app/privacy/page.tsx`](frontend/src/app/privacy/page.tsx) | Viết lại toàn bộ 11 phần theo ngôn ngữ phổ thông dễ hiểu, đánh dấu rõ **Bản dự thảo**, loại bỏ implementation detail không phù hợp, phân biệt rõ 5 khái niệm bảo vệ dữ liệu và phân biệt hết hiệu lực quy tắc với xóa dữ liệu. |
| [`frontend/src/components/docs/DataLifecycleSvg.tsx`](frontend/src/components/docs/DataLifecycleSvg.tsx) | Đơn giản hóa sơ đồ vòng đời dữ liệu cho người dùng phổ thông; loại bỏ tên file nguồn, tên bảng DB, tên khối code và ngưỡng kỹ thuật nội bộ. |
| [`frontend/src/app/technical/page.tsx`](frontend/src/app/technical/page.tsx) | Chuẩn hóa đủ 17 tiêu đề tiếng Việt; chỉnh sửa lỗi diễn giải CER và phạm vi kết quả 40/40; làm rõ quan hệ 3 tầng kiến trúc ↔ 4 giai đoạn pipeline ↔ 3 nguồn tín hiệu; rà soát security disclosure; cập nhật chính xác giấy phép MinerU, NumPy, Whisper và LICENSE dự án. |
| [`frontend/src/components/docs/SystemArchitectureSvg.tsx`](frontend/src/components/docs/SystemArchitectureSvg.tsx) | Đồng bộ thuật ngữ tiếng Việt chuẩn, thể hiện rõ ánh xạ Tầng 1 (Giai đoạn 1–3), Tầng 2 (đầu Giai đoạn 4), Tầng 3 (cuối Giai đoạn 4), loại bỏ tên file nguồn và ngưỡng điểm nội bộ. |
| [`frontend/src/components/docs/ThreeTierFusionSvg.tsx`](frontend/src/components/docs/ThreeTierFusionSvg.tsx) | Làm rõ Nguồn 1 & Nguồn 2 đều thuộc Tầng 1 (kiểm tra xác định + E5 ONNX), Nguồn 3 thuộc Tầng 2; chuyển các hệ số trọng số và ngưỡng điểm chi tiết ra khỏi sơ đồ công khai trong khi giữ nguyên nguyên tắc kỹ thuật. |

*(Không thay đổi giao diện, design system, cấu trúc `DocsShell`/`DocsToc`, cũng như logic backend.)*

---

## 2. Bảng đối chiếu chi tiết các thay đổi (Cũ → Mới)

### 2.1. Chuẩn hóa thuật ngữ toàn cục (`/technical`, `/privacy` và 3 sơ đồ SVG)

| Nội dung cũ | Nội dung mới | Vị trí chỉnh sửa | Lý do thay đổi |
|---|---|---|---|
| `Pháp y phương tiện` / `Pháp y ảnh vật lý` / `Pháp y điểm ảnh vật lý` | `Phân tích hình ảnh và âm thanh` / `Phân tích tính xác thực của hình ảnh` / `Phân tích dấu hiệu chỉnh sửa hình ảnh` | `technical/page.tsx` (mục 01, 03, 06, 12), `SystemArchitectureSvg.tsx` | Loại bỏ cách dịch máy từ "media/physical forensics", dùng đúng ngữ cảnh tiếng Việt chuyên ngành. |
| `Gỡ băng ghi âm` / `gỡ băng cuộc gọi` / `gỡ băng tiếng Việt` | `Chuyển giọng nói thành văn bản` (kèm chú thích STT khi xuất hiện lần đầu) | `privacy/page.tsx` (02–04), `technical/page.tsx` (03, 09, 12, 17), `DataLifecycleSvg.tsx` | Tự nhiên, chính xác và nhất quán với khái niệm Speech-to-Text. |
| `Động cơ OCR` / `Engine OCR` | `Công cụ OCR` | `technical/page.tsx` (06, 14.3, 17), `SystemArchitectureSvg.tsx` | Tránh dịch sát nghĩa từ "engine" gây gượng gạo. |
| `Ngăn xếp công nghệ` / `Technology Stack` | `Công nghệ sử dụng` | `technical/page.tsx` (TOC & mục 12) | Tự nhiên và đúng yêu cầu tiêu đề tiếng Việt thống nhất. |
| `Chấm dứt TLS` | `xử lý kết nối TLS (TLS termination)` | `technical/page.tsx` (02, 13, 17), `SystemArchitectureSvg.tsx` | "Chấm dứt TLS" sai sắc thái kỹ thuật; giải thích đúng bản chất reverse proxy. |
| `Suy giảm an toàn` | `Chế độ xử lý dự phòng (Degraded Mode)` | `technical/page.tsx` (09), `SystemArchitectureSvg.tsx` | Diễn đạt đúng cơ chế fallback khi AI gặp sự cố. |
| `Bằng chứng cứng` / `Sàn bảo mật cứng` | `Bằng chứng kỹ thuật` / `Ngưỡng điểm rủi ro tối thiểu` | `technical/page.tsx` (04, 15), `SystemArchitectureSvg.tsx`, `ThreeTierFusionSvg.tsx` | Tránh cụm từ dịch thô ("hard evidence", "hard floor"). |
| `Không gian điều hành` / `Xác nhận đơn mục tiêu` / `Hạng mục năng lực` | `Trung tâm giám sát` / `Xác nhận từng đối tượng` / `Chức năng` | `technical/page.tsx` (01, 11), `privacy/page.tsx` (01), `SystemArchitectureSvg.tsx` | Chuẩn hóa theo tiếng Việt chuyên nghiệp, ngắn gọn. |
| `Tiêm lệnh AI` | `Tấn công chèn chỉ thị (Prompt Injection)` | `technical/page.tsx` (03, 05, 09, 14.2, 15), `privacy/page.tsx` (03), `ThreeTierFusionSvg.tsx` | Diễn đạt chính xác bản chất lỗ hổng và giữ thuật ngữ gốc lần đầu xuất hiện. |
| `Điểm chạm ngoài biên` / `Đường ống phân tích` / `Ảnh nền` | `Điểm chuyển dữ liệu ra bên ngoài` / `Quy trình phân tích (pipeline)` / `Docker base image` | `privacy/page.tsx` (04, 06), `DataLifecycleSvg.tsx`, `technical/page.tsx` (03, 13) | Loại bỏ cụm từ dịch máy khó hiểu. |
| `Nguyên tắc trung thực biên lai` / `Báo động giả` | `Nguyên tắc xác minh biên lai` / `Cảnh báo nhầm` | `technical/page.tsx` (06, 14.2), `SystemArchitectureSvg.tsx`, `ThreeTierFusionSvg.tsx` | Chính xác và tự nhiên hơn trong ngữ cảnh vận hành chống gian lận. |
| `Đo đạc thực nghiệm` / `Bộ kiểm chuẩn` / `Thực nghiệm toàn trình` / `100% synthetic` | `Đo lường` / `Bộ dữ liệu kiểm thử` / `Đánh giá toàn bộ quy trình (End-to-End)` / `Hoàn toàn sử dụng dữ liệu tổng hợp` | `technical/page.tsx` (mục 14 & metadata) | Chuẩn hóa thuật ngữ báo cáo khoa học tiếng Việt. |
| `Đóng băng bộ mã hóa` / `Truy hồi tri thức lai` / `Tải trọng QR` | `Cố định trọng số bộ mã hóa` / `Truy xuất tri thức kết hợp` / `Dữ liệu chứa trong mã QR` | `technical/page.tsx` (05, 07), `privacy/page.tsx` (05) | Chính xác về mặt kỹ thuật học máy và dễ hiểu hơn. |
| `Thông tin định danh phi số học` / `Cổng tự phục vụ` | `Thông tin cá nhân như họ tên, địa chỉ và email` / `Chức năng quản lý dữ liệu dành cho người dùng` | `privacy/page.tsx` (05, 09) | Dễ hiểu ngay với người dùng phổ thông. |
| `Ẩn danh từ tầng lưu trữ` | `Giả danh hóa và che giấu ngay tại tầng lưu trữ` | `technical/page.tsx` (10) | Sửa lỗi dùng sai thuật ngữ "ẩn danh" cho cơ chế băm và che chuỗi. |
| `Không permissive` / `MinerU với điều khoản giới hạn thương mại` | `LicenseRef-MinerU-Open-Source-License (Apache-2.0 + điều khoản thương mại có điều kiện)` | `technical/page.tsx` (14.3, 17) | Trình bày chính xác giấy phép thực tế của MinerU thay vì mô tả chung chung dễ gây hiểu nhầm là cấm thương mại. |

### 2.2. Chuẩn hóa tiêu đề mục lục & nội dung trang `/technical`

| Nội dung cũ | Nội dung mới | Vị trí | Lý do |
|---|---|---|---|
| Tiêu đề pha trộn Anh–Việt ở 8/17 phần (`Semantic Classification với E5 & ONNX`, `VietQR Analysis`, `URL Intelligence`, `Multimodal AI`, `Fraud Intelligence Graph`, `Closed-Loop Fraud Operations`, `Technology Stack`, `Benchmark và kết quả thực nghiệm`) | Chuẩn hóa đủ 17 tiêu đề tiếng Việt nhất quán trong cả `TECHNICAL_TOC`, `<DocSection>` và SEO metadata | `technical/page.tsx` (dòng 15–39 & 17 section) | Đồng nhất phong cách Engineering Documentation tiếng Việt và khớp tuyệt đối giữa mục lục, heading và anchor link. |
| `0,30·T1 + 0,35·ONNX + 0,35·AI`, sàn `≥ 96`, `≤ 16`, `≥ 85`, `≥ 82`, `≥ 78`, `≥ 45–70`, `≥ 30–32`, ngưỡng OCR `< 0,45`, ngưỡng sandbox `≥ 40`, cờ `--host-resolver-rules=MAP * ~NOTFOUND`, `UID 1001/10001`, `2.200 MB / 1,5 CPU / 256 PIDs`, `12 ký tự hex`, tên tệp mã nguồn (`risk_calibrator.py`, `vietqr_parser.py`, `test_security_redteam.py`...) | Giữ nguyên kiến trúc, nguyên lý phòng vệ và kết quả thực nghiệm; chuyển ngưỡng cấu hình nội bộ, cờ CLI sandbox, định dạng `case_id` và chi tiết phân bổ cgroup container khỏi trang công khai | `technical/page.tsx` (02–15), `SystemArchitectureSvg.tsx`, `ThreeTierFusionSvg.tsx` | Giảm bề mặt lộ thông tin hỗ trợ né tránh bộ lọc (security disclosure hygiene) trong khi vẫn bảo toàn giá trị nghiên cứu và công khai đầy đủ các giới hạn ảnh hưởng đến người dùng. |

### 2.3. Viết lại hoàn toàn trang `/privacy` cho người dùng phổ thông

| Nội dung cũ | Nội dung mới | Vị trí | Lý do |
|---|---|---|---|
| Trạng thái: `Tài liệu kỹ thuật minh bạch — một số mục quản trị cần chủ dự án hoàn thiện` | Đánh dấu rõ **Bản dự thảo** ngay ở `title` metadata, phần metadata đầu trang và hộp cảnh báo đầu trang | `privacy/page.tsx` (dòng 14, 39, 45–57) | Phản ánh trung thực tình trạng pháp lý/quản trị chưa hoàn thiện. |
| Liệt kê tên hàm (`redact_report_pii`, `scrub_free_text_pii`), khối `finally`, tên bảng DB (`cases`, `telegram_updates`, `radar_audit_logs`, `block_rules`, `ioc_sightings`, `campaigns`, `receipt_hashes`), biến môi trường (`IOC_HMAC_SECRET`, `is_simulation=true`), đường dẫn (`/app/ocr_cache`, `pipeline.py`, `repository.py`), định dạng `case_id` 12 ký tự hex, ngưỡng `4.096 IP`, `200 sự kiện`, `< 0,45`, `≥ 40` | Diễn đạt bằng ngôn ngữ phổ thông ngắn gọn, dễ hiểu; giữ nguyên 100% sự thật kỹ thuật về thu thập, xử lý, chia sẻ bên thứ ba, lưu trữ, xác thực và xóa dữ liệu | `privacy/page.tsx` (toàn bộ 11 phần), `DataLifecycleSvg.tsx` | Chính sách quyền riêng tư hướng đến người dùng cuối, không phải báo cáo kiểm toán source code. |
| Chỉ mô tả chung về che giấu và băm | Phân biệt rõ 5 khái niệm: **Che giấu thông tin (Masking/Redaction)**, **Giả danh hóa (Pseudonymization)**, **Băm một chiều (Hashing)**, **Mã hóa đường truyền (Encryption)** và giải thích rõ vì sao **không khẳng định "ẩn danh hoàn toàn" (Anonymization)** | `privacy/page.tsx` (mục 05) | Bảo đảm tính chính xác về quyền riêng tư, tránh cam kết quá mức. |
| Ghi `block_rules: Hết hiệu lực ngay khi quá mốc expires_at` (dễ hiểu nhầm là dữ liệu tự bị xóa) | Phân biệt rõ: khi quá thời hạn, quy tắc **ngừng áp dụng (hết hiệu lực)** ngay lập tức, nhưng **bản ghi trong cơ sở dữ liệu chưa tự động bị xóa** cho đến khi quản trị viên thu hồi, ghi đè hoặc đặt lại | `privacy/page.tsx` (mục 07) | Đối chiếu trực tiếp với `CaseRepository.match_active_block_rules` (lọc `expires_at > ?`) và `revoke_block_rule` (`DELETE`) trong `backend/app/db/repository.py`. |

---

## 3. Các lỗi diễn giải kỹ thuật và thực nghiệm đã sửa

1. **Diễn giải sai chỉ số CER thành "tỷ lệ sai dấu tiếng Việt":**
   - *Lỗi cũ (`technical/page.tsx` mục 16):* Viết *"latin_PP-OCRv5_rec_mobile vẫn có tỷ lệ sai dấu tiếng Việt khoảng 10,96% trên ảnh nhỏ/mờ (CER không dấu 2,94%)"*.
   - *Thực tế từ `evaluation/ocr_benchmark/results.json`:* `0,1096` là **CER gốc (Character Error Rate)** trung bình trên toàn bộ **25 ảnh tổng hợp** (không phải riêng nhóm ảnh nhỏ/mờ — nhóm `low_quality` có CER gốc `0,1331`), và CER bao gồm mọi lỗi ký tự (sai dấu, thay thế ký tự, thiếu/thừa ký tự và khoảng trắng). Việc so sánh **CER gốc (`0,1096`)** với **CER sau khi bỏ dấu (`0,0294`; trên ảnh biên lai `0,0112`)** cho thấy phần lớn lỗi rơi vào dấu tiếng Việt trong khi ký tự Latin/số cơ bản có sai số thấp hơn đáng kể.
   - *Bổ sung chuẩn hóa:* Thêm cột **WER** (`0,9222`, `0,4994`, `0,5162`, `0,4465`, `0,0000`) và thống nhất toàn bộ ký hiệu `Precision`, `Recall`, `F1-score`, `Macro-F1`, `Accuracy`, `CER`, `WER`, `P50`, `P95`, `Peak RSS` cùng định dạng số và đơn vị `MB`, `GB`, `ms`.
2. **Ngăn ngừa suy rộng sai lệch kết quả 40/40 tình huống tổng hợp:**
   - Bổ sung lưu ý phương pháp luận rõ ràng ngay tại mục 14 và bảng 14.2 rằng kết quả `40/40` chỉ phản ánh hiệu năng trên bộ dữ liệu tổng hợp nội bộ (`n = 40`), **không thể suy rộng thành độ chính xác 100% trong thực tế**.
3. **Làm rõ tính nhất quán giữa 3 tầng kiến trúc, 4 giai đoạn thực thi và 3 nguồn tín hiệu:**
   - Trước đây sơ đồ tổng thể đặt E5 ONNX trong Tầng 1, nhưng sơ đồ hợp nhất điểm lại gọi Tín hiệu 1 là "Điểm xác định Tầng 1" và Tín hiệu 2 là "E5-Small INT8 ONNX", dễ gây hiểu nhầm E5 ONNX nằm ở Tầng 2.
   - Đã thống nhất hoàn toàn theo `pipeline.py` và `risk_calibrator.py`: **Tầng 1** (thực thi ở Giai đoạn 1–3) xuất ra **2 nguồn tín hiệu độc lập** (điểm kiểm tra kỹ thuật xác định và xác suất E5-Small INT8 ONNX); **Tầng 2** (đầu Giai đoạn 4) cung cấp **nguồn tín hiệu thứ 3** (AI đa phương thức tùy chọn); **Tầng 3** (cuối Giai đoạn 4) hiệu chuẩn từ cả 3 nguồn tín hiệu và tạo gói hành động ứng phó.
4. **Sửa mô tả giấy phép MinerU và đối chiếu đủ metadata phụ thuộc:**
   - Sửa nhãn `"Không permissive"` / `"giới hạn thương mại"` dễ hiểu nhầm thành cấm thương mại sang đúng bản chất `LicenseRef-MinerU-Open-Source-License` (dựa trên `Apache-2.0` kèm điều khoản sử dụng thương mại có điều kiện về quy mô/doanh thu, yêu cầu ghi nhận thương hiệu bắt buộc trên giao diện và điều khoản chấm dứt tự động).
   - Bổ sung ghi nhận chính xác `CTranslate2 (v4.9.1, MIT)`, `faster-whisper (v1.2.1, MIT)`, `RapidOCR (v3.10.0, Apache-2.0)`, `NumPy` (`BSD-3-Clause` cùng thành phần phụ `0BSD/MIT/Zlib/CC0-1.0`) và bản quyền dự án `MIT — Copyright (c) 2026 Trần Chí Vỹ` theo tệp [`LICENSE`](LICENSE).
5. **Phân biệt rõ "ẩn danh" với "giả danh hóa/che giấu" và "hết hiệu lực quy tắc" với "xóa dữ liệu":**
   - Sửa mục 10 của `/technical` và mục 05, 07 của `/privacy` để khớp tuyệt đối với hành vi lưu trữ thực tế trong `repository.py`.

---

## 4. Các nội dung cần chủ dự án xác nhận trước khi công bố chính thức

Các mục sau **không được tự tạo** trong mã nguồn và hiện đang được đánh dấu rõ là **Bản dự thảo** trên `/privacy`:

1. **Đơn vị / cá nhân chịu trách nhiệm vận hành và bảo vệ dữ liệu** (pháp nhân hoặc tên nhóm chính thức; hiện tệp `LICENSE` chỉ ghi chủ sở hữu bản quyền mã nguồn là `Trần Chí Vỹ`).
2. **Địa chỉ email và kênh liên hệ chính thức** tiếp nhận thắc mắc về quyền riêng tư, báo cáo sự cố bảo mật và yêu cầu xóa dữ liệu.
3. **Thời hạn lưu trữ chính thức (retention policy)** đối với hồ sơ kiểm tra, đồ thị dấu hiệu, mã đặc trưng biên lai và lịch sử webhook Telegram.
4. **Quy trình xác minh danh tính và thời hạn phản hồi** đối với yêu cầu tra cứu hoặc xóa hồ sơ của người dùng.
5. **Ngày có hiệu lực chính thức** của chính sách quyền riêng tư sau khi hoàn tất 4 mục trên.

---

## 5. Các vấn đề bảo mật & quyền riêng tư cần xử lý trong task kỹ thuật riêng

> *Lưu ý nguyên tắc:* Việc tinh gọn các ngưỡng nội bộ khỏi trang công khai `/technical` chỉ là biện pháp vệ sinh công bố thông tin (defense-in-depth), **không thay thế cho việc khắc phục các giới hạn kiến trúc bên dưới**.

1. **Thiếu xác thực truy cập hồ sơ đã lưu (`GET /api/v1/cases/{case_id}` và tải PDF):**
   - Bất kỳ ai sở hữu `case_id` đều có thể đọc lại báo cáo JSON hoặc tải PDF. Cần bổ sung signed capability token có thời hạn ngắn hoặc cơ chế xác thực phiên người dùng trước khi triển khai rộng rãi.
2. **Dữ liệu nguyên bản được gửi tới nhà cung cấp AI bên thứ ba trước bước che giấu:**
   - Cần đánh giá giải pháp tiền lọc/che giấu PII mức văn bản (tùy chọn cho người dùng hoặc mặc định với SĐT/STK không cần thiết cho ngữ cảnh) trước khi gửi tới LLM bên ngoài, hoặc bổ sung tùy chọn rõ ràng trên giao diện "Chỉ phân tích nội bộ (không gửi sang AI ngoài)".
3. **Chưa có cơ chế tự động xóa dữ liệu định kỳ (retention TTL) và chưa có chức năng xóa hồ sơ cho người dùng:**
   - Cần xây dựng tác vụ nền định kỳ xóa các bản ghi quá hạn trong `cases`, `telegram_updates`, `block_rules` đã hết hạn (`expires_at <= now`) và bổ sung cơ chế yêu cầu/thực thi xóa hồ sơ có xác thực.
4. **Báo cáo văn bản tự do vẫn có thể lưu thông tin cá nhân ngoài SĐT/STK:**
   - Bộ che giấu hiện chỉ xử lý số điện thoại và số tài khoản ngân hàng; họ tên, địa chỉ, email, CCCD hoặc nội dung chuyển khoản trong `ocr_text`, `transcript`, `summary_vi`, `evidence` vẫn được lưu. Cần nghiên cứu mở rộng nhận diện thực thể (NER) che giấu CCCD/email/họ tên ở tầng lưu trữ.
5. **Xác thực quản trị `/radar` và giới hạn tần suất phân tán:**
   - Nên thay thế xác thực PIN dùng chung bằng SSO/RBAC có nhật ký theo từng tài khoản quản trị và chuyển bộ giới hạn tần suất từ bộ nhớ tiến trình đơn sang kho dùng chung (như Redis) khi mở rộng nhiều worker.
6. **Quyết định tài liệu nội bộ cho các ngưỡng hiệu chuẩn:**
   - Nên lưu các bảng ngưỡng điểm rủi ro, hệ số trọng số hiệu chuẩn và tham số sandbox chi tiết vào tài liệu vận hành nội bộ riêng (không công khai trên giao diện người dùng cuối) để thuận tiện bảo trì và điều chỉnh chống né tránh.
