# Kịch Bản Quay Video Demo Sản Phẩm Thực Tế (Thời lượng chuẩn: `02:50` — Tối đa `03:00`)

> **Quy tắc bắt buộc:** Video xuất định dạng `.mp4`, độ phân giải `1080p`, tổng thời lượng **`<= 02:55`** (dự phòng an toàn 5 giây dưới trần 3 phút). Quay trực tiếp giao diện thật đang chạy tại `https://verishield.joiboi.app`.

---

## Phân cảnh 1 (`0:00 – 0:25`) — Mở đầu Vấn đề & Toàn cảnh Giải pháp
- **Hình ảnh trên màn hình:** Mở trang chủ `https://verishield.joiboi.app`, lướt nhẹ qua thanh **5 Kịch bản Thực chiến 1-Click** và 3 tab chế độ (*Cá nhân*, *Chủ cửa hàng*, *Ví Trước Chuyển Tiền*).
- **Lời bình:**
  > *"Tại Việt Nam, kẻ gian thao túng nạn nhân suốt Phút 01 đến Phút 88 qua tin nhắn giả mạo ngân hàng, ảnh biên lai chỉnh sửa trên Zalo hay cuộc gọi giả danh Công an; tới Phút 89 khi mở ví bấm chuyển tiền, cảnh báo chữ đơn thuần không còn đủ sức ngăn chặn. VeriShield AI v2.0 giải quyết trọn vẹn chu trình này bằng kiến trúc 3 tầng kết hợp mô hình ngữ nghĩa tiếng Việt INT8 ONNX 10 mili-giây, pháp y chứng từ 4 lớp và trung tâm vận hành Fraud Ops khép kín."*

---

## Phân cảnh 2 (`0:25 – 1:15`) — Pháp y Biên lai Zalo & Giải mã Bẫy VietQR Cho Chủ Cửa Hàng
- **Hình ảnh trên màn hình:**
  1. Nhấn kịch bản 1-Click **Ảnh Fake Bill Zalo** (`merchant`): thanh **SSE Pipeline Trace** chạy trực tiếp từng bước; bảng kết quả hiện cảnh báo kèm dải màu hổ phách **CHƯA ĐỐI SOÁT SỐ DƯ — BẮT BUỘC KIỂM TRA APP NGÂN HÀNG / LOA THÔNG BÁO**.
  2. Mở tab **Pháp y Ảnh & ELA** (hiển thị bản đồ nhiệt sai số nén JPEG + `dHash`) và tab **Nghiệp vụ Biên lai** (bắt lỗi định dạng số tiền, mã giao dịch giả, ngày tương lai, sai STK nhận).
  3. Nhấn tiếp kịch bản **Bẫy VietQR Nhận Tiền Hoàn** → mở tab **Giải mã VietQR** chỉ rõ khung `EMVCo NAPAS CRC-16: VALID` nhưng thực chất là lệnh chuyển tiền đi.
- **Lời bình:**
  > *"Với chủ hộ kinh doanh khi ảnh gửi qua Zalo bị mất toàn bộ EXIF, VeriShield AI soi trực tiếp bản đồ nhiệt sai số nén ELA, độ lệch dòng chữ OCR và đối chiếu số tài khoản cửa hàng, đồng thời giải mã khung nhị phân EMVCo VietQR để lật tẩy chiêu lừa quét QR nhận tiền hoàn. Đặc biệt, kể cả khi ảnh biên lai sạch, hệ thống luôn gắn nhãn UNVERIFIED_SCREENSHOT nhắc chủ quán kiểm tra biến động số dư thực tế trước khi giao hàng."*

---

## Phân cảnh 3 (`1:15 – 2:00`) — Chốt Chặn Phút 89 (`30s Cooling-Off Lock`) & Action Copilot
- **Hình ảnh trên màn hình:**
  1. Nhấn kịch bản **Cuộc gọi Giả danh Công an (`in_active_call = true`)**.
  2. Kéo xuống khung **Chốt Chặn Phút 89 — Can thiệp Trước Xác Nhận Chuyển Tiền**: đồng hồ **Khóa làm nguội 30s** đang đếm ngược, nút tiếp tục bị khóa mờ cùng bộ câu hỏi phá vỡ hoảng loạn. Nhấn nút xanh **Dừng Giao dịch & Ngắt Cuộc gọi Ngay (An toàn)**.
  3. Tại cột **Action Copilot**, nhấn **Sao chép** câu phản hồi an toàn và bấm **Tải Hồ sơ Tố giác PDF** mở nhanh file PDF tiếng Việt vừa xuất.
- **Lời bình:**
  > *"Ở Phút 89, khi phát hiện người dùng vừa nghe điện thoại vừa lập lệnh chuyển khoản đáng ngờ, VeriShield AI kích hoạt Khóa làm nguội 30 giây và buộc xác nhận bộ câu hỏi kiểm chứng để phá vỡ trạng thái hoảng loạn. Action Copilot cung cấp ngay câu trả lời cắt đuôi kẻ gian, tin nhắn Lá chắn Gia đình và xuất báo cáo pháp y PDF tiếng Việt chỉ với một cú nhấp."*

---

## Phân cảnh 4 (`2:00 – 2:50`) — Vòng Lặp Khép Kín Trên Trung Tâm Fraud Ops (`/radar`) & Kết Luận
- **Hình ảnh trên màn hình:**
  1. Chuyển sang `/radar`: nhấp vào nút trên **Đồ thị Liên kết Chiến dịch & Cụm IOC Ẩn danh** (`99****66`).
  2. Nhấn nút đỏ **1-Click Khóa Khẩn cấp** trên chiến dịch mạo danh Công an (PIN `2026` điền sẵn).
  3. Kéo xuống **Fintech Pre-Transfer REST API Playground**, nhấn **Gửi Yêu cầu API Kiểm định Ví** cho giao dịch tới `STK 999888777666` → màn hình hiện ngay **`BỊ CHẶN BỞI FRAUD OPS RULE (96/100)`** (`blocked_by_ops_rule: true`).
  4. Nhấn **Khôi phục Demo (Reset)** và kết thúc với thẻ tổng kết (`F1 = 1.0000`, `0%` báo động giả trên tin khuyến cáo, `https://verishield.joiboi.app`).
- **Lời bình:**
  > *"Điểm khác biệt cốt lõi cho đội ngũ vận hành Fintech nằm tại trung tâm /radar: mọi SĐT và số tài khoản đều được băm SHA-256 ẩn danh PII. Khi chuyên viên bấm Khóa Khẩn cấp 1-Click, ngay lập tức lệnh chuyển tiền từ ứng dụng ví gọi qua REST API bị chặn cứng ở mức 96 trên 100 điểm. Đạt F1 tuyệt đối trên 40 ca thực nghiệm tiếng Việt với 0% báo động giả trên tin khuyến cáo chính thống, VeriShield AI v2.0 đã sẵn sàng trực tuyến tại verishield.joiboi.app."*
