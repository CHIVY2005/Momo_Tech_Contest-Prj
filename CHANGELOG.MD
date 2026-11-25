# Changelog

Tất cả các thay đổi đáng chú ý của dự án **VeriShield AI** (MoMo Tech Contest 2026) được ghi lại tại tệp này.

## [0.1.0] - 2026-11-25

### Đã thêm
- Lưu trữ tài liệu đề bài ([docs/Brief.md](docs/Brief.md)) và cấu hình ignore cho tệp thể lệ tham khảo cục bộ.
- Hoàn thiện Bản Đề xuất & Đặc tả Kỹ thuật **VeriShield AI** ([docs/PROPOSAL.md](docs/PROPOSAL.md)) với các trụ cột cốt lõi:
  - **Kiến trúc Two-Stage Cascade:** Kết hợp mô hình **`VisoBERT` 7 lớp tự fine-tune & lượng tử hóa ONNX INT8 (`< 35ms` CPU)** cùng **Tầng An ninh mạng/Pháp y ảnh** và **Gemini 2.5 Flash Multimodal**.
  - **Phát hiện Fake Bill 3 tầng:** Kết hợp Pháp y vật lý (ELA Heatmap + EXIF), Kiểm tra hình học/typography (VLM), và Xác thực logic nghiệp vụ ngân hàng Việt Nam (chống ảnh bị nén qua Zalo/Messenger).
  - **Phòng thủ An ninh mạng & Chống báo động giả:** Lọc khuyến cáo an toàn chính thống, chặn Adversarial Prompt Injection, giải mã QR OpenCV, kiểm tra URL chống SSRF/DNS Rebinding và bắt giả mạo IDN Punycode/Homoglyph.
  - **Đa điểm chạm Không Ma sát:** Web Workbench, **Telegram Bot Chuyển tiếp 1 chạm**, và **Mô phỏng Ví Điện Tử** tự động bật **Khóa làm nguội 30 giây** với tín hiệu ngữ cảnh cuộc gọi (`in_active_call`).
  - **Không gian làm việc Fintech Khép kín (`/radar`):** Đồ thị IOC ẩn danh hóa và luồng chuyên viên duyệt chặn 1 chạm (`POST /api/v1/radar/block-rules`) bảo vệ toàn hệ thống tức thì.
- Thiết lập Kế hoạch Triển khai 8 ngày ([docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)) chia luồng song song cho đội 2 thành viên (**AI & Multimodal Forensics Lead** + **Security & Web Fullstack Lead**) gồm 13 Task TDD và bộ Benchmark 40 ca tiếng Việt.

### Đã cập nhật
- Cập nhật `.gitignore` bổ sung các quy tắc loại trừ tệp build, biến môi trường và thư viện cho dự án Fullstack Python + Next.js (`node_modules/`, `.next/`, `out/`, `.env*.local`, `*.onnx` nháp nếu cần).
