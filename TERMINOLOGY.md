# TERMINOLOGY.md — Bộ thuật ngữ & Chuẩn UX Writing của VeriShield AI

Tài liệu này quy định giọng văn, cách viết hoa, bảng chuyển đổi thuật ngữ bắt buộc và quy ước hiển thị thống nhất trên toàn bộ sản phẩm **VeriShield AI**: giao diện web, Bot Telegram, báo cáo PDF, thông báo lỗi API và nội dung phản hồi từ AI.

---

## 1. Nguyên tắc UX Writing cốt lõi

1. **Tiếng Việt tự nhiên, đúng ngữ cảnh:** Diễn đạt theo cách người dùng Việt Nam nói và đọc khi xử lý giao dịch tài chính, không dịch sát từng từ tiếng Anh.
2. **Quy tắc viết hoa đầu câu (Sentence case):** Chỉ viết hoa chữ cái đầu câu và danh từ riêng (`VeriShield AI`, `Telegram`, `VietQR`, `VNeID`, `Công an`, tên ngân hàng Việt Nam). Không viết hoa tùy tiện giữa câu (ví dụ: dùng *Điểm rủi ro ước tính*, không dùng *Điểm Rủi ro Hiệu chuẩn*).
3. **Không trộn Anh–Việt khi có từ tiếng Việt tự nhiên:** Ưu tiên diễn đạt thuần Việt trong giao diện người dùng phổ thông. Chỉ giữ các từ đã quen thuộc với người dùng Việt như `Link` / `Liên kết`, `URL` (khi gắn nhãn ô nhập kỹ thuật), `QR` / `VietQR`, `Telegram`, `PDF`, `OTP`, `SMS`.
4. **Câu ngắn, rõ ràng, hướng đến hành động:** Ưu tiên động từ trực tiếp (*Kiểm tra ngay*, *Dừng chuyển tiền*, *Sao chép tin nhắn*, *Chặn dấu hiệu này*).
5. **Tách biệt giao diện phổ thông và thông tin kỹ thuật:**
   - **Giao diện phổ thông:** Chỉ giải thích dấu hiệu bất thường và hành động cần làm bằng ngôn ngữ đời thường.
   - **Khu vực thông tin kỹ thuật (mục mở rộng `Thông tin kỹ thuật` hoặc tài liệu kiến trúc):** Dành cho thông số như `ONNX`, `INT8`, `ELA`, `dHash`, `EMVCo`, `CRC-16`, `SSRF`, `Punycode`, `EXIF`, tên mô hình (`multilingual-e5-small`, `Gemini 2.5 Flash`), mã hồ sơ và JSON API.
6. **Không để lộ chi tiết triển khai:** Không hiển thị nguyên văn tên biến (`in_active_call`, `primary_ioc_hash`), mã enum nội bộ (`CRITICAL_SCAM`, `UNVERIFIED_SCREENSHOT`, `BENEFICIARY_MISMATCH`, `VALID_VIETQR`, `bank_account`), mã HTTP kỹ thuật (`HTTP 403`, `HTTP 409`) hay tên ngoại lệ Python trên giao diện người dùng phổ thông.
7. **Trung thực và không cam kết tuyệt đối:**
   - Không bao giờ khẳng định giao dịch "chắc chắn an toàn 100%" hay "đảm bảo không có lừa đảo". Luôn dùng cách nói thận trọng (*Chưa phát hiện dấu hiệu bất thường*, *Mức độ rủi ro thấp*, *Hệ thống chỉ hỗ trợ tham khảo*).
   - **Quy tắc trung thực biên lai chuyển khoản:** Ảnh chụp màn hình biên lai chưa bao giờ là bằng chứng tiền đã vào tài khoản. Kể cả khi chưa phát hiện dấu hiệu chỉnh sửa ảnh, vẫn phải nhắc người bán kiểm tra trực tiếp biến động số dư hoặc loa thông báo nhận tiền trước khi giao hàng.
8. **Không dùng tên thương hiệu bên thứ ba làm tên sản phẩm:** Giữ tên sản phẩm thống nhất là **VeriShield AI**.

---

## 2. Bảng thay thế bắt buộc

| Cụm từ cũ (không sử dụng) | Cụm từ chuẩn (bắt buộc) | Ghi chú sử dụng |
|---|---|---|
| Pháp y đa phương thức | Phân tích bằng chứng số | Tiêu đề, mô tả sản phẩm, tài liệu giới thiệu |
| Pháp y ảnh | Phân tích tính xác thực của hình ảnh | Kiểm tra ảnh chụp biên lai, ảnh màn hình |
| Phòng vệ phút 89 / Chốt chặn Phút 89 | Ngăn chặn lừa đảo trước khi chuyển tiền | Mô tả lớp cảnh báo trước khi xác nhận giao dịch |
| Fraud Ops khép kín | Quy trình xử lý gian lận toàn diện | Mô tả vòng khép kín kiểm tra – cảnh báo – chặn dấu hiệu |
| Phòng vệ ví | Bảo vệ tài sản | Tiêu đề trang, mô tả lợi ích người dùng |
| Bàn điều tra đa phương thức | Công cụ kiểm tra lừa đảo | Khu vực nhập dữ liệu trên trang chính |
| Cộng hưởng rủi ro | Tăng mức cảnh báo rủi ro | Khi người dùng đang nghe cuộc gọi lạ |
| Khóa làm nguội | Tạm dừng để kiểm tra | Bộ đếm 30 giây giúp người dùng bình tĩnh xác minh |
| 1-Chạm | Một chạm | Viết `một chạm` khi đứng giữa câu |
| Mở Bot Telegram | Kiểm tra qua Telegram | Nút điều hướng sang bot `@verishieldvnbot` |
| Phân tích & Kiểm chứng Ngay | Kiểm tra ngay | Nút gửi phân tích chính |
| PII thô | Dữ liệu định danh cá nhân chưa qua xử lý | Chính sách quyền riêng tư, giải thích che giấu thông tin |

---

## 3. Bảng chuẩn hóa thuật ngữ mở rộng

| Cách diễn đạt cũ / trộn Anh–Việt | Cách diễn đạt chuẩn tiếng Việt | Ngữ cảnh |
|---|---|---|
| Workbench & Ví 30s | Kiểm tra & bảo vệ | Thanh điều hướng chính |
| Fraud Ops Radar / Trung tâm Fraud Ops | Trung tâm giám sát gian lận | Trang `/radar` và liên kết điều hướng |
| Luồng điều tra thời gian thực (SSE Pipeline Trace) | Tiến trình kiểm tra | Khối hiển thị tiến độ phân tích |
| Trợ lý Ứng phó Tức thì (Action Copilot) | Hướng dẫn xử lý nhanh | Khối gợi ý bước xử lý và mẫu phản hồi |
| Điểm Rủi ro Hiệu chuẩn | Mức độ rủi ro | Thẻ kết quả phân tích |
| 1-Click / 1-Click Copy / 1-Click Ecosystem Block | Một chạm / Sao chép nhanh / Chặn trên toàn hệ thống | Nút thao tác |
| Zero-Login | Không cần đăng nhập | Thẻ giới thiệu thao tác nhanh |
| Zero Raw PII | Không lưu dữ liệu định danh cá nhân chưa qua xử lý | Huy hiệu bảo mật quyền riêng tư |
| Playground / API Playground | Kiểm thử kết nối API | Khu vực mở rộng dành cho kỹ thuật trên `/radar` |
| Fake Bill / Bill giả | Biên lai giả / Ảnh biên lai có dấu hiệu chỉnh sửa | Cảnh báo tiểu thương và Telegram |
| Bill Replay / Replay ảnh biên lai | Ảnh biên lai bị dùng lại | Kiểm tra trùng lặp biên lai |
| Mule STK / Tài khoản Mule | Tài khoản nghi vấn nhận tiền lừa đảo | Bảng giám sát chiến dịch trên `/radar` |
| Phishing / Link phishing | Trang web giả mạo / Đường dẫn giả mạo | Cảnh báo đường dẫn và trang đăng nhập giả |
| Audio Transcript | Nội dung chuyển từ ghi âm | Kết quả phân tích tệp âm thanh |
| Guardrail / Chống báo giả | Cơ chế kiểm chứng chống cảnh báo nhầm | Kịch bản kiểm chứng giao dịch hợp lệ |
| Khôi phục Demo (Reset) | Đặt lại dữ liệu mẫu | Nút đặt lại quy tắc trên `/radar` |
| Photo hoặc File ảnh | Ảnh chụp hoặc tệp ảnh | Hướng dẫn trên Telegram Bot |
| Voice | Tin nhắn thoại hoặc tệp ghi âm | Hướng dẫn trên Telegram Bot |
| Hybrid KB Mode / ONNX Active | *Đưa vào mục `Thông tin kỹ thuật`* | Không hiển thị ở khu vực người dùng phổ thông |
| ELA / dHash / EMVCo / CRC-16 / SSRF / Punycode / EXIF | *Giải thích bằng tiếng Việt dễ hiểu; giữ ký hiệu gốc trong mục `Thông tin kỹ thuật`* | Xem bảng mục 4 và 5 |

---

## 4. Ánh xạ mã nội bộ sang nhãn hiển thị tiếng Việt

Các giá trị enum ở tầng API và cơ sở dữ liệu **không thay đổi**, nhưng giao diện, Telegram Bot và báo cáo PDF phải hiển thị nhãn tiếng Việt thống nhất dưới đây:

### 4.1 Mức đánh giá rủi ro (`VerdictLevel`)
| Enum nội bộ | Nhãn hiển thị | Mô tả ngắn |
|---|---|---|
| `CRITICAL_SCAM` | Cảnh báo rủi ro rất cao | Có nhiều dấu hiệu cho thấy nguy cơ lừa đảo nghiêm trọng. Cần dừng giao dịch ngay. |
| `HIGH_RISK` | Cảnh báo rủi ro cao | Phát hiện dấu hiệu bất thường đáng lo ngại. Cần xác minh lại trước khi thực hiện giao dịch. |
| `SUSPICIOUS` | Cần thận trọng | Có một số điểm chưa rõ ràng. Nên kiểm tra thêm qua kênh chính thức trước khi tiếp tục. |
| `SAFE` | Chưa phát hiện dấu hiệu bất thường | Chưa thấy dấu hiệu lừa đảo rõ ràng từ dữ liệu đã cung cấp. Vẫn nên tự kiểm tra thông tin trước khi giao dịch. |

### 4.2 Chế độ kiểm tra (`AnalyzeMode`)
| Enum nội bộ | Nhãn hiển thị |
|---|---|---|
| `personal` | Cá nhân |
| `merchant` | Người bán / Cửa hàng |
| `wallet_transfer` | Trước khi chuyển tiền |

### 4.3 Mức độ nghiêm trọng của bằng chứng (`SeverityLevel`)
| Enum nội bộ | Nhãn hiển thị |
|---|---|---|
| `CRITICAL` | Rất nghiêm trọng |
| `HIGH` | Nghiêm trọng |
| `MEDIUM` | Cần lưu ý |
| `LOW` | Thấp |
| `INFO` | Thông tin bổ sung |

### 4.4 Trạng thái kiểm tra biên lai (`ReceiptVerificationStatus`)
| Enum nội bộ | Nhãn hiển thị |
|---|---|---|
| `UNVERIFIED_SCREENSHOT` | Chưa thể xác nhận tiền đã vào tài khoản từ ảnh chụp |
| `BENEFICIARY_MISMATCH` | Thông tin người nhận không khớp |
| `TAMPER_OR_LOGIC_ANOMALY` | Ảnh biên lai có dấu hiệu chỉnh sửa hoặc sai lệch thông tin |
| `REPLAYED_RECEIPT` | Ảnh biên lai đã từng xuất hiện trước đó |

### 4.5 Loại mã QR (`QrKind`)
| Enum nội bộ | Nhãn hiển thị |
|---|---|---|
| `VALID_VIETQR` | Mã chuyển khoản VietQR đúng định dạng |
| `INVALID_CRC_VIETQR` | Mã VietQR bị lỗi cấu trúc hoặc sai mã kiểm tra |
| `URL_QR` | Mã QR dẫn tới trang web |
| `TEXT_QR` | Mã QR chứa văn bản thông thường |

### 4.6 Loại dấu hiệu nghi vấn (`IocType`)
| Enum nội bộ | Nhãn hiển thị |
|---|---|---|
| `bank_account` | Số tài khoản ngân hàng |
| `domain` | Tên miền trang web |
| `phone` | Số điện thoại |
| `campaign` | Nhóm chiến dịch nghi vấn |
| `case` | Hồ sơ kiểm tra |

### 4.7 Nguồn phát hiện bằng chứng (`Evidence.source`)
| Mã nguồn nội bộ | Nhãn hiển thị |
|---|---|
| `image_forensics` | Phân tích tính xác thực của hình ảnh |
| `vietqr_parser` | Kiểm tra mã QR chuyển khoản |
| `url_inspector` | Kiểm tra đường dẫn trang web |
| `phishing_sandbox` | Kiểm tra trang web trong môi trường cách ly |
| `receipt_validator` | Đối chiếu biên lai chuyển khoản |
| `fraud_ops_radar` | Danh sách chặn rủi ro hệ thống |
| `guardrails` | Kiểm tra an toàn nội dung |
| `gemini_vision` | Phân tích ngữ cảnh AI |
| `pipeline` | Hệ thống tổng hợp |

### 4.8 Nhãn phân loại tình huống (`ScamClassifier.predicted_label`)
| Mã nhãn nội bộ | Nhãn hiển thị |
|---|---|
| `authority_impersonation` | Giả mạo cơ quan nhà nước hoặc công an |
| `fake_bill` | Biên lai chuyển khoản giả hoặc bị chỉnh sửa |
| `phishing_link` | Đường dẫn hoặc trang web giả mạo |
| `investment_job_scam` | Lừa đảo đầu tư hoặc việc làm trực tuyến |
| `safe_legitimate` | Giao dịch hoặc thông báo thông thường |

---

## 5. Ranh giới hiển thị thông tin kỹ thuật

- **Luôn hiển thị rõ cho người dùng:** Mức cảnh báo, tóm tắt dễ hiểu, lý do nghi vấn bằng tiếng Việt đời thường, các bước cần làm ngay, mẫu tin nhắn phản hồi và cảnh báo kiểm tra số dư thực tế (đối với biên lai).
- **Thu gọn trong mục `Thông tin kỹ thuật` (`<details>`):**
  - Tên mô hình, độ trễ xử lý (`ONNX`, `INT8`, `multilingual-e5-small`, `Gemini 2.5 Flash`, `RapidOCR`).
  - Tham số phân tích hình ảnh (`ELA`, `dHash`, `EXIF`, hệ số lệch chiều cao chữ OCR).
  - Thông số mã hóa và an toàn mạng (`EMVCo`, `CRC-16`, `TLV`, `Tag 62.08`, tên miền mã hóa `Punycode/ASCII`, lớp chặn `SSRF`).
  - Mã hồ sơ hệ thống (`case_id`), chuỗi băm định danh và công cụ gửi yêu cầu thử nghiệm API JSON.
