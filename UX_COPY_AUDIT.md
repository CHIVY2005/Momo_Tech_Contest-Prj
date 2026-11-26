# UX_COPY_AUDIT.md — Báo cáo rà soát và chuẩn hóa nội dung tiếng Việt (VeriShield AI)

Tài liệu này ghi nhận toàn bộ vấn đề về ngôn ngữ đã được phát hiện trong quá trình kiểm kê mã nguồn **VeriShield AI** và bảng ánh xạ chi tiết giữa nội dung cũ, nội dung mới, vị trí tệp và lý do điều chỉnh theo chuẩn [TERMINOLOGY.md](./TERMINOLOGY.md).

---

## 1. Tổng quan các nhóm vấn đề đã xử lý

1. **Ngôn ngữ dịch máy & nặng thuật ngữ chuyên môn ở giao diện phổ thông:** Các cụm từ như *Pháp y đa phương thức*, *Pháp y ảnh*, *Phòng vệ phút 89*, *Fraud Ops khép kín*, *Cộng hưởng rủi ro*, *Khóa làm nguội*, *Bàn điều tra đa phương thức*, *Điểm Rủi ro Hiệu chuẩn*, *Buồng Cô lập Trình duyệt Không đầu* đã được chuyển sang tiếng Việt tự nhiên, dễ hiểu.
2. **Viết hoa tùy tiện (Title Case kiểu tiếng Anh):** Chuẩn hóa toàn bộ tiêu đề, nhãn thẻ, nút bấm, nhãn cảnh báo sang quy tắc viết hoa đầu câu (sentence case), loại bỏ cách viết toàn chữ in hoa gây cảm giác gắt gỏng (*ÍT RỦI RO — CHƯA PHÁT HIỆN...*, *CHẶN KHẨN CẤP...*, *ỔN ĐỊNH*).
3. **Trộn Anh–Việt thiếu nhất quán:** Loại bỏ các cụm trộn như *Workbench & Ví 30s*, *Fraud Ops Radar*, *1-Click Copy*, *Zero-Login · SSE Live*, *Zero Raw PII*, *Mule STK*, *Fake Bill Canvas*, *Audio Transcript*, *API Playground*, *Khôi phục Demo (Reset)*, *Photo hoặc File ảnh*.
4. **Lộ chi tiết triển khai, tên biến và mã enum nội bộ:**
   - Gỡ bỏ tên biến `in_active_call`, `primary_ioc_hash`, `case_id` khỏi các nhãn tương tác chính.
   - Ánh xạ toàn bộ mã enum (`SAFE`, `SUSPICIOUS`, `HIGH_RISK`, `CRITICAL_SCAM`, `UNVERIFIED_SCREENSHOT`, `BENEFICIARY_MISMATCH`, `TAMPER_OR_LOGIC_ANOMALY`, `REPLAYED_RECEIPT`, `VALID_VIETQR`, `URL_QR`, `TEXT_QR`, `CRITICAL/HIGH/MEDIUM/LOW/INFO`, `bank_account/domain/phone`, `image_forensics/url_inspector/...`, `fake_bill/...`) sang nhãn tiếng Việt thống nhất tại [frontend/src/lib/copy.ts](./frontend/src/lib/copy.ts), [backend/app/services/report_pdf.py](./backend/app/services/report_pdf.py) và [backend/app/services/ai_orchestrator.py](./backend/app/services/ai_orchestrator.py).
   - Loại bỏ mã HTML (`<input type='password'>`), tên quy tắc nội bộ (`xml_tag_breakout`), tên lớp ngoại lệ Python (`{type(exc).__name__}`) và mã lỗi kỹ thuật (`HTTP 403`, `HTTP 409`) khỏi thông báo người dùng.
5. **Tách thông tin kỹ thuật vào khu vực mở rộng (`<details>Thông tin kỹ thuật</details>`):** Các thông số `ONNX`, `INT8`, `multilingual-e5-small`, `Gemini 2.5 Flash`, `ELA`, `dHash`, `EXIF`, `RapidOCR`, `EMVCo`, `CRC-16`, `TLV`, `SSRF`, `Punycode/ASCII`, mã hồ sơ và JSON `POST /api/v1/analyze` được chuyển vào các mục mở rộng riêng để giữ giao diện phổ thông gọn sạch mà vẫn hỗ trợ kiểm tra kỹ thuật khi cần.
6. **Tập trung hóa chuỗi giao diện:** Tạo tệp [frontend/src/lib/copy.ts](./frontend/src/lib/copy.ts) làm nguồn chuẩn duy nhất cho nhãn mức rủi ro, chế độ kiểm tra, mức nghiêm trọng, trạng thái biên lai, loại mã QR, loại dấu hiệu, nguồn bằng chứng, nhãn phân loại và câu lưu ý miễn trừ.
7. **Thống nhất giọng văn không cam kết tuyệt đối:** Giữ nguyên **Rào chắn trung thực biên lai cho người bán** ở cả web, Telegram Bot, PDF và AI prompt, đồng thời bổ sung nhắc nhở kết quả chỉ mang tính hỗ trợ tham khảo.

---

## 2. Bảng ánh xạ chi tiết theo khu vực

### 2.1 SEO Metadata, Điều hướng, Footer & Trang chính

| Vị trí tệp | Nội dung cũ | Nội dung mới | Lý do thay đổi |
|---|---|---|---|
| `frontend/src/app/layout.tsx` | `VeriShield AI v2.0 — Điều tra Lừa đảo Đa phương thức & Phòng vệ Ví` | `VeriShield AI — Phân tích bằng chứng số và ngăn chặn lừa đảo trước khi chuyển tiền` | Thay thế cụm từ bắt buộc, bỏ Title Case |
| `frontend/src/app/layout.tsx` | `Pháp y Đa phương thức · Phòng vệ Phút 89 · Fraud Ops Khép kín` | `Phân tích bằng chứng số · Ngăn chặn lừa đảo trước khi chuyển tiền · Quy trình xử lý gian lận toàn diện` | Thay thế 3 cụm từ bắt buộc |
| `frontend/src/app/layout.tsx` | `Kiến trúc 3 Tầng (Deterministic Forensics + Pruned E5 INT8 ONNX + Gemini 2.5 Flash)` & `Không lưu PII thô` | Đưa mô tả kiến trúc vào `<details>Thông tin kỹ thuật hệ thống</details>`; footer chính hiển thị: `Không lưu dữ liệu định danh cá nhân chưa qua xử lý` + câu lưu ý tham khảo | Quy tắc 6, 9 và thay thế `PII thô` |
| `frontend/src/components/layout/TopNav.tsx` | `Workbench & Ví 30s` / `Fraud Ops Radar` | `Kiểm tra & bảo vệ` / `Trung tâm giám sát gian lận` | Loại bỏ trộn Anh–Việt, chuẩn sentence case |
| `frontend/src/app/page.tsx` | `Không gian Điều tra Lừa đảo Đa phương thức & Phòng vệ Giao dịch Số` | `Phân tích bằng chứng số và bảo vệ tài sản trước khi chuyển tiền` | Tiếng Việt tự nhiên, bỏ Title Case |
| `frontend/src/app/page.tsx` | `Giải mã EMVCo VietQR, pháp y ảnh ELA 4 lớp, phân loại ngữ nghĩa multilingual-e5-small INT8 ONNX...` | `Kiểm tra nhanh tin nhắn nghi ngờ, đường dẫn lạ, mã VietQR, tính xác thực của hình ảnh biên lai và tệp ghi âm cuộc gọi để phát hiện sớm dấu hiệu bất thường.` | Chuyển tên mô hình/thuật ngữ kỹ thuật khỏi phần giới thiệu phổ thông |
| `frontend/src/app/page.tsx` | `ONNX Active` / `Hybrid KB Mode` | Loại bỏ huy hiệu nội bộ khỏi phần đầu trang; giữ `Hệ thống sẵn sàng (20 kịch bản lừa đảo phổ biến)` | Quy tắc 5, 6 |
| `frontend/src/app/page.tsx` | `Mở Bot Telegram 1-Chạm` & `Khóa IOC Khép kín (/radar)` | `Kiểm tra qua Telegram` & `Trung tâm giám sát gian lận` | Thay thế bắt buộc `Mở Bot Telegram`, `1-Chạm`, bỏ lộ route `/radar` |
| `frontend/src/app/page.tsx` | `Đã ghi nhận Thực thể Đáng ngờ vào Đồ thị Chiến dịch` / `Mở /radar` | `Đã ghi nhận dấu hiệu đáng ngờ vào hệ thống giám sát` / `Mở trung tâm giám sát` | Tiếng Việt tự nhiên, bỏ lộ tên route và `Fraud Ops` |

### 2.2 Công cụ kiểm tra, Tình huống mẫu, Tiến trình & Kết quả phân tích

| Vị trí tệp | Nội dung cũ | Nội dung mới | Lý do thay đổi |
|---|---|---|---|
| `frontend/src/components/workbench/DemoScenarioBar.tsx` | `5 Kịch bản Thực chiến 1-Click (Dành cho Hội đồng Giám khảo)` · `Zero-Login · SSE Live` | `5 tình huống mẫu để kiểm tra một chạm` · `Không cần đăng nhập · Dữ liệu mẫu` | Thay `1-Click` → `một chạm`, bỏ ngôn ngữ kỹ thuật/sáo rỗng |
| `frontend/src/components/workbench/DemoScenarioBar.tsx` | `Ví 30s` / `Chủ shop` | `Chuyển tiền` / `Cửa hàng` (từ `copy.ts`) | Thống nhất thuật ngữ chế độ kiểm tra |
| `frontend/src/components/workbench/InputWorkbench.tsx` | `Bàn Điều tra Đa phương thức (Multimodal Workbench)` | `Công cụ kiểm tra lừa đảo` | Thay thế bắt buộc #6 |
| `frontend/src/components/workbench/InputWorkbench.tsx` | `Kết hợp phân tích văn bản, URL Punycode/SSRF, pháp y ELA ảnh biên lai...` | `Dán tin nhắn, đường dẫn hoặc tải lên ảnh biên lai, mã QR và tệp ghi âm để kiểm tra dấu hiệu bất thường.` | Bỏ thuật ngữ `Punycode/SSRF/ELA` khỏi mô tả phổ thông |
| `frontend/src/components/workbench/InputWorkbench.tsx` | Huy hiệu `in_active_call` & `Kích hoạt cộng hưởng rủi ro & Khóa làm nguội 30 giây` | Bỏ hẳn `in_active_call`; đổi thành `Tự động tăng mức cảnh báo rủi ro và tạm dừng để kiểm tra 30 giây khi người lạ đang thúc giục bạn qua điện thoại.` | Quy tắc 8 + thay thế bắt buộc #7, #8 |
| `frontend/src/components/workbench/InputWorkbench.tsx` | `Phân tích & Kiểm chứng Ngay` / `Đang điều tra đa tầng...` | `Kiểm tra ngay` / `Đang kiểm tra...` | Thay thế bắt buộc #11, ngắn gọn |
| `frontend/src/components/workbench/InputWorkbench.tsx` | `Tầng 1 chạy nội bộ (<50ms) · ... không lưu PII thô.` | `Dữ liệu được phân tích an toàn và không lưu dữ liệu định danh cá nhân chưa qua xử lý.` | Thay thế bắt buộc #12, bỏ chi tiết kiến trúc |
| `frontend/src/components/workbench/LiveTracePanel.tsx` | `Luồng Điều tra Thời gian thực (SSE Pipeline Trace)` / `Xem chi tiết trace` | `Tiến trình kiểm tra` / `Xem tiến trình kiểm tra` | Bỏ trộn tiếng Anh (`SSE Pipeline Trace`, `trace`) |
| `frontend/src/components/workbench/VerdictDashboard.tsx` | `ÍT RỦI RO — CHƯA PHÁT HIỆN MÃ ĐỘC / LỪA ĐẢO` ... `CẢNH BÁO ĐỎ — ...` | 4 mức chuẩn trong `copy.ts` (`Chưa phát hiện dấu hiệu bất thường`, `Cần thận trọng — nên xác minh thêm`, `Cảnh báo rủi ro cao — tạm dừng giao dịch`, `Cảnh báo rủi ro rất cao — có nhiều dấu hiệu lừa đảo`) | Bỏ toàn chữ in hoa, bỏ hàm ý an toàn tuyệt đối |
| `frontend/src/components/workbench/VerdictDashboard.tsx` | `Điểm Rủi ro Hiệu chuẩn` / `Độ tin cậy` / `Bản gỡ băng lời thoại cuộc gọi (Audio Transcript)` | `Mức độ rủi ro` / `Mức độ chắc chắn` / `Nội dung chuyển từ tệp ghi âm` | Sentence case, bỏ tiếng Anh thừa |
| `frontend/src/components/workbench/VerdictDashboard.tsx` | Hàng badge `Hồ sơ: vs_...`, `E5 ONNX: fake_bill`, `LLM: gemini-...` hiển thị trực tiếp | Thu gọn trong `<details>Thông tin kỹ thuật</details>`, ánh xạ `predicted_label` sang tiếng Việt | Quy tắc 6 và 8 |
| `frontend/src/components/wallet/WalletPreTransferSim.tsx` | `Chốt Chặn Phút 89 — Can thiệp Trước Xác Nhận Chuyển Tiền` / `Khóa làm nguội: 30s` | `Ngăn chặn lừa đảo trước khi chuyển tiền` / `Tạm dừng để kiểm tra: 30 giây` | Thay thế bắt buộc #3 và #8 |
| `frontend/src/components/wallet/WalletPreTransferSim.tsx` | `GIAO DỊCH BỊ CHẶN CỨNG BỞI QUY TẮC FRAUD OPS (/radar)` | `Giao dịch bị chặn do dấu hiệu nghi vấn` | Bỏ ALL CAPS, bỏ `FRAUD OPS (/radar)` |
| `frontend/src/components/copilot/ActionCopilotPanel.tsx` | `Trợ lý Ứng phó Tức thì (Action Copilot)` / `(1-Click Copy)` | `Hướng dẫn xử lý nhanh` / `(sao chép một chạm)` | Bỏ tiếng Anh, thay `1-Click` → `một chạm` |

### 2.3 Thẻ bằng chứng & Kiểm tra hình ảnh, biên lai, VietQR, đường dẫn

| Vị trí tệp | Nội dung cũ | Nội dung mới | Lý do thay đổi |
|---|---|---|---|
| `frontend/src/components/evidence/EvidenceTabs.tsx` | `Pháp y Ảnh & ELA`, `URL & Sandbox`, hiển thị nguyên `ev.source` (`image_forensics`) và `ev.severity` (`CRITICAL`) | `Tính xác thực hình ảnh`, `Kiểm tra đường dẫn`, ánh xạ `formatEvidenceSource(ev.source)` và `SEVERITY_COPY[ev.severity]` | Quy tắc 5, 6, 8 |
| `frontend/src/components/evidence/ElaCompareView.tsx` | `Perceptual dHash`, `Độ lệch dòng chữ OCR (CV)`, `EXIF`, `Bản đồ Nhiệt Sai số Nén JPEG (Error Level Analysis — ELA)`, `RapidOCR` | Đưa `dHash`, `OCR CV`, `EXIF`, `ELA`, `RapidOCR` vào `<details>Thông tin kỹ thuật phân tích hình ảnh</details>`; giao diện chính dùng `Mức nghi vấn chỉnh sửa hình ảnh`, `Bản đồ vùng có dấu hiệu chỉnh sửa ảnh`, `Văn bản đọc được từ ảnh` | Quy tắc 5 và 6 |
| `frontend/src/components/evidence/ReceiptCheckCard.tsx` | `Trạng thái: UNVERIFIED_SCREENSHOT`, `ỔN ĐỊNH/BẤT THƯỜNG`, `Pháp y Vật lý Ảnh (ELA & EXIF)`, `bounding-box OCR`, `Replay`, `dHash` | Ánh xạ `RECEIPT_STATUS_COPY[verificationStatus]`, trạng thái `Bình thường` / `Có bất thường` / `Chưa đủ thông tin`, `Phân tích tính xác thực của hình ảnh`, mô tả dễ hiểu; đưa điểm kỹ thuật vào `<details>` | Quy tắc 2, 5, 6, 8 |
| `frontend/src/components/evidence/VietQrCard.tsx` | `Giải mã Khung EMVCo / NAPAS VietQR`, `CRC-16/CCITT-FALSE: VALID`, `URL_QR`, `TEXT_QR`, `Tag 62.08`, `N/A` | `Mã chuyển khoản VietQR`, `Cấu trúc hợp lệ` / `Cấu trúc không hợp lệ`, `Nội dung chuyển khoản`, `Chưa có`; chuyển `EMVCo`, `BIN`, `CRC-16`, `TLV`, `service_code` vào `<details>Thông tin kỹ thuật mã QR</details>` | Quy tắc 5, 6, 8 |
| `frontend/src/components/evidence/PhishingSandboxCard.tsx` | `ASCII:`, `ĐÃ CHẶN SSRF`, `Punycode IDN`, `Buồng Cô lập Trình duyệt Không đầu (Playwright Headless Detonation)` | `Đã chặn địa chỉ mạng nội bộ không an toàn`, `Tên miền dùng ký tự gần giống để đánh lừa`, `Kiểm tra trang web trong môi trường cách ly`; đưa `ASCII/Punycode`, `SSRF` vào `<details>Thông tin kỹ thuật đường dẫn</details>` | Quy tắc 5, 6, 8 |

### 2.4 Trung tâm giám sát gian lận (`/radar`) & Tiện ích định dạng

| Vị trí tệp | Nội dung cũ | Nội dung mới | Lý do thay đổi |
|---|---|---|---|
| `frontend/src/app/radar/page.tsx` | `Closed-Loop Fintech Fraud Operations Workspace`, `Trung tâm Điều hành Chống Gian lận Khép kín (/radar)` | `Quy trình xử lý gian lận toàn diện`, `Trung tâm giám sát gian lận` | Thay thế bắt buộc #4, bỏ tiếng Anh và route |
| `frontend/src/components/radar/IocGraphSvg.tsx` | `Đồ thị Liên kết Chiến dịch & Cụm IOC Ẩn danh (Zero Raw PII)`, hiển thị raw `node.risk_level` (`CRITICAL_SCAM`) | `Sơ đồ liên kết chiến dịch và dấu hiệu nghi vấn`, ánh xạ `VERDICT_COPY[node.risk_level].shortLabel` | Quy tắc 3, 8 |
| `frontend/src/components/radar/CampaignQueue.tsx` | `Hàng đợi Chiến dịch Bùng phát (1-Click Ecosystem Block)`, `primary_ioc_hash`, `Mule STK`, `Tên miền Phishing`, `1-Click Khóa Khẩn cấp` | `Danh sách chiến dịch cần xử lý nhanh`, bỏ `primary_ioc_hash` và `SHA256`, đổi sang `Số tài khoản ngân hàng`, `Tên miền trang web`, `Chặn một chạm` | Thay thế bắt buộc #9, Quy tắc 3, 8 |
| `frontend/src/components/radar/BlockRuleManager.tsx` | `Cách ly Đa Giám khảo (TTL 30m)`, `Khôi phục Demo (Reset)`, `HTTP 403`, `HTTP 409`, hiển thị raw `rule.ioc_type` (`bank_account`) | `Quản lý quy tắc chặn tạm thời`, `Đặt lại dữ liệu mẫu`, bỏ mã HTTP kỹ thuật, ánh xạ `IOC_TYPE_COPY[rule.ioc_type]` | Quy tắc 3, 5, 8 |
| `frontend/src/components/radar/ApiPlaygroundCard.tsx` | `Fintech Pre-Transfer REST API Playground (POST /api/v1/analyze)`, `in_active_call = true`, `BỊ CHẶN BỞI FRAUD OPS RULE`, raw `result.verdict` | `Kiểm thử hiệu lực quy tắc chặn`, `Giả lập người dùng đang nghe điện thoại khi chuyển tiền`, `Đã bị chặn bởi quy tắc hệ thống`, ánh xạ `VERDICT_COPY`; đưa endpoint + JSON vào `<details>Thông tin kỹ thuật API</details>` | Quy tắc 3, 6, 8 |
| `frontend/src/lib/formatters.ts` & `api.ts` | `Lỗi trường 'analyst_pin': String should have...`, `QR tĩnh / Tự nhập`, `N/A`, `Yêu cầu thất bại (HTTP ${status})` | Ánh xạ tên trường sang tiếng Việt (`Thông tin mã PIN xác thực chưa đúng định dạng yêu cầu.`), `QR tĩnh (tự nhập số tiền)`, `Chưa có`, `Không thể hoàn thành yêu cầu lúc này. Vui lòng thử lại sau.` | Quy tắc 1, 2, 8 |

### 2.5 Backend, Prompt AI, Báo cáo PDF, Dữ liệu mẫu & Telegram Bot

| Vị trí tệp | Nội dung cũ | Nội dung mới | Lý do thay đổi |
|---|---|---|---|
| `backend/app/services/action_copilot.py` | `TẠM KHÓA LÀM NGUỘI 30 GIÂY`, `DANH SÁCH ĐEN FRAUD OPS`, `LƯU Ý BẮT BUỘC CHO TIỂU THƯƠNG` | `Tạm dừng để kiểm tra 30 giây...`, `danh sách chặn rủi ro của hệ thống`, `Lưu ý bắt buộc cho người bán:` (giữ nguyên nhắc `biến động số dư`) | Thay thế bắt buộc #8, sentence case, giữ guardrail |
| `backend/app/services/ai_orchestrator.py` & `llm_client.py` | Prompt yêu cầu vai trò `pháp y chứng từ`; fallback hiển thị `Fraud Ops`, `Prompt Injection`, `IDN Punycode`, raw `classifier.predicted_label` | Cập nhật prompt hướng dẫn tiếng Việt tự nhiên, sentence case, không dùng thuật ngữ kỹ thuật hay mã enum, không cam kết tuyệt đối; ánh xạ `_CLASSIFIER_LABEL_VI` và làm sạch toàn bộ câu dự phòng | Quy tắc 1, 2, 5, 8, 9, 10 |
| `backend/app/services/pipeline.py` | Bước trace lộ `ELA/dHash/VietQR`, `Block Rules, SSRF/Punycode URL & Guardrails`, `ONNX: fake_bill (11ms)`, `(CRITICAL_SCAM) [gemini-...]` | Chuyển toàn bộ tiêu đề và mô tả tiến trình sang tiếng Việt dễ hiểu, ánh xạ `_VERDICT_SHORT_VI`, bỏ rò rỉ tên mô hình/enum khỏi tiến trình phổ thông | Quy tắc 5, 6, 8 |
| `backend/app/services/receipt_validator.py` | `summary_vi` gắn raw `(UNVERIFIED_SCREENSHOT)`, `(REPLAYED_RECEIPT)`, `(BENEFICIARY_MISMATCH)`, `(TAMPER_OR_LOGIC_ANOMALY)`, `(Bill Replay)`, `bounding-box OCR (>2.15x trung vị)` | Diễn đạt hoàn toàn bằng tiếng Việt tự nhiên, giữ 100% logic và rào chắn trung thực biên lai | Quy tắc 2, 5, 8, 9 |
| `backend/app/services/vietqr_parser.py` | `Mã VietQR sai cấu trúc EMVCo`, `CRC-16`, `Tag 38.01`, `Tag 54`, `({service_code})` | Diễn đạt tự nhiên về lỗi cấu trúc/tính toàn vẹn mã VietQR, bỏ ký hiệu thẻ nội bộ | Quy tắc 5, 6, 8 |
| `backend/app/services/url_inspector.py` & `phishing_detonator.py` | `SSRF Guard`, `SSRF Redirect`, `IDN Punycode`, `phishing`, `(<input type='password'>)`, `({type(exc).__name__})`, raw exception `{exc}` | Diễn đạt tiếng Việt dễ hiểu về tên miền giả mạo, ký tự dễ gây nhầm lẫn, chặn địa chỉ nội bộ, biểu mẫu yêu cầu mật khẩu; không lộ ngoại lệ kỹ thuật | Quy tắc 3, 5, 6, 8 |
| `backend/app/services/guardrails.py` | `Adversarial Prompt Injection`, liệt kê raw `inj_patterns` (`xml_tag_breakout`, ...) | `Phát hiện nội dung tìm cách thao túng kết quả kiểm tra`, bỏ danh sách tên quy tắc nội bộ | Quy tắc 3, 8 |
| `backend/app/services/report_pdf.py` | `Case ID`, `in_active_call`, `CRITICAL_SCAM`, `UNVERIFIED_SCREENSHOT`, `[CRITICAL \| url_inspector]`, `Đã Ẩn danh PII` | Ánh xạ toàn bộ sang tiếng Việt chuẩn theo `TERMINOLOGY.md`, thêm câu miễn trừ tham khảo ở chân trang | Quy tắc 2, 8, 9, 10 |
| `backend/app/services/telegram_formatting.py`, `telegram_bot.py`, `scripts/setup_telegram_bot.py` | `1-Chạm`, `Chốt chặn Phút 89`, `Khóa làm nguội 30s`, `pháp y ELA`, `EMVCo CRC-16`, `Fake Bill`, `Photo hoặc File ảnh`, `Voice`, `Fraud Ops Radar` | `một chạm`, `Ngăn chặn lừa đảo trước khi chuyển tiền`, `Tạm dừng để kiểm tra 30 giây`, `Phân tích tính xác thực của hình ảnh`, `Ảnh biên lai`, `ảnh chụp hoặc tệp ảnh`, `tin nhắn thoại`, `Trung tâm giám sát gian lận`, bổ sung nhắc nhở tham khảo | Toàn bộ bảng thay thế bắt buộc & Quy tắc 10 |
| `backend/app/api/v1/{analyze,cases,radar}.py`, `main.py`, `repository.py` | `Case not found.`, `Unknown demo_id`, `Uploaded file ... exceeds`, `IOC này thuộc kịch bản Demo an toàn gốc` | Toàn bộ thông báo lỗi API dùng tiếng Việt tự nhiên, không lộ tên trường hay chi tiết hệ thống | Quy tắc 1, 3, 8 |
| `backend/app/data/{demo_scenarios,seed_iocs,vn_scam_kb}.json` | `Pháp y ảnh`, `in_active_call`, `Khóa làm nguội`, `Guardrail`, `Phishing`, `Mule Account`, `Fake Bill Canvas`, `EMVCo VietQR (QRIBFTTA)`, `Tag 38`, `Deepfake`, `Robocall` | Chuẩn hóa đồng bộ với `TERMINOLOGY.md`, giữ nguyên toàn bộ `demo_id`, từ khóa khớp mẫu và kịch bản kiểm thử | Quy tắc 3, 5, 6, 10 |

---

## 3. Các tệp kiểm thử được đồng bộ

Chỉ cập nhật đúng các chuỗi kiểm tra văn bản đã đổi theo bộ thuật ngữ mới, không làm yếu bất kỳ kiểm thử bảo mật hay logic nghiệp vụ nào:

- `frontend/src/lib/__tests__/auditRegressions.test.ts`: Cập nhật kiểm tra thông báo lỗi `sanitizeValidationErrorDetail` (xác nhận hiển thị `"mã PIN xác thực"` và không lộ `"analyst_pin"` hay `"999"`) và `formatVietQrAmount(null)` (`"QR tĩnh (tự nhập số tiền)"`).
- `backend/tests/unit/test_report_pdf.py`: Xác nhận báo cáo PDF hiển thị `"Cảnh báo rủi ro rất cao"`, đồng thời khẳng định không còn rò rỉ `"CRITICAL_SCAM"` hay `"in_active_call"`.
- `backend/tests/unit/test_telegram_bot.py`: Cập nhật kiểm tra phản hồi lệnh `/call` sang `"Tạm dừng để kiểm tra 30 giây"`.
- `backend/tests/unit/test_codex_audit_regressions.py`: Cập nhật kiểm tra tiêu đề bằng chứng lỗi cấu trúc mã VietQR sang tiếng Việt phổ thông (`"cấu trúc"` và không báo nhầm lỗi `"crc"`).
- `frontend/src/lib/__tests__/sse.test.ts`: Cập nhật chuỗi mẫu trong dữ liệu giả lập SSE sang `"Xác thực ảnh VietQR"`.
