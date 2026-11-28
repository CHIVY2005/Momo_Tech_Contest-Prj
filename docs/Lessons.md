# Bài học Kỹ thuật & Kinh nghiệm Thực chiến (Lessons Learned) — VeriShield AI

> Đúc kết trực tiếp từ quá trình xây dựng, đánh giá thực nghiệm, và kiểm định bảo mật nhiều vòng trên codebase **VeriShield AI v2.0** (cập nhật nhánh `v3` — `2026-11-28`).

---

## 1. Kiến trúc AI, ONNX CPU & Hybrid RAG

1. **Dùng chung 1 phiên `scam_e5_int8.onnx` cho cả Phân loại & Truy hồi (`predict_and_encode`):**
   - Đóng băng encoder `intfloat/multilingual-e5-small` (MIT), cắt tỉa còn `36.000` token Việt–Anh từ tập train + KB (0% rò rỉ val/test), lượng tử hóa INT8 còn **`34.30 MB`** (`< 50 MB`). Xuất đồng thời xác suất 7 lớp và vector 384 chiều trong 1 lượt chạy CPU (`~5–13 ms`), không cần `torch`/`transformers` ở runtime, dễ vừa vặn trong giới hạn RAM `2200 MB` của VPS 4GB.
2. **Kiểm tra độ ổn định số học INT8 theo phiên bản `onnxruntime`:**
   - Đồ thị lượng tử hóa động `QUInt8` nhạy với tối ưu hóa cấp cao `ORT_ENABLE_ALL` trên một số phiên bản `onnxruntime` mới (trên `1.32.0` từng làm xác suất `SAFE_ADVISORY` tụt từ `0.7156` xuống `0.5666`). Luôn kiểm thử trực tiếp trên phiên bản runtime thực tế và cân nhắc `ORT_ENABLE_BASIC` khi cần độ ổn định số học cao hơn.
3. **Không dùng ngưỡng cosine thô (`0.81`) làm Scope Gate cho Multilingual-E5:**
   - Vector E5 gốc có độ bất đẳng hướng (anisotropy) cao nên câu ngoài miền như bài toán lập trình/phương trình bậc 2 vẫn đạt cosine `0.81+`. Lưu `E_raw` trên đĩa rồi tính vector trung bình & `E_centered` trong RAM lúc khởi động (`~0.039 ms`), kết hợp **Dual-Signal Scope Gate** (centered + raw + BM25) và Hybrid RRF (`B6`) nâng `Recall@3` lên **`98.4%`**, `OOD Reject = 100%`, và `FRR` xuống còn **`1.56%`**.
4. **Hiệu chuẩn đa tín hiệu + Sàn/Trần xác định (`risk_calibrator.py`) triệt tiêu điểm thất thường:**
   - Khóa cứng ưu tiên: Luật chặn từ Ops (`>= 96`) → Khuyến cáo an toàn (`<= 16`, nhưng tự động vô hiệu hóa nếu có bất kỳ mối đe dọa cứng nào) → Sàn bảo mật (VietQR bẫy `>= 85`, URL giả mạo/SSRF `>= 82`, Injection `>= 78`, ảnh sửa/lỗi biên lai `>= 45–85`).

---

## 2. OCR Tiếng Việt & Pháp y Đa phương thức

1. **Đừng chạy theo mô hình nặng nếu thực nghiệm chứng minh bản nhẹ thắng toàn diện:**
   - Thực nghiệm 25 ảnh (`OCR_BENCHMARK.md`, `ADR-001`): `MinerU` đạt CER `0.0906` nhưng ngốn **`948.4 MB` Peak RSS**, `2.77 GB` đĩa và dính license không phù hợp; trong khi **`RapidOCR PP-OCRv5 Latin` (`use_cls=False`, `Apache-2.0`)** chỉ tốn **`12.14 MB` đĩa**, `336.2 MB` RSS, `p50 = 733.5 ms`, giảm **51.1% Exact CER** (`0.2243 → 0.1096`) và **72.1% ASCII CER** (`0.1054 → 0.0294`) so với v4, đạt **100% Recall / 0 FP** nhận diện biên lai.
   - Bật `use_cls=True` trên ảnh chat ngang lại làm Exact CER tăng gần gấp đôi (`0.1933`) và tụt độ chính xác scam (`92% → 84%`), nên tắt mặc định (`use_cls=False`).
   - Phải pre-bake trọng số OCR vào Docker (`/app/ocr_cache`) bằng bước warm-up và khóa tải runtime (`VERISHIELD_ALLOW_OCR_DOWNLOAD=0`) ở production.
2. **Cách ly nguồn gốc URL & Sàn an toàn khi Media không đọc được:**
   - URL trích từ chữ OCR trên ảnh hoặc từ QR/STT là nguồn **không đáng tin cậy ở mức cao hơn** (`untrusted_media_only_url_set`) — không được tự kích hoạt request mạng hay nổ Playwright ra ngoài để tránh biến hệ thống thành công cụ quét/SSRF qua ảnh.
   - Khi OCR/STT lỗi hoặc trả rỗng trên ca chỉ có ảnh/audio, không bao giờ để mặc định rơi về `SAFE` tin cậy cao; phải đặt sàn rủi ro thận trọng (`30–32`) và giới hạn `confidence <= 0.45`.
3. **Bất biến đạo đức sản phẩm (`Merchant Receipt Honesty Guardrail`):**
   - Không có mô hình AI hay thuật toán ELA nào chứng minh được tiền đã vào tài khoản ngân hàng của chủ shop. Phải ép bất biến này đồng bộ ở cả Schema validator, Risk Calibrator, Action Copilot, Assistant Tier-0/Tier-1 gate và giao diện.

---

## 3. An ninh mạng & Bảo vệ Trợ lý AI (`NV-01..NV-41`)

1. **Khóa truy cập theo vụ việc + Tách kênh (Zero Cross-Channel IDOR):**
   - `case_id` phải đủ dài không đoán được (128-bit), mọi truy cập `/cases/*`, `/report.pdf`, `/assistant/*` đều yêu cầu token HMAC `X-Case-Access-Token` ký riêng bằng `CASE_TOKEN_SECRET`, và trả PDF qua Telegram chỉ cho phép ở chat riêng tư (`chat_type == "private"`) khớp `owner_chat_hash`.
2. **Làm sạch PII theo 2 lớp (Vault trước khi gửi LLM + Redact trước khi lưu/hiển thị):**
   - Thay SĐT/STK/URL/VietQR bằng token tham chiếu `*_REF_n` qua `RequestEntityVault`, bọc toàn bộ dữ liệu người dùng + lịch sử hội thoại trong **một** khối `<UNTRUSTED_USER_CONTENT>` duy nhất, và chạy `apply_final_wire_egress_chokepoint` ngay trước khi serialize gửi đi trên cả 2 giao thức (`openai_compatible` & `google_genai`).
   - Dữ liệu nhạy cảm như OTP, PIN, CVV, CCCD, thẻ 16 số phải bị che cứng ngay lập tức; riêng `Tool` tra cứu chỉ nhận `*_REF_*` của đúng lượt hiện tại.
3. **Cổng Kiểm duyệt Đầu ra 3 Tầng trước khi stream ra UI (`assistant_guardrails.py`):**
   - Không bao giờ `flush` nửa câu khi đang dùng streaming gate (`Tier 2`); nếu câu dài (`> 160` ký tự) hoặc dính từ khóa nhạy cảm, giữ lại và thăng cấp lên `Tier 1` để kiểm toàn bộ câu trả lời (chặn bịa hotline, chặn hứa hẹn đã nhận tiền, chặn lời khuyên nguy hiểm) trước khi gửi tới người dùng.
4. **Chống SSRF & Bom giải nén tới tận tầng Socket:**
   - Kiểm tra URL ban đầu thôi chưa đủ — phải gắn IP công cộng vào socket (`_PinnedPublicNetworkBackend`), chặn cả redirect hop lẫn sub-request trong Playwright (tắt DNS nội bộ Chromium, chặn `WebSocket`/`WebRTC`/`Beacon`), và giải nén `gzip`/`deflate` từng chunk có ngân sách byte tổng (`SharedByteBudget`).

---

## 4. Hiệu năng Frontend, Motion UX & Quy chuẩn Ngôn từ

1. **Tránh React re-render trong vòng lặp tương tác 60–120Hz (`IocGraphSvg`):**
   - Dùng khóa topology tách biệt khỏi pan/zoom, cache `getBoundingClientRect` bằng `ResizeObserver`, thay `useState` pan/zoom/hover bằng `useRef` + `rAF` + CSS `matrix()` / `translate3d()`, dùng lưới spatial-hash `O(N)` thay cho lực đẩy `O(N²)`, và tắt `onWheel` passive bằng listener `{ passive: false }` + `data-lenis-prevent-wheel`. Kết quả đưa đồ thị 500 nút từ giật/CLS `1.685` lên **`98–120 FPS`**, `0` chồng lấn, `0` CLS.
2. **Hiệu ứng chuyển động an toàn (`MIT-only` + `prefers-reduced-motion`):**
   - Dùng `lenis` + `motion` (`LazyMotion` `domAnimation`) kèm test tự động (`frontendLicenses.test.ts`) khóa chặt giấy phép mở và cấm thư viện không rõ nguồn gốc; luôn giữ spinner xoay và tắt delay trên cảnh báo khẩn cấp (`Verdict`, `Alert`).
3. **Quy chuẩn ngôn từ (`TERMINOLOGY.md`) & Nhất quán 7 Nhãn Phân loại BE ↔ FE:**
   - Khi đổi tên nhãn phân loại từ snake_case cũ sang 7 `SCAM_LABELS` IN HOA (`SAFE_NORMAL..PROMPT_INJECTION`), phải cập nhật đồng thời bảng ánh xạ ở cả `backend/app/services/ai_orchestrator.py` và `frontend/src/lib/copy.ts` kèm unit test chặn rò rỉ enum thô; đồng bộ mốc thanh rủi ro (`0–24 / 25–54 / 55–79 / 80–100`) và tách rõ câu chữ `"che giấu / giả danh hóa"` thay vì dùng chữ `"ẩn danh"` mâu thuẫn với tuyên bố pháp lý ở Mục 05 trang `/privacy`.
4. **Kiểm thử Mock 2 Lớp cho Web Input & Chatbot (`node --test` + Playwright `page.route`):**
   - Kết hợp mock unit client (`workbenchAndChatMock.test.ts` chạy dưới `node --test`) với Playwright E2E thật chạy trên `next start` (`scripts/test_web_mock_e2e.py` mock `/api/v1/**` qua `page.route`, kèm fallback tìm Chromium cached trong `ms-playwright` nếu bản `.venv` lệch revision) giúp kiểm chứng trọn vẹn `FormData`, SSE phân mảnh tiếng Việt, chatbot nhiều lượt, bằng chứng cục bộ và tải file PDF mà không phụ thuộc backend/API key ngoài.

---

## 5. Đóng gói & Vận hành trên Windows / Linux

1. **Giữ đầu dòng LF cho file Linux bằng `.gitattributes`:** Tránh lỗi `exec format` / CRLF khi build `Dockerfile` hoặc chạy `.sh` từ máy Windows.
2. **Kiểm tra chữ ký triển khai & đóng gói sạch:** Luôn đóng gói `.zip` từ `git ls-files -z` để không lọt `.env`, `.db`, `node_modules`, `.venv`; mọi tài liệu nộp bài (`submission/slides`, `submission/guide`, `submission/video-script-3min.md`) phải được cập nhật & render lại ngay sau mỗi đợt nâng cấp tính năng lớn trước ngày đóng băng **03/12/2026**.
