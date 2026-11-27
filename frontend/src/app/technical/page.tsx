import type { Metadata } from "next";
import Link from "next/link";

import {
  DocCallout,
  DocSection,
  DocsShell,
  DocTable,
  ImplementationStatus,
} from "@/components/docs/DocsShell";
import type { TocItem } from "@/components/docs/DocsToc";
import { SystemArchitectureSvg } from "@/components/docs/SystemArchitectureSvg";
import { ThreeTierFusionSvg } from "@/components/docs/ThreeTierFusionSvg";

export const metadata: Metadata = {
  title: "Công nghệ và kiến trúc hệ thống — VeriShield AI",
  description:
    "Tài liệu kỹ thuật về kiến trúc phân tích ba tầng, mô hình E5 ONNX, OCR, VietQR, kiểm tra đường dẫn, đồ thị giám sát gian lận, kết quả thực nghiệm và giấy phép mã nguồn mở của VeriShield AI.",
};

const TECHNICAL_TOC: readonly TocItem[] = [
  { id: "tong-quan-he-thong", number: "01", label: "Tổng quan hệ thống" },
  { id: "kien-truc-tong-the", number: "02", label: "Kiến trúc tổng thể" },
  { id: "quy-trinh-phan-tich", number: "03", label: "Quy trình phân tích dữ liệu" },
  { id: "kien-truc-ba-tang", number: "04", label: "Kiến trúc phân tích ba tầng" },
  { id: "semantic-e5-onnx", number: "05", label: "Semantic Classification với E5 & ONNX" },
  { id: "ocr-hinh-anh", number: "06", label: "OCR và phân tích hình ảnh" },
  { id: "vietqr-analysis", number: "07", label: "VietQR Analysis" },
  { id: "url-intelligence", number: "08", label: "URL Intelligence" },
  { id: "multimodal-ai", number: "09", label: "Multimodal AI" },
  { id: "fraud-graph", number: "10", label: "Fraud Intelligence Graph" },
  { id: "closed-loop-ops", number: "11", label: "Closed-Loop Fraud Operations" },
  { id: "technology-stack", number: "12", label: "Technology Stack" },
  { id: "kien-truc-trien-khai", number: "13", label: "Kiến trúc triển khai" },
  { id: "benchmark-thuc-nghiem", number: "14", label: "Benchmark và kết quả thực nghiệm" },
  { id: "bien-phap-bao-mat", number: "15", label: "Các biện pháp bảo mật" },
  { id: "gioi-han-he-thong", number: "16", label: "Giới hạn của hệ thống" },
  { id: "thu-vien-giay-phep", number: "17", label: "Thư viện và giấy phép sử dụng" },
];

export default function TechnicalPage() {
  return (
    <DocsShell
      breadcrumbLabel="Công nghệ"
      title="Công nghệ và kiến trúc hệ thống"
      description="Tài liệu kỹ thuật mô tả kiến trúc phân tích đa phương thức, mô hình suy luận cục bộ, cơ chế phòng vệ an ninh mạng, kết quả đo đạc thực nghiệm và giấy phép thành phần của VeriShield AI."
      metaItems={[
        { label: "Loại tài liệu", value: "Engineering Documentation & Research Showcase" },
        { label: "Nguồn đối chiếu", value: "Mã nguồn backend/frontend, ADR-001 và kết quả thực nghiệm lưu trong kho mã" },
        { label: "Chính sách số liệu", value: "Chỉ công bố chỉ số đo trực tiếp; phân rõ hạng mục đã triển khai và dự kiến" },
      ]}
      tocItems={TECHNICAL_TOC}
    >
      {/* 1. Tổng quan hệ thống */}
      <DocSection id="tong-quan-he-thong" number="01" title="Tổng quan hệ thống">
        <p>
          <strong className="font-semibold text-ink">VeriShield AI</strong> là hệ thống phân tích
          bằng chứng đa phương thức hỗ trợ nhận diện dấu hiệu lừa đảo tài chính tại Việt Nam trước
          thời điểm chuyển tiền, đồng thời kết nối trực tiếp với không gian điều hành giám sát gian
          lận khép kín (<code className="font-mono text-ink">/radar</code>).
        </p>
        <p>
          Hệ thống kết hợp các kiểm tra kỹ thuật xác định (pháp y hình ảnh, chuẩn EMVCo VietQR,
          kiểm tra đường dẫn và trình duyệt cách ly), mô hình phân loại ngữ nghĩa tiếng Việt lượng
          tử hóa INT8 chạy trực tiếp trên CPU và tầng suy luận đa phương thức có khả năng vận hành
          dự phòng khi ngoại tuyến.
        </p>

        <DocTable
          caption="Phân loại trạng thái triển khai các nhóm năng lực của VeriShield AI"
          headers={["Hạng mục năng lực", "Trạng thái", "Phạm vi thực tế trong mã nguồn"]}
          rows={[
            [
              "Kiểm tra đa phương thức (văn bản, URL, tối đa 4 ảnh, 2 ghi âm) theo luồng SSE",
              <ImplementationStatus key="s1" status="implemented" />,
              "Hoạt động trên trang chủ (/), API đồng bộ/SSE và kênh Telegram Bot (khi cấu hình).",
            ],
            [
              "Phân loại E5 INT8 ONNX, RapidOCR PP-OCRv5 Latin, VietQR CRC-16, ELA/dHash, URL/Playwright Sandbox",
              <ImplementationStatus key="s2" status="implemented" />,
              "Chạy cục bộ hoàn toàn trên CPU backend; không yêu cầu PyTorch trong runtime.",
            ],
            [
              "Đồ thị Fraud Intelligence & Closed-Loop Block Rules (TTL, chống chặn nhầm, mô phỏng tách biệt, audit log)",
              <ImplementationStatus key="s3" status="implemented" />,
              "Hoạt động trên /radar với SQLite WAL và đối chiếu HMAC-SHA256.",
            ],
            [
              "Bộ chuyển đổi OCR MinerU Basic ONNX",
              <ImplementationStatus key="s4" status="experimental" />,
              "Có adapter cô lập trong mã nguồn để đối sánh nghiên cứu; không cài trong môi trường production do giới hạn giấy phép và tài nguyên.",
            ],
            [
              "Xác thực SSO/RBAC cho /radar, tự động xóa hồ sơ theo TTL, rate limit phân tán (Redis) và tích hợp cổng thanh toán trực tiếp",
              <ImplementationStatus key="s5" status="planned" />,
              "Chưa tích hợp trong phiên bản hiện tại; được ghi nhận rõ trong phần giới hạn hệ thống.",
            ],
          ]}
        />
      </DocSection>

      {/* 2. Kiến trúc tổng thể */}
      <DocSection id="kien-truc-tong-the" number="02" title="Kiến trúc tổng thể">
        <p>
          VeriShield AI được tổ chức theo cấu trúc monorepo tách biệt lớp giao diện web (
          <code className="font-mono text-ink">frontend/</code>), máy chủ phân tích API và suy luận
          cục bộ (<code className="font-mono text-ink">backend/</code>), quy trình huấn luyện ngoại
          tuyến (<code className="font-mono text-ink">training/</code>) và bộ đo kiểm thực nghiệm (
          <code className="font-mono text-ink">evaluation/</code>).
        </p>

        <SystemArchitectureSvg />

        <p>
          Toàn bộ lưu lượng sản xuất đi qua Caddy 2 (chấm dứt TLS, áp dụng CSP/HSTS và giới hạn thân
          yêu cầu 22 MB) trước khi định tuyến yêu cầu <code className="font-mono text-ink">/api/*</code>{" "}
          tới FastAPI với chế độ truyền luồng không đệm (<code className="font-mono text-ink">flush_interval -1</code>)
          để cập nhật tiến độ phân tích theo thời gian thực qua Server-Sent Events (SSE).
        </p>
      </DocSection>

      {/* 3. Quy trình phân tích dữ liệu */}
      <DocSection id="quy-trinh-phan-tich" number="03" title="Quy trình phân tích dữ liệu">
        <p>
          Mỗi yêu cầu gửi tới <code className="font-mono text-ink">AnalysisPipeline</code> đi qua
          lớp kiểm tra đầu vào nghiêm ngặt và 4 chặng xử lý tuần tự phát sự kiện tiến độ (
          <code className="font-mono text-ink">trace</code>) trước khi trả báo cáo chuẩn hóa:
        </p>

        <ol className="list-decimal space-y-2.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">Tiền kiểm định tệp tải lên:</strong> Đọc luồng
            giới hạn dung lượng (≤ 10 MB/tệp, tổng ≤ 20 MB, tối đa 4 ảnh và 2 ghi âm), kiểm tra MIME
            khai báo, chữ ký đầu tệp (magic bytes), giới hạn giải nén ảnh (≤ 25 triệu điểm ảnh, mỗi
            cạnh ≤ 10.000 px) và giới hạn giải mã âm thanh (≤ 10 phút ở 48 kHz, ≤ 8 kênh).
          </li>
          <li>
            <strong className="font-semibold text-ink">Chặng 1 — Pháp y phương tiện, OCR, STT và VietQR:</strong>{" "}
            Thực thi đồng thời ELA/EXIF/dHash + giải mã đa mã QR bằng OpenCV, sau đó trích xuất văn
            bản qua <code className="font-mono text-ink">OcrOrchestrator</code> (RapidOCR PP-OCRv5
            Latin, có tùy chọn dự phòng Gemini OCR giới hạn ngân sách) và gỡ băng ghi âm tiếng Việt
            bằng <code className="font-mono text-ink">faster-whisper</code> (timeout 15 giây).
          </li>
          <li>
            <strong className="font-semibold text-ink">Chặng 2 — Trích xuất IOC, kiểm tra URL, Sandbox và Guardrails:</strong>{" "}
            Tách nguồn gốc URL (URL người dùng nhập/từ mã QR so với URL chỉ nằm trong chữ OCR), đối
            chiếu danh sách chặn đang hiệu lực, kiểm tra tĩnh và lần theo tối đa 5 bước chuyển hướng
            qua kết nối gắn IP công cộng, kích hoạt Chromium cách ly cho URL đáng ngờ (không áp dụng
            cho URL chỉ từ OCR) và quét tiêm lệnh AI / thông báo khuyến cáo an toàn.
          </li>
          <li>
            <strong className="font-semibold text-ink">Chặng 3 — Phân loại E5 ONNX, truy hồi kịch bản và kiểm tra biên lai:</strong>{" "}
            Chạy một lượt suy luận <code className="font-mono text-ink">scam_e5_int8.onnx</code> lấy
            đồng thời xác suất 7 lớp và vector 384 chiều, truy hồi lai 20 kịch bản lừa đảo phổ biến
            tại Việt Nam, đồng thời xác thực logic biên lai ngân hàng và kiểm tra biên lai dùng lại
            theo nguyên tử (<code className="font-mono text-ink">BEGIN IMMEDIATE</code>).
          </li>
          <li>
            <strong className="font-semibold text-ink">Chặng 4 — Suy luận đa phương thức, hiệu chuẩn điểm và lưu hồ sơ:</strong>{" "}
            Gọi AI Tầng 2 (bọc dữ liệu không tin cậy trong thẻ cách ly; tự chuyển chế độ nội bộ nếu
            lỗi/không cấu hình), kiểm tra lại IOC nếu có lời thoại bổ sung từ AI, hiệu chuẩn điểm 3
            tín hiệu, dựng gói hành động ứng phó, che giấu SĐT/STK và lưu SQLite WAL (bỏ qua bước lưu
            nếu đang ở chế độ mô phỏng).
          </li>
        </ol>
      </DocSection>

      {/* 4. Kiến trúc phân tích ba tầng */}
      <DocSection id="kien-truc-ba-tang" number="04" title="Kiến trúc phân tích ba tầng">
        <p>
          Thay vì phó mặc quyết định cho một mô hình ngôn ngữ duy nhất, VeriShield AI tách trách
          nhiệm thành 3 tầng bổ trợ và tổng hợp bằng bộ hiệu chuẩn xác định (
          <code className="font-mono text-ink">risk_calibrator.py</code>):
        </p>

        <ThreeTierFusionSvg />

        <ul className="list-disc space-y-1.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">Chống cộng dồn sai lệch:</strong> Điểm Tầng 1
            lấy giá trị lớn nhất (<code className="font-mono text-ink">max</code>) trong nhóm tín
            hiệu độc lập (URL, Sandbox, ELA/EXIF, logic biên lai, VietQR, khớp kịch bản).
          </li>
          <li>
            <strong className="font-semibold text-ink">Nguyên tắc không hạ thấp bằng chứng cứng:</strong>{" "}
            Các sàn bảo mật xác định bảo đảm tín hiệu AI không thể vô hiệu hóa phát hiện kỹ thuật rõ
            ràng (ví dụ: bẫy VietQR hoàn tiền ≥ 85, biên lai dùng lại hoặc lệch STK ≥ 85, SSRF hoặc
            giả mạo thương hiệu ≥ 82, tiêm lệnh AI ≥ 78).
          </li>
          <li>
            <strong className="font-semibold text-ink">Chống kết luận an toàn khi OCR thất bại:</strong>{" "}
            Nếu OCR gặp lỗi/quá thời gian hoặc ảnh không đọc được chữ mà không có văn bản/QR/AI xác
            minh bổ sung, hệ thống áp sàn điểm tối thiểu 30–32 (giữ mức thận trọng) và hạ độ tin cậy
            xuống ≤ 0,45.
          </li>
        </ul>
      </DocSection>

      {/* 5. Semantic Classification với E5 và ONNX */}
      <DocSection id="semantic-e5-onnx" number="05" title="Semantic Classification với E5 và ONNX">
        <p>
          Mô hình phân loại ngữ nghĩa cục bộ được huấn luyện ngoại tuyến từ backbone mã nguồn mở{" "}
          <code className="font-mono text-ink">intfloat/multilingual-e5-small</code> (giấy phép
          MIT) theo kiến trúc hai đầu ra (Dual-Head):
        </p>

        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Kiến trúc mạng:</strong> Giữ đóng băng bộ mã
            hóa ngữ nghĩa E5 (384 chiều, độ dài chuỗi tối đa 192 token) để bảo toàn không gian ngữ
            nghĩa tiếng Việt, kết hợp đầu phân loại MLP (
            <code className="font-mono text-ink">Linear(384→128) + LayerNorm + GELU + Dropout(0.25) + Linear(128→7)</code>
            ) trên vector mean-pooling chuẩn hóa L2. Một lượt chạy trả về đồng thời logits 7 lớp và
            vector 384 chiều dùng cho truy hồi kịch bản.
          </li>
          <li>
            <strong className="font-semibold text-ink">7 nhóm phân loại:</strong>{" "}
            <code className="font-mono text-ink">SAFE_NORMAL</code>,{" "}
            <code className="font-mono text-ink">SAFE_ADVISORY</code>,{" "}
            <code className="font-mono text-ink">SCAM_IMPERSONATION</code>,{" "}
            <code className="font-mono text-ink">SCAM_TASK_INVEST_LOAN</code>,{" "}
            <code className="font-mono text-ink">SCAM_PHISHING_APK_OTP</code>,{" "}
            <code className="font-mono text-ink">SCAM_URGENT_BORROW</code> và{" "}
            <code className="font-mono text-ink">PROMPT_INJECTION</code>.
          </li>
          <li>
            <strong className="font-semibold text-ink">Tối ưu dung lượng và bộ nhớ sản xuất:</strong>{" "}
            Cắt tỉa bảng từ vựng SentencePiece xuống đúng <strong className="text-ink">36.000 token</strong>{" "}
            tiếng Việt/Anh (khớp riêng trên tập huấn luyện và kho kịch bản để tránh rò rỉ dữ liệu
            kiểm thử) rồi lượng tử hóa động sang INT8, đạt kích thước tệp ONNX{" "}
            <strong className="text-ink">34,3 MB</strong> (tổng thư mục mô hình 35,8 MB, dưới ngưỡng
            50 MB).
          </li>
          <li>
            <strong className="font-semibold text-ink">Tách biệt runtime và huấn luyện:</strong> Môi
            trường chạy thật hoàn toàn không cài <code className="font-mono text-ink">torch</code>{" "}
            hay <code className="font-mono text-ink">transformers</code>; suy luận chạy trên{" "}
            <code className="font-mono text-ink">onnxruntime</code> CPU với{" "}
            <code className="font-mono text-ink">enable_cpu_mem_arena=False</code> và{" "}
            <code className="font-mono text-ink">enable_mem_pattern=False</code> để tránh tích lũy
            bộ nhớ RSS dài hạn.
          </li>
          <li>
            <strong className="font-semibold text-ink">Truy hồi tri thức lai (Hybrid KB):</strong>{" "}
            Kho tri thức gồm <strong className="text-ink">20 kịch bản lừa đảo tại Việt Nam</strong>{" "}
            được nhúng sẵn (<code className="font-mono text-ink">playbook_embeddings.npy</code>), kết
            hợp độ tương đồng cosine 384 chiều (ngưỡng kích hoạt ≥ 0,85) với đối khớp cụm từ không
            phân biệt dấu tiếng Việt.
          </li>
        </ul>
      </DocSection>

      {/* 6. OCR và phân tích hình ảnh */}
      <DocSection id="ocr-hinh-anh" number="06" title="OCR và phân tích hình ảnh">
        <p>
          Phân hệ xử lý hình ảnh kết hợp trích xuất văn bản dạng mô-đun (
          <code className="font-mono text-ink">backend/app/services/ocr/</code>), pháp y điểm ảnh
          vật lý và kiểm định logic biên lai ngân hàng Việt Nam:
        </p>

        <DocTable
          caption="Các tầng xử lý OCR và pháp y hình ảnh trong VeriShield AI"
          headers={["Thành phần", "Cơ chế triển khai thực tế", "Vai trò phát hiện"]}
          rows={[
            [
              "OCR chính: RapidOCR v3 PP-OCRv5 Latin (ONNX CPU)",
              "Sử dụng ch_PP-OCRv5_det_mobile.onnx + latin_PP-OCRv5_rec_mobile.onnx (12,14 MB, Apache-2.0), tích hợp sẵn ngoại tuyến trong ảnh Docker (/app/ocr_cache), tắt phân loại xoay dòng (use_cls=False dựa trên thực nghiệm ablation), giới hạn đồng thời 2 luồng và timeout 8 giây/ảnh.",
              "Trích xuất văn bản tiếng Việt/số tài khoản/mã giao dịch và tọa độ khung bao (OcrBox) phục vụ kiểm tra sai lệch cỡ chữ.",
            ],
            [
              "OCR dự phòng: Gemini Multimodal OCR (giới hạn chặt)",
              "Chỉ kích hoạt khi OCR cục bộ lỗi/quá giờ, độ tin cậy trung bình < 0,45 hoặc ảnh không kèm văn bản/QR mà OCR trả rỗng. Giới hạn 0 lần thử lại, timeout 8 giây và tối đa 2 ảnh/yêu cầu.",
              "Khôi phục chữ trên ảnh mờ, nền tối phức tạp hoặc ảnh xoay 180 độ mà không làm tăng tải cho mọi yêu cầu bình thường.",
            ],
            [
              "Pháp y ảnh vật lý (ELA, EXIF/XMP, dHash)",
              "Nén lại JPEG chất lượng 90% và tính phương sai sai số theo lưới 16×16 (p98/median) kèm bản đồ nhiệt JET; quét thẻ phần mềm chỉnh sửa (Photoshop, Canva, PicsArt, Photopea, GIMP, Lightroom, Figma...); tính mã băm cảm nhận dHash 64-bit.",
              "Phát hiện vùng ghép số tiền, dấu vết công cụ chỉnh sửa ảnh và nhận diện ảnh biên lai bị gửi lặp lại dù đã nén qua ứng dụng nhắn tin.",
            ],
            [
              "Kiểm định logic biên lai (receipt_validator.py)",
              "Kiểm tra định dạng số tiền trộn dấu chấm/phẩy, quy chuẩn mã tham chiếu (tối đa 24 ký tự, phát hiện mã quá ngắn/chứa mẫu giả), kiểm tra mốc thời gian múi giờ Việt Nam (vượt quá tương lai > 10 phút hoặc cũ > 7 ngày), tỷ lệ chiều cao dòng chữ OCR (max/median ≥ 2,15) và đối chiếu số tài khoản nhận.",
              "Phát hiện biên lai tạo giả về mặt nghiệp vụ và bắt buộc giữ nguyên cảnh báo chưa thể xác nhận tiền vào tài khoản chỉ từ ảnh chụp.",
            ],
          ]}
        />

        <DocCallout tone="warning" title="Nguyên tắc trung thực biên lai (Merchant Receipt Honesty Guardrail)">
          <p>
            Ngay cả khi ảnh chụp biên lai không có dấu hiệu chỉnh sửa và đạt mức rủi ro thấp, hệ
            thống vẫn gắn trạng thái{" "}
            <code className="font-mono text-ink">UNVERIFIED_SCREENSHOT</code> và luôn hiển thị cảnh
            báo yêu cầu người bán tự kiểm tra biến động số dư thực tế trên ứng dụng ngân hàng hoặc
            loa thông báo nhận tiền trước khi giao hàng.
          </p>
        </DocCallout>
      </DocSection>

      {/* 7. VietQR Analysis */}
      <DocSection id="vietqr-analysis" number="07" title="VietQR Analysis">
        <p>
          Sau khi OpenCV (<code className="font-mono text-ink">QRCodeDetector</code>) giải mã một
          hoặc nhiều mã QR từ hình ảnh, bộ phân tích{" "}
          <code className="font-mono text-ink">vietqr_parser.py</code> kiểm định chuỗi theo chuẩn
          EMVCo Merchant-Presented QR và quy chuẩn VietQR NAPAS (QĐ 1928/QĐ-NHNN):
        </p>
        <ul className="list-disc space-y-1.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">Kiểm tra toàn vẹn CRC-16/CCITT-FALSE:</strong>{" "}
            Tính toán đa thức <code className="font-mono text-ink">0x1021</code> (khởi tạo{" "}
            <code className="font-mono text-ink">0xFFFF</code>) trên toàn bộ khung dữ liệu tới thẻ{" "}
            <code className="font-mono text-ink">6304</code> để phát hiện chuỗi QR bị sửa đổi.
          </li>
          <li>
            <strong className="font-semibold text-ink">Phân tích cấu trúc TLV nghiêm ngặt:</strong>{" "}
            Giải mã tuần tự cặp Tag-Length-Value, từ chối thẻ trùng lặp, sai độ dài hoặc thẻ số tiền
            (Tag 54) không đúng chuẩn; kiểm tra định danh NAPAS GUID{" "}
            <code className="font-mono text-ink">A000000727</code> và mã dịch vụ{" "}
            <code className="font-mono text-ink">QRIBFTTA</code> (tài khoản) /{" "}
            <code className="font-mono text-ink">QRIBFTTC</code> (thẻ).
          </li>
          <li>
            <strong className="font-semibold text-ink">Tra cứu BIN ngân hàng &amp; ngữ cảnh lừa đảo:</strong>{" "}
            Ánh xạ 18 mã BIN ngân hàng Việt Nam trong kho tri thức, phân biệt QR tĩnh/động, phát
            hiện bẫy <em>&ldquo;quét mã để nhận/hoàn tiền&rdquo;</em> (khi ngữ cảnh hứa hoàn tiền
            nhưng mã QR thực chất là lệnh chuyển tiền đi) và đối chiếu lệch số tài khoản thụ hưởng
            cho cửa hàng (chống dán đè mã QR).
          </li>
        </ul>
      </DocSection>

      {/* 8. URL Intelligence */}
      <DocSection id="url-intelligence" number="08" title="URL Intelligence">
        <p>
          Phân hệ kiểm tra đường dẫn kết hợp phân tích tĩnh, truy vết chuyển hướng an toàn và môi
          trường trình duyệt cách ly nhằm giảm thiểu rủi ro tấn công giả mạo (phishing) và tệp cài
          đặt độc hại (<code className="font-mono text-ink">.apk</code>):
        </p>

        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Phân tích tĩnh tên miền và đường dẫn:</strong>{" "}
            Chuẩn hóa IDN/Punycode (<code className="font-mono text-ink">xn--</code>), khử ký tự đồng
            hình (Cyrillic/chữ số thay chữ cái), tính khoảng cách Levenshtein ≤ 2 đối chiếu với danh
            mục <strong className="text-ink">17 thương hiệu ngân hàng, ví và cơ quan chính thống</strong>{" "}
            tại Việt Nam, đánh giá TLD rủi ro cao (như <code className="font-mono text-ink">.top</code>,{" "}
            <code className="font-mono text-ink">.vip</code>, <code className="font-mono text-ink">.xyz</code>,{" "}
            <code className="font-mono text-ink">.click</code>) và phát hiện đường dẫn OTP/đăng nhập
            hoặc tệp <code className="font-mono text-ink">.apk</code>.
          </li>
          <li>
            <strong className="font-semibold text-ink">Truy vết chuyển hướng gắn IP công cộng (IP-Pinned):</strong>{" "}
            Lần theo tối đa 5 bước chuyển hướng HTTP (timeout 5,5 giây) qua tầng truyền tải{" "}
            <code className="font-mono text-ink">httpcore</code> tự tùy biến, ghim kết nối TCP trực
            tiếp vào IP công cộng đã kiểm duyệt để ngăn tấn công DNS Rebinding và SSRF trên mọi bước
            nhảy.
          </li>
          <li>
            <strong className="font-semibold text-ink">Môi trường cách ly Playwright Chromium:</strong>{" "}
            Chỉ kích hoạt cho URL có điểm rủi ro tĩnh ≥ 40 và không bị chặn SSRF. Trình duyệt vô
            hiệu hóa phân giải DNS trực tiếp (
            <code className="font-mono text-ink">--host-resolver-rules=MAP * ~NOTFOUND</code>), chặn{" "}
            <code className="font-mono text-ink">WebSocket</code>,{" "}
            <code className="font-mono text-ink">EventSource</code>,{" "}
            <code className="font-mono text-ink">RTCPeerConnection</code>,{" "}
            <code className="font-mono text-ink">sendBeacon</code>, định tuyến mọi yêu cầu phụ qua
            bộ lọc IP công cộng (giới hạn 1,5 MB/phản hồi, timeout 3 giây) và kiểm tra DOM tìm ô mật
            khẩu, biểu mẫu OTP/thẻ, thương hiệu giả mạo và liên kết <code className="font-mono text-ink">.apk</code>.
          </li>
          <li>
            <strong className="font-semibold text-ink">Cách ly nguồn gốc URL từ OCR:</strong> Các
            đường dẫn chỉ xuất hiện trong văn bản trích xuất từ ảnh OCR chỉ được kiểm tra tĩnh,{" "}
            <strong>tuyệt đối không</strong> tự động truy vấn mạng hoặc mở trong Playwright.
          </li>
        </ul>
      </DocSection>

      {/* 9. Multimodal AI */}
      <DocSection id="multimodal-ai" number="09" title="Multimodal AI">
        <p>
          Tầng 2 (<code className="font-mono text-ink">ai_orchestrator.py</code> &amp;{" "}
          <code className="font-mono text-ink">llm_client.py</code>) bổ sung khả năng giải thích ngữ
          cảnh tiếng Việt tự nhiên, phát hiện chiêu thức thao túng tâm lý, kiểm tra bất thường thị
          giác trên biên lai và gợi ý câu từ chối an toàn:
        </p>
        <ul className="list-disc space-y-1.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">Đa giao thức linh hoạt:</strong> Hỗ trợ song
            song Google GenAI SDK (<code className="font-mono text-ink">google-genai</code>) và cổng
            API tương thích OpenAI (mô hình mặc định <code className="font-mono text-ink">gemini-2.5-flash</code>,
            có thể cấu hình qua biến môi trường), bắt buộc đầu ra JSON hợp lệ theo schema Pydantic (
            <code className="font-mono text-ink">temperature=0.1</code>).
          </li>
          <li>
            <strong className="font-semibold text-ink">Cách ly ngữ cảnh chống tiêm lệnh:</strong>{" "}
            Loại bỏ ký tự tàng hình/hai chiều, tước thẻ thoát và bọc toàn bộ văn bản người dùng cùng
            khối <code className="font-mono text-ink">[OCR_EXTRACTED_UNTRUSTED_TEXT]</code> bên trong{" "}
            <code className="font-mono text-ink">&lt;UNTRUSTED_USER_CONTENT&gt;</code>. Các tín hiệu
            Tầng 1 tin cậy chỉ được truyền dưới dạng nhãn mã hóa cố định.
          </li>
          <li>
            <strong className="font-semibold text-ink">Xử lý giọng nói hai lớp:</strong> Tệp ghi âm
            được gỡ băng cục bộ trước bằng <code className="font-mono text-ink">faster-whisper</code>{" "}
            INT8 (CPU, bật lọc khoảng lặng VAD); nếu AI Tầng 2 trả về lời thoại bổ sung, đường ống
            tự động chạy lại bước trích xuất IOC và đối chiếu danh sách chặn trên lời thoại mới.
          </li>
          <li>
            <strong className="font-semibold text-ink">Suy giảm an toàn (Degraded Mode):</strong>{" "}
            Khi quá thời gian, gặp giới hạn tốc độ, bộ lọc an toàn (<code className="font-mono text-ink">SAFETY</code>)
            hoặc chưa cấu hình khóa API, hệ thống tự chuyển sang chế độ phân tích nội bộ Tầng 1 và
            vẫn trả <code className="font-mono text-ink">HTTP 200</code> kèm cờ{" "}
            <code className="font-mono text-ink">degraded_mode=true</code>.
          </li>
        </ul>
      </DocSection>

      {/* 10. Fraud Intelligence Graph */}
      <DocSection id="fraud-graph" number="10" title="Fraud Intelligence Graph">
        <p>
          Mọi hồ sơ đạt mức rủi ro từ <strong className="text-ink">45/100</strong> trở lên (ngoại
          trừ các phiên mô phỏng) sẽ cập nhật tần suất xuất hiện và cạnh đồng xuất hiện (tối đa 20
          IOC mỗi hồ sơ để kiểm soát mật độ đồ thị) vào các bảng{" "}
          <code className="font-mono text-ink">campaigns</code>,{" "}
          <code className="font-mono text-ink">ioc_sightings</code> và{" "}
          <code className="font-mono text-ink">ioc_edges</code> trong SQLite WAL.
        </p>
        <ul className="list-disc space-y-1.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">Ẩn danh từ tầng lưu trữ:</strong> Toàn bộ
            đỉnh đồ thị dùng mã băm một chiều (HMAC-SHA256 khi có khóa bí mật) làm khóa định danh và
            chỉ hiển thị nhãn đã che giấu (ví dụ <code className="font-mono text-ink">091****678</code>,{" "}
            <code className="font-mono text-ink">19****01</code>,{" "}
            <code className="font-mono text-ink">na****.top</code>).
          </li>
          <li>
            <strong className="font-semibold text-ink">Trực quan hóa nhẹ không phụ thuộc nặng:</strong>{" "}
            Trang <Link href="/radar" className="text-sky-300 underline decoration-sky-500/40 underline-offset-2 hover:text-sky-200">/radar</Link>{" "}
            dùng bộ bố cục cụm chiến dịch viết riêng bằng TypeScript + SVG (
            <code className="font-mono text-ink">radarLayout.ts</code> &amp;{" "}
            <code className="font-mono text-ink">IocGraphSvg.tsx</code>), hỗ trợ phóng to/thu nhỏ,
            kéo vùng nhìn, vừa khung, toàn màn hình, làm nổi bật cụm lân cận, lọc loại đối tượng và
            chuyển đổi chế độ bảng dữ liệu.
          </li>
          <li>
            <strong className="font-semibold text-ink">Tách bạch dữ liệu mẫu và thực tế:</strong>{" "}
            Mỗi chiến dịch và IOC gắn cờ <code className="font-mono text-ink">is_demo</code>; trong
            môi trường <code className="font-mono text-ink">APP_ENV=production</code>, hệ thống bỏ
            qua nạp 3 chiến dịch mẫu tổng hợp và chỉ giữ danh mục bảo vệ tên miền chính thống.
          </li>
        </ul>
      </DocSection>

      {/* 11. Closed-Loop Fraud Operations */}
      <DocSection id="closed-loop-ops" number="11" title="Closed-Loop Fraud Operations">
        <p>
          VeriShield AI nối liền phát hiện đơn lẻ thành vòng lặp vận hành phòng chống gian lận khép
          kín:
        </p>
        <p className="rounded-lg border border-border-subtle bg-surface-subtle/70 px-3.5 py-2.5 font-mono text-xs text-ink">
          Phát hiện dấu hiệu → Gom cụm chiến dịch → Xem bằng chứng chi tiết → Xác nhận đối tượng &amp;
          TTL → Áp dụng quy tắc chặn → Mô phỏng kiểm chứng → Thu hồi hoặc hết hạn tự động
        </p>
        <ul className="list-disc space-y-1.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">Xác nhận đơn mục tiêu có kiểm soát:</strong>{" "}
            Thao tác tạo quy tắc chỉ áp dụng cho đối tượng cụ thể được người vận hành chọn, yêu cầu
            lý do, thời hạn hiệu lực (TTL 1–1.440 phút, mặc định 30 phút) và xác thực quản trị phía
            backend.
          </li>
          <li>
            <strong className="font-semibold text-ink">Cơ chế chống chặn nhầm:</strong> Danh sách
            thực thể chính thức được bảo vệ (như tên miền ngân hàng, cổng dịch vụ công, NAPAS) bị từ
            chối tạo quy tắc chặn với mã <code className="font-mono text-ink">HTTP 409</code> và ghi
            vào nhật ký kiểm toán.
          </li>
          <li>
            <strong className="font-semibold text-ink">Phạm vi thực thi:</strong> Khi quy tắc có
            hiệu lực, mọi lượt kiểm tra (bao gồm cả tên miền con của tên miền bị chặn) khớp mã băm sẽ
            lập tức kích hoạt sàn điểm ≥ 96/100 và cảnh báo dừng giao dịch trong hệ thống VeriShield.
            VeriShield không trực tiếp phong tỏa tài khoản ngân hàng khi chưa có tích hợp cổng thanh
            toán chính thức.
          </li>
        </ul>
      </DocSection>

      {/* 12. Technology Stack */}
      <DocSection id="technology-stack" number="12" title="Technology Stack">
        <DocTable
          caption="Ngăn xếp công nghệ sử dụng trong VeriShield AI"
          headers={["Lớp hệ thống", "Công nghệ chính", "Vai trò cụ thể"]}
          rows={[
            [
              "Giao diện Web",
              "Next.js 15 (App Router, standalone), React 19, TypeScript 5.8 (strict), Tailwind CSS v4, Lucide Icons",
              "Giao diện kiểm tra đa phương thức, bảng điều khiển Radar, trang tài liệu tĩnh; 0 thư viện biểu đồ/đồ thị bên ngoài.",
            ],
            [
              "Máy chủ API",
              "Python 3.12, FastAPI, Pydantic v2, Uvicorn, HTTPX, python-multipart",
              "Cung cấp REST/SSE endpoints, pure ASGI middleware kiểm soát tải và bảo mật.",
            ],
            [
              "ML cục bộ & Pháp y",
              "ONNX Runtime (CPU), HuggingFace Tokenizers, RapidOCR v3 (PP-OCRv5 Latin), faster-whisper (INT8), OpenCV-headless, Pillow, PyAV, Playwright Chromium, fpdf2",
              "Phân loại 7 lớp E5 INT8, trích xuất văn bản OCR, gỡ băng STT, ELA/dHash/QR, sandbox trình duyệt và tạo báo cáo PDF tiếng Việt.",
            ],
            [
              "AI đa phương thức (Tùy chọn)",
              "google-genai SDK & HTTPX OpenAI-compatible adapter",
              "Suy luận giải thích ngữ cảnh Tầng 2 và OCR dự phòng giới hạn ngân sách.",
            ],
            [
              "Lưu trữ & Hạ tầng",
              "SQLite 3 (WAL mode), Caddy 2.8, Docker & Docker Compose",
              "Lưu hồ sơ đã che SĐT/STK, đồ thị IOC băm, quy tắc TTL, reverse proxy HTTPS/CSP.",
            ],
            [
              "Huấn luyện & Kiểm thử (ngoại tuyến)",
              "PyTorch, Transformers, scikit-learn, pytest, ruff, mypy --strict, node --test",
              "Chỉ dùng khi huấn luyện/xuất ONNX và kiểm định tự động; tách rời hoàn toàn khỏi runtime container.",
            ],
          ]}
        />
      </DocSection>

      {/* 13. Kiến trúc triển khai */}
      <DocSection id="kien-truc-trien-khai" number="13" title="Kiến trúc triển khai">
        <p>
          Cấu hình sản xuất (<code className="font-mono text-ink">docker-compose.prod.yml</code>)
          đóng gói hệ thống thành 3 container tối giản đặc quyền chạy trên máy chủ đơn (4 GB RAM):
        </p>

        <DocTable
          caption="Cấu trúc container và phân bổ tài nguyên triển khai"
          headers={["Dịch vụ", "Ảnh nền & Người dùng", "Giới hạn tài nguyên", "Cấu hình nổi bật"]}
          rows={[
            [
              "caddy",
              "caddy:2.8-alpine (cap_drop: ALL, chỉ giữ NET_BIND_SERVICE)",
              "256 MB RAM · 0,5 CPU · 128 PIDs",
              "TLS tự động, chuyển hướng HTTP→HTTPS (308), HSTS, CSP chặt, giới hạn body 22 MB, proxy SSE không đệm.",
            ],
            [
              "frontend",
              "node:22-alpine (non-root nextjs UID 1001, cap_drop: ALL)",
              "512 MB RAM · 0,5 CPU · 128 PIDs",
              "Bản dựng Next.js standalone tối gọn, chỉ mở cổng nội bộ 3000 trong mạng Docker, có healthcheck định kỳ.",
            ],
            [
              "backend",
              "python:3.12-slim-bookworm (non-root verishield UID 10001, cap_drop: ALL)",
              "2.200 MB RAM · 1,5 CPU · 256 PIDs",
              "1 worker Uvicorn, Playwright max concurrency = 1, trọng số RapidOCR PP-OCRv5 (12,14 MB) và Whisper tiny đóng gói sẵn ngoại tuyến (tắt tải mạng khi chạy), gắn volume SQLite WAL.",
            ],
          ]}
        />
      </DocSection>

      {/* 14. Benchmark và kết quả thực nghiệm */}
      <DocSection id="benchmark-thuc-nghiem" number="14" title="Benchmark và kết quả thực nghiệm">
        <p>
          Toàn bộ chỉ số dưới đây được trích xuất trực tiếp từ các tệp kết quả đo đạc thực nghiệm
          lưu trong kho mã nguồn (<code className="font-mono text-ink">training_metrics.json</code>,{" "}
          <code className="font-mono text-ink">evaluation/results.json</code> và{" "}
          <code className="font-mono text-ink">evaluation/ocr_benchmark/results.json</code>). Không
          có chỉ số ước lượng hay số liệu mô phỏng tiếp thị.
        </p>

        <DocCallout tone="info" title="Lưu ý phương pháp đo và phạm vi diễn giải">
          <p>
            Tất cả bộ dữ liệu đánh giá hiện tại là <strong>dữ liệu tổng hợp tiếng Việt</strong>{" "}
            (100% synthetic, không chứa dữ liệu cá nhân thật). Kết quả phản ánh năng lực của hệ
            thống trên bộ kiểm chuẩn nội bộ, chưa thay thế cho đánh giá diện rộng trên lưu lượng
            giao dịch ngân hàng thực tế.
          </p>
        </DocCallout>

        <h3 className="pt-2 text-sm font-semibold text-ink">
          14.1. Đánh giá mô hình E5-Small INT8 ONNX (tập kiểm thử tách khung mẫu, n = 364)
        </h3>
        <p className="text-xs text-ink-muted">
          Nguồn: <code className="font-mono text-ink-secondary">backend/app/data/models/training_metrics.json</code>{" "}
          — chia tập huấn luyện/đánh giá/kiểm thử theo nhóm mẫu câu tách biệt hoàn toàn (52 mẫu/lớp ×
          7 lớp). Kích thước tệp <code className="font-mono text-ink-secondary">scam_e5_int8.onnx</code>:{" "}
          <strong className="text-ink">34,3 MB</strong>; PyTorch FP32 Test Macro-F1:{" "}
          <strong className="text-ink">0,9472</strong>; ONNX INT8 Test Macro-F1:{" "}
          <strong className="text-ink">0,9314</strong> (Accuracy: <strong className="text-ink">93,13%</strong>).
        </p>
        <DocTable
          caption="Kết quả phân loại chi tiết theo 7 lớp của mô hình E5-Small INT8 ONNX"
          headers={["Lớp phân loại", "Precision", "Recall", "F1-Score", "Số mẫu (Support)"]}
          rows={[
            ["SAFE_NORMAL", "0,979", "0,904", "0,940", "52"],
            ["SAFE_ADVISORY", "0,850", "0,981", "0,911", "52"],
            ["SCAM_IMPERSONATION", "0,788", "1,000", "0,881", "52"],
            ["SCAM_TASK_INVEST_LOAN", "0,979", "0,904", "0,940", "52"],
            ["SCAM_PHISHING_APK_OTP", "1,000", "0,750", "0,857", "52"],
            ["SCAM_URGENT_BORROW", "1,000", "1,000", "1,000", "52"],
            ["PROMPT_INJECTION", "1,000", "0,981", "0,990", "52"],
          ]}
        />

        <h3 className="pt-2 text-sm font-semibold text-ink">
          14.2. Thực nghiệm toàn trình 40 tình huống tiếng Việt &amp; Red-Team
        </h3>
        <p className="text-xs text-ink-muted">
          Nguồn: <code className="font-mono text-ink-secondary">evaluation/results.json</code> — 40
          ca tổng hợp (28 ca lừa đảo/tấn công + 12 ca an toàn/khuyến cáo), chạy đường ống đầy đủ với
          E5 ONNX cục bộ và dịch vụ LLM trực tiếp.
        </p>
        <DocTable
          caption="Kết quả thực nghiệm toàn trình trên 40 tình huống tổng hợp tiếng Việt"
          headers={["Chỉ số thực nghiệm", "Kết quả đo", "Chi tiết quan sát"]}
          rows={[
            ["Precision / Recall / F1 (nhị phân)", "1,000 / 1,000 / 1,000", "Đúng 40/40 ca (TP=28, TN=12, FP=0, FN=0)."],
            ["Báo động giả trên tin khuyến cáo (Advisory FPR)", "0,0%", "5/5 tin khuyến cáo an toàn đều được phân loại mức rủi ro thấp (1–5/100)."],
            ["Nhóm tấn công Prompt Injection", "100% (3/3)", "3/3 ca đạt điểm ≥ 70 và bật cờ phát hiện tĩnh prompt_injection_detected."],
            ["Nhóm biên lai giả (Fake Bill)", "100% (4/4)", "4/4 ca kích hoạt tín hiệu pháp y biên lai Tầng 1 và tuân thủ cảnh báo kiểm tra số dư."],
            ["Độ trễ E5 ONNX (CPU)", "P50 = 10 ms · P95 = 13 ms", "Đo trực tiếp trên từng yêu cầu trong pipeline."],
            ["Độ trễ toàn trình (có gọi LLM trực tiếp)", "P50 = 7.176 ms · P95 = 10.077 ms", "Phần lớn độ trễ thuộc thời gian phản hồi mạng của LLM (P50 = 7.119 ms)."],
          ]}
        />

        <h3 className="pt-2 text-sm font-semibold text-ink">
          14.3. Thực nghiệm so sánh động cơ OCR tiếng Việt (n = 25 ảnh, đo cô lập tiến trình)
        </h3>
        <p className="text-xs text-ink-muted">
          Nguồn: <code className="font-mono text-ink-secondary">OCR_BENCHMARK.md</code> &amp;{" "}
          <code className="font-mono text-ink-secondary">evaluation/ocr_benchmark/results.json</code>{" "}
          — 25 ảnh tổng hợp gồm 5 nhóm (tin nhắn/chat, biên lai ngân hàng, mã VietQR, giao diện tối
          và ảnh nén mờ chất lượng thấp), chạy từng động cơ trong tiến trình con riêng để đo Peak RSS
          chính xác.
        </p>
        <DocTable
          caption="So sánh thực nghiệm các động cơ OCR tiếng Việt trên 25 ảnh chuẩn"
          headers={[
            "Động cơ OCR",
            "Giấy phép",
            "CER tiếng Việt ↓",
            "CER không dấu ↓",
            "Entity F1 ↑",
            "Độ trễ p50 / p95",
            "Peak RSS",
            "Quyết định",
          ]}
          rows={[
            [
              "RapidOCR v4 CH (nền cũ)",
              "Apache-2.0",
              "0,2243",
              "0,1054",
              "0,7158",
              "1.342 / 1.689 ms",
              "339,2 MB",
              "Đã thay thế",
            ],
            [
              "RapidOCR v3 PP-OCRv5 Latin (use_cls=False)",
              "Apache-2.0",
              "0,1096",
              "0,0294 (biên lai: 0,0112)",
              "0,8041",
              "734 / 1.032 ms",
              "336,2 MB",
              "Chọn chạy chính (12,14 MB)",
            ],
            [
              "RapidOCR v3 PP-OCRv5 Latin (use_cls=True)",
              "Apache-2.0",
              "0,1933",
              "0,1251",
              "0,7912",
              "749 / 1.069 ms",
              "340,5 MB",
              "Loại (lật nhầm dòng ngắn)",
            ],
            [
              "MinerU v4.2.3 Basic ONNX",
              "Không permissive",
              "0,0906",
              "0,0554",
              "0,9400",
              "1.210 / 1.312 ms",
              "948,4 MB",
              "Không dùng ở prod (2,77 GB đĩa)",
            ],
            [
              "Gemini Multimodal OCR",
              "API thương mại",
              "0,0000",
              "0,0000",
              "1,0000",
              "5.182 / 12.350 ms",
              "112,2 MB (client)",
              "Dự phòng có điều kiện",
            ],
          ]}
        />

        <p className="text-xs text-ink-muted">
          <strong className="text-ink-secondary">Hạng mục chưa đo kiểm:</strong> Chưa có kết quả đo
          tải đồng thời nhiều người dùng (load/stress test) kéo dài trên hạ tầng sản xuất và chưa có
          đánh giá độ chính xác trên tập dữ liệu giao dịch thực tế ngoài môi trường thử nghiệm.
        </p>
      </DocSection>

      {/* 15. Các biện pháp bảo mật */}
      <DocSection id="bien-phap-bao-mat" number="15" title="Các biện pháp bảo mật">
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Kiểm soát tải lên và chống tấn công tài nguyên:</strong>{" "}
            Pure ASGI middleware giới hạn kích thước thân yêu cầu theo luồng (streaming body limit),
            từ chối tệp vượt ngưỡng (HTTP 413) hoặc định dạng giả mạo/rỗng/hỏng (HTTP 400), chặn
            decompression bomb ảnh và tệp âm thanh bất thường.
          </li>
          <li>
            <strong className="font-semibold text-ink">Phòng chống SSRF đa lớp:</strong> Chặn toàn bộ
            dải địa chỉ không công khai (loopback, RFC1918, CGNAT 100.64.0.0/10, link-local/IMDS
            169.254.0.0/16, multicast, IPv4-mapped IPv6, IP viết tắt/thập lục phân, Unix socket) ở
            URL gốc, từng bước chuyển hướng và mọi sub-request trong Playwright; kết hợp ghim socket
            TCP vào IP đã kiểm duyệt.
          </li>
          <li>
            <strong className="font-semibold text-ink">Phòng vệ Prompt Injection và cách ly OCR:</strong>{" "}
            Bọc dữ liệu đầu vào trong thẻ <code className="font-mono text-ink">&lt;UNTRUSTED_USER_CONTENT&gt;</code>,
            tách biệt URL chỉ xuất hiện trong văn bản OCR để không bao giờ tự truy vấn mạng, và dùng
            bộ phát hiện tiêm lệnh kết hợp sàn điểm bảo mật.
          </li>
          <li>
            <strong className="font-semibold text-ink">Bảo vệ quản trị và giảm thiểu PII:</strong>{" "}
            Xác thực khóa bí mật bằng hàm so sánh thời gian hằng (
            <code className="font-mono text-ink">hmac.compare_digest</code>), áp dụng giới hạn tần
            suất riêng chặt hơn cho thao tác ghi quy tắc, chặn sử dụng mã PIN yếu/mặc định khi chạy
            ở môi trường production, băm HMAC-SHA256 cho đối chiếu IOC và lưu nhật ký kiểm toán
            không chứa dữ liệu thô.
          </li>
          <li>
            <strong className="font-semibold text-ink">Cô lập container &amp; tiêu đề HTTP:</strong>{" "}
            Chạy tiến trình không phải root, gỡ bỏ toàn bộ Linux capabilities không cần thiết (
            <code className="font-mono text-ink">cap_drop: ALL</code>,{" "}
            <code className="font-mono text-ink">no-new-privileges</code>), bật HSTS, CSP và kiểm
            định tự động qua các bộ test bảo mật red-team (<code className="font-mono text-ink">test_security_redteam.py</code>,{" "}
            <code className="font-mono text-ink">test_ocr_pipeline_security.py</code>,{" "}
            <code className="font-mono text-ink">test_radar_security_and_simulation.py</code>).
          </li>
        </ul>
      </DocSection>

      {/* 16. Giới hạn của hệ thống */}
      <DocSection id="gioi-han-he-thong" number="16" title="Giới hạn của hệ thống">
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Không thay thế xác minh dòng tiền ngân hàng:</strong>{" "}
            Mọi kết luận đều mang tính hỗ trợ tham khảo; phân tích ảnh biên lai không thể chứng minh
            tiền đã thực sự ghi có vào tài khoản và hệ thống không có quyền tự động chặn giao dịch
            trên ngân hàng/ví điện tử.
          </li>
          <li>
            <strong className="font-semibold text-ink">Phạm vi dữ liệu huấn luyện tổng hợp:</strong>{" "}
            Mô hình E5 INT8 và các bộ benchmark đều xây dựng từ dữ liệu tổng hợp và thông báo khuyến
            cáo công khai; các biến thể lừa đảo mới tinh vi ngoài tập mẫu vẫn cần giám sát và cập
            nhật định kỳ.
          </li>
          <li>
            <strong className="font-semibold text-ink">Giới hạn OCR và nhận diện giọng nói cục bộ:</strong>{" "}
            <code className="font-mono text-ink">latin_PP-OCRv5_rec_mobile</code> vẫn có tỷ lệ sai
            dấu tiếng Việt khoảng 10,96% trên ảnh nhỏ/mờ (CER không dấu 2,94%) và việc tắt xoay dòng
            (<code className="font-mono text-ink">use_cls=False</code>) khiến ảnh xoay ngược 180 độ
            phải dựa vào tầng AI dự phòng. Mô hình <code className="font-mono text-ink">faster-whisper tiny</code>{" "}
            ưu tiên tiết kiệm RAM nên độ chính xác kém hơn trên cuộc gọi nhiều nhiễu.
          </li>
          <li>
            <strong className="font-semibold text-ink">Giới hạn kiến trúc mở rộng &amp; phân quyền:</strong>{" "}
            Bộ giới hạn tần suất hiện lưu trong RAM phù hợp mô hình 1 worker (cần chuyển sang kho
            dùng chung như Redis nếu mở rộng nhiều worker); trang{" "}
            <code className="font-mono text-ink">/radar</code> đang dùng chế độ xem công khai đã che
            giấu kết hợp xác thực PIN cho thao tác ghi, chưa tích hợp SSO/RBAC doanh nghiệp; bảng hồ
            sơ chưa có lịch xóa tự động theo TTL.
          </li>
        </ul>
      </DocSection>

      {/* 17. Thư viện và giấy phép sử dụng */}
      <DocSection id="thu-vien-giay-phep" number="17" title="Thư viện và giấy phép sử dụng">
        <p>
          VeriShield AI chỉ sử dụng các thư viện và mô hình mã nguồn mở có giấy phép cho phép triển
          khai thương mại/mở trong môi trường production. Các mô hình có giấy phép hạn chế nghiên
          cứu hoặc copyleft mạnh (như <code className="font-mono text-ink">uitnlp/visobert</code>,{" "}
          <code className="font-mono text-ink">vinai/phobert*</code> AGPL-3.0, hoặc{" "}
          <code className="font-mono text-ink">MinerU</code> với điều khoản giới hạn thương mại)
          không được đưa vào gói chạy thật.
        </p>

        <DocTable
          caption="Danh mục mã nguồn dự án, mô hình AI, thư viện và giấy phép đã xác minh"
          headers={["Nhóm", "Thành phần", "Giấy phép", "Ghi chú & Attribution"]}
          rows={[
            [
              "Dự án",
              "VeriShield AI",
              "MIT",
              "Copyright (c) 2026 Trần Chí Vỹ (tệp LICENSE tại thư mục gốc).",
            ],
            [
              "Mô hình AI cục bộ",
              "intfloat/multilingual-e5-small · faster-whisper / OpenAI Whisper",
              "MIT",
              "Backbone phân loại ngữ nghĩa tiếng Việt 384 chiều và mô hình gỡ băng giọng nói INT8.",
            ],
            [
              "Mô hình & Engine OCR",
              "RapidOCR v3 · PaddleOCR PP-OCRv5 (det & latin rec mobile)",
              "Apache-2.0",
              "Xác minh từ kho RapidAI/RapidOCR và PaddlePaddle/PaddleOCR (ADR-001).",
            ],
            [
              "AI bên thứ ba (tùy chọn)",
              "Google Gemini API (google-genai SDK: Apache-2.0)",
              "API thương mại",
              "Tầng suy luận tùy chọn; hệ thống vẫn vận hành ở chế độ nội bộ khi không cấu hình.",
            ],
            [
              "Backend Runtime",
              "FastAPI, Pydantic, pydantic-settings, ONNX Runtime (MIT) · Uvicorn, HTTPX, idna, NumPy, PyAV/av (BSD-3-Clause) · Pillow (MIT-CMU) · Tokenizers, OpenCV-headless, Playwright, python-multipart (Apache-2.0) · fpdf2 (LGPL-3.0-only)",
              "Permissive / LGPL-3.0",
              "Kiểm tra từ metadata gói cài đặt thực tế trong backend/requirements.txt.",
            ],
            [
              "Frontend Web",
              "Next.js 15, React 19, Tailwind CSS v4 (MIT) · TypeScript (Apache-2.0) · Lucide React (ISC)",
              "MIT / Apache-2.0 / ISC",
              "Khai báo trong frontend/package.json.",
            ],
            [
              "Phông chữ",
              "DejaVuSans.ttf (PDF) · Inter & JetBrains Mono (Web)",
              "Bitstream Vera / SIL OFL-1.1",
              "DejaVuSans: Fonts (c) 2003 Bitstream, Inc.; Arev glyphs (c) 2006 Tavmjong Bah; DejaVu modifications in Public Domain (xem backend/app/data/fonts/LICENSE-DejaVu.txt). Inter & JetBrains Mono tự đóng gói qua next/font.",
            ],
            [
              "Cơ sở dữ liệu & Proxy",
              "SQLite 3 (Public Domain) · Caddy 2 (Apache-2.0)",
              "Public Domain / Apache-2.0",
              "Hạ tầng lưu trữ WAL và reverse proxy HTTPS.",
            ],
          ]}
        />

        <p className="pt-2 text-xs text-ink-muted">
          Tìm hiểu cách dữ liệu người dùng đi qua từng thành phần trên tại trang{" "}
          <Link
            href="/privacy"
            className="font-medium text-sky-300 underline decoration-sky-500/40 underline-offset-2 hover:text-sky-200"
          >
            Chính sách quyền riêng tư
          </Link>
          .
        </p>
      </DocSection>
    </DocsShell>
  );
}
