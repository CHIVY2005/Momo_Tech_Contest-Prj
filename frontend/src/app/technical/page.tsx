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
import { DrawOnView } from "@/components/motion/DrawOnView";

export const metadata: Metadata = {
  title: "Công nghệ và kiến trúc hệ thống — VeriShield AI",
  description:
    "Tài liệu kỹ thuật về kiến trúc phân tích ba tầng, mô hình E5 ONNX, Trợ lý VeriShield (RAG lai E5 + BM25, cổng kiểm duyệt 3 tầng, công cụ kiểm soát), công cụ OCR, phân tích mã VietQR, kiểm tra đường dẫn, mạng lưới liên kết gian lận, kết quả thực nghiệm và giấy phép sử dụng của VeriShield AI.",
};

const TECHNICAL_TOC: readonly TocItem[] = [
  { id: "tong-quan-he-thong", number: "01", label: "Tổng quan hệ thống" },
  { id: "kien-truc-tong-the", number: "02", label: "Kiến trúc tổng thể" },
  { id: "quy-trinh-phan-tich", number: "03", label: "Quy trình phân tích dữ liệu" },
  { id: "kien-truc-ba-tang", number: "04", label: "Kiến trúc phân tích ba tầng" },
  { id: "phan-loai-e5-onnx", number: "05", label: "Phân loại ngữ nghĩa với E5 và ONNX" },
  { id: "ocr-phan-tich-anh", number: "06", label: "OCR và phân tích hình ảnh" },
  { id: "phan-tich-vietqr", number: "07", label: "Phân tích mã VietQR" },
  { id: "phan-tich-url", number: "08", label: "Phân tích đường dẫn và tên miền" },
  { id: "ai-da-phuong-thuc", number: "09", label: "AI đa phương thức" },
  { id: "tro-ly-verishield", number: "10", label: "Trợ lý VeriShield: RAG lai và cổng an toàn" },
  { id: "mang-luoi-lien-ket", number: "11", label: "Mạng lưới liên kết gian lận" },
  { id: "quy-trinh-khep-kin", number: "12", label: "Quy trình phòng chống gian lận khép kín" },
  { id: "cong-nghe-su-dung", number: "13", label: "Công nghệ sử dụng" },
  { id: "kien-truc-trien-khai", number: "14", label: "Kiến trúc triển khai" },
  { id: "danh-gia-hieu-nang", number: "15", label: "Đánh giá hiệu năng và kết quả thực nghiệm" },
  { id: "bien-phap-bao-mat", number: "16", label: "Các biện pháp bảo mật" },
  { id: "gioi-han-he-thong", number: "17", label: "Giới hạn của hệ thống" },
  { id: "thu-vien-giay-phep", number: "18", label: "Thư viện và giấy phép sử dụng" },
];

export default function TechnicalPage() {
  return (
    <DocsShell
      breadcrumbLabel="Công nghệ"
      title="Công nghệ và kiến trúc hệ thống"
      description="Tài liệu kỹ thuật trình bày kiến trúc phân tích đa phương thức, mô hình suy luận cục bộ, cơ chế phòng vệ an ninh mạng, kết quả thực nghiệm và giấy phép thành phần của VeriShield AI."
      metaItems={[
        { label: "Loại tài liệu", value: "Tài liệu kiến trúc kỹ thuật và báo cáo thực nghiệm" },
        { label: "Nguyên tắc công bố", value: "Chỉ trình bày chỉ số thực nghiệm đã đo lường; phân rõ chức năng đã triển khai và dự kiến" },
      ]}
      tocItems={TECHNICAL_TOC}
    >
      {/* 1. Tổng quan hệ thống */}
      <DocSection id="tong-quan-he-thong" number="01" title="Tổng quan hệ thống">
        <p>
          <strong className="font-semibold text-ink">VeriShield AI</strong> là hệ thống phân tích
          bằng chứng đa phương thức hỗ trợ nhận diện dấu hiệu lừa đảo tài chính tại Việt Nam trước
          thời điểm chuyển tiền, đồng thời kết nối trực tiếp với Trung tâm giám sát gian lận khép
          kín (<Link href="/radar" className="text-sky-300 underline decoration-sky-500/40 underline-offset-2 hover:text-sky-200">/radar</Link>).
        </p>
        <p>
          Hệ thống kết hợp các cơ chế kiểm tra kỹ thuật xác định (phân tích hình ảnh, chuẩn EMVCo
          VietQR, kiểm tra đường dẫn và trình duyệt cách ly), mô hình phân loại ngữ nghĩa tiếng Việt
          lượng tử hóa số nguyên 8-bit (INT8) chạy qua ONNX Runtime (Open Neural Network Exchange)
          trực tiếp trên CPU, tầng AI đa phương thức tùy chọn có chế độ xử lý dự phòng khi gián đoạn,
          và <strong className="font-semibold text-ink">Trợ lý VeriShield</strong> hỗ trợ hỏi đáp
          theo ngữ cảnh hồ sơ dựa trên truy xuất tri thức kết hợp (Hybrid RAG) cục bộ cùng cổng kiểm
          duyệt đầu ra nhiều tầng.
        </p>

        <DocTable
          caption="Trạng thái triển khai các nhóm chức năng của VeriShield AI"
          headers={["Chức năng", "Trạng thái", "Phạm vi triển khai hiện tại"]}
          rows={[
            [
              "Kiểm tra đa phương thức (văn bản, đường dẫn, tối đa 4 ảnh, 2 ghi âm) có cập nhật tiến độ thời gian thực (SSE)",
              <ImplementationStatus key="s1" status="implemented" />,
              "Hoạt động trên trang kiểm tra chính (/), giao diện lập trình API và kênh Telegram Bot (khi cấu hình).",
            ],
            [
              "Phân loại E5 INT8 ONNX, RapidOCR PP-OCRv5 Latin, VietQR CRC-16, phân tích dấu hiệu chỉnh sửa ảnh, kiểm tra URL và trình duyệt cách ly",
              <ImplementationStatus key="s2" status="implemented" />,
              "Thực thi cục bộ trên CPU của máy chủ backend; không cần PyTorch trong môi trường vận hành.",
            ],
            [
              "Trợ lý VeriShield (Hybrid E5 + BM25/RRF RAG cục bộ, cổng kiểm duyệt đầu ra 3 tầng, công cụ xác minh chỉ đọc theo tham chiếu, bằng chứng bổ sung cục bộ tạm thời & khóa phiên truy cập hồ sơ thống nhất)",
              <ImplementationStatus key="s2b" status="implemented" />,
              "Tái sử dụng phiên E5 ONNX đã nạp ở Tầng 1 (không thêm framework RAG hay cơ sở dữ liệu vector rời); bảo vệ đồng bộ đọc hồ sơ, tải PDF và Trợ lý bằng khóa phiên HMAC 128-bit (hết hạn sau 2 giờ), còn Telegram Bot chỉ gửi PDF qua chat riêng 1-1.",
            ],
            [
              "Mạng lưới liên kết gian lận và quy trình áp dụng quy tắc chặn tạm thời (TTL, chống chặn nhầm, mô phỏng tách biệt, nhật ký kiểm toán)",
              <ImplementationStatus key="s3" status="implemented" />,
              "Hoạt động tại Trung tâm giám sát (/radar) dựa trên SQLite WAL và cơ chế băm có khóa HMAC-SHA256.",
            ],
            [
              "Bộ chuyển đổi công cụ OCR MinerU Basic ONNX",
              <ImplementationStatus key="s4" status="experimental" />,
              "Chỉ dùng để đối sánh nghiên cứu trong môi trường tách biệt; không tích hợp vào môi trường vận hành do tài nguyên và điều khoản giấy phép bổ sung.",
            ],
            [
              "Xác thực đăng nhập một lần/phân quyền theo vai trò (SSO/RBAC) cho quản trị, tự động xóa hồ sơ định kỳ, giới hạn tần suất phân tán (Redis) và tích hợp cổng thanh toán",
              <ImplementationStatus key="s5" status="planned" />,
              "Chưa triển khai ở phiên bản hiện tại; được liệt kê cụ thể trong phần Giới hạn của hệ thống.",
            ],
          ]}
        />
      </DocSection>

      {/* 2. Kiến trúc tổng thể */}
      <DocSection id="kien-truc-tong-the" number="02" title="Kiến trúc tổng thể">
        <p>
          VeriShield AI được tổ chức trong một kho mã nguồn thống nhất (monorepo), tách biệt lớp
          giao diện web (Next.js 15), dịch vụ phân tích và suy luận cục bộ (FastAPI + ONNX
          Runtime), quy trình huấn luyện ngoại tuyến và bộ kịch bản đánh giá thực nghiệm.
        </p>

        <DrawOnView>
          <SystemArchitectureSvg />
        </DrawOnView>

        <p>
          Lưu lượng thực tế đi qua máy chủ trung gian (reverse proxy) Caddy 2 để xử lý mã hóa HTTPS
          (TLS), gắn tiêu đề bảo mật (HSTS, CSP) và giới hạn dung lượng yêu cầu trước khi chuyển
          tiếp tới FastAPI theo chế độ truyền kết quả trực tiếp theo thời gian thực (SSE, không lưu
          đệm) nhằm đẩy tiến độ và phản hồi Trợ lý VeriShield về trình duyệt.
        </p>
      </DocSection>

      {/* 3. Quy trình phân tích dữ liệu */}
      <DocSection id="quy-trinh-phan-tich" number="03" title="Quy trình phân tích dữ liệu">
        <p>
          Về mặt thực thi, quy trình phân tích chạy tuần tự qua bước kiểm tra đầu vào và{" "}
          <strong className="font-semibold text-ink">4 giai đoạn xử lý</strong>, phát sự kiện tiến
          độ thời gian thực ở cuối mỗi giai đoạn. Trong đó, Giai đoạn 1–3 thuộc{" "}
          <strong className="font-semibold text-ink">Tầng 1</strong> (phân tích cục bộ), còn Giai
          đoạn 4 thực thi lần lượt <strong className="font-semibold text-ink">Tầng 2</strong> (AI đa
          phương thức) và <strong className="font-semibold text-ink">Tầng 3</strong> (hiệu chuẩn,
          ứng phó và lưu trữ):
        </p>

        <ol className="list-decimal space-y-2.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">Kiểm tra đầu vào tệp tải lên:</strong> Đọc
            luồng có kiểm soát dung lượng (≤ 10 MB mỗi tệp, tổng ≤ 20 MB, tối đa 4 ảnh và 2 ghi âm),
            xác thực kiểu MIME, chữ ký đầu tệp (magic bytes), giới hạn kích thước giải nén ảnh (≤ 25
            triệu điểm ảnh) và giới hạn giải mã âm thanh (≤ 10 phút).
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Giai đoạn 1 (Tầng 1) — Phân tích hình ảnh, âm thanh, OCR và VietQR:
            </strong>{" "}
            Kiểm tra dấu hiệu chỉnh sửa ảnh, siêu dữ liệu EXIF/XMP, mã băm đặc trưng hình ảnh
            (dHash) và giải mã mã QR bằng OpenCV; sau đó trích xuất chữ bằng công cụ OCR cục bộ
            (RapidOCR PP-OCRv5 Latin, có dự phòng có điều kiện) và chuyển giọng nói thành văn bản
            (Speech-to-Text — STT) bằng <code className="font-mono text-ink">faster-whisper</code>.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Giai đoạn 2 (Tầng 1) — Trích xuất dấu hiệu, kiểm tra đường dẫn và bộ lọc an toàn:
            </strong>{" "}
            Tách nguồn gốc đường dẫn (URL người dùng nhập trực tiếp hoặc từ mã QR so với URL chỉ
            trích từ chữ ảnh), đối chiếu danh sách chặn đang hiệu lực, kiểm tra tĩnh, lần theo
            chuyển hướng qua kết nối ràng buộc IP công cộng, kích hoạt trình duyệt cách ly với URL
            đáng ngờ (trừ URL chỉ có trong OCR) và rà soát tấn công chèn chỉ thị (Prompt Injection)
            cùng tin khuyến cáo an toàn.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Giai đoạn 3 (Tầng 1) — Phân loại E5 ONNX, truy xuất tri thức và kiểm tra biên lai:
            </strong>{" "}
            Thực thi một lượt suy luận mô hình E5-Small INT8 ONNX để lấy đồng thời xác suất 7 lớp và
            vector ngữ nghĩa 384 chiều, đối chiếu 20 kịch bản lừa đảo phổ biến tại Việt Nam, đồng
            thời kiểm tra tính hợp lệ nghiệp vụ biên lai và phát hiện biên lai gửi lặp lại theo giao
            dịch nguyên tử trong cơ sở dữ liệu.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Giai đoạn 4 (Tầng 2 → Tầng 3) — AI đa phương thức, hiệu chuẩn và lưu hồ sơ:
            </strong>{" "}
            Gọi AI đa phương thức Tầng 2 (tự chuyển chế độ xử lý dự phòng nếu gián đoạn hoặc chưa cấu
            hình), kiểm tra bổ sung dấu hiệu nếu AI trích thêm lời thoại cuộc gọi, sau đó chuyển sang
            Tầng 3 để hiệu chuẩn điểm từ 3 nguồn tín hiệu, tạo khuyến nghị ứng phó, che giấu số điện
            thoại/số tài khoản và lưu vào SQLite WAL (bỏ qua bước lưu khi chạy mô phỏng).
          </li>
        </ol>
      </DocSection>

      {/* 4. Kiến trúc phân tích ba tầng */}
      <DocSection id="kien-truc-ba-tang" number="04" title="Kiến trúc phân tích ba tầng">
        <p>
          Thay vì dựa vào một mô hình ngôn ngữ duy nhất, VeriShield AI tách trách nhiệm thành{" "}
          <strong className="font-semibold text-ink">3 tầng kiến trúc</strong>: Tầng 1 đảm nhiệm
          kiểm tra kỹ thuật xác định và phân loại ngữ nghĩa cục bộ (E5-Small INT8 ONNX); Tầng 2 bổ
          sung suy luận ngữ cảnh đa phương thức (Google Gemini hoặc cổng tương thích OpenAI); Tầng 3
          hiệu chuẩn điểm từ <strong className="font-semibold text-ink">3 nguồn tín hiệu</strong>{" "}
          (điểm kiểm tra kỹ thuật Tầng 1, xác suất từ E5 ONNX thuộc Tầng 1 và điểm suy luận AI Tầng
          2) để ra kết luận và gói hành động ứng phó.
        </p>

        <DrawOnView>
          <ThreeTierFusionSvg />
        </DrawOnView>

        <ul className="list-disc space-y-1.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">Tránh cộng dồn sai lệch:</strong> Điểm kiểm
            tra kỹ thuật Tầng 1 sử dụng toán tử giá trị lớn nhất (
            <code className="font-mono text-ink">max</code>) giữa các thành phần độc lập (URL, môi
            trường cách ly, phân tích hình ảnh, biên lai, VietQR, kho kịch bản) thay vì cộng tuyến
            tính.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Bảo toàn bằng chứng kỹ thuật bằng ngưỡng điểm rủi ro tối thiểu:
            </strong>{" "}
            Khi phát hiện dấu hiệu rõ ràng như trùng danh sách chặn, bẫy VietQR hoàn tiền, biên lai
            dùng lại, lệch tài khoản thụ hưởng, giả mạo thương hiệu hoặc tấn công chèn chỉ thị, bộ
            hiệu chuẩn áp đặt ngưỡng điểm rủi ro tối thiểu để AI Tầng 2 không thể hạ thấp cảnh báo.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Thận trọng khi trích xuất văn bản không hoàn tất:
            </strong>{" "}
            Nếu công cụ OCR gặp lỗi, quá thời gian hoặc ảnh không đọc được chữ mà không có ngữ cảnh
            văn bản, mã QR hay xác minh thị giác bổ sung, hệ thống giữ mức điểm thận trọng và hạ độ
            tin cậy thay vì kết luận rủi ro thấp.
          </li>
        </ul>
      </DocSection>

      {/* 5. Phân loại ngữ nghĩa với E5 và ONNX */}
      <DocSection id="phan-loai-e5-onnx" number="05" title="Phân loại ngữ nghĩa với E5 và ONNX">
        <p>
          Mô hình phân loại ngữ nghĩa cục bộ (thuộc Tầng 1) được huấn luyện ngoại tuyến từ mô hình
          nền mã nguồn mở <code className="font-mono text-ink">intfloat/multilingual-e5-small</code>{" "}
          (giấy phép MIT) theo kiến trúc hai đầu ra (Dual-Head):
        </p>

        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Kiến trúc mạng:</strong> Cố định trọng số bộ
            mã hóa ngữ nghĩa E5 (vector 384 chiều, độ dài chuỗi tối đa 192 token) để bảo toàn biểu
            diễn tiếng Việt, kết hợp đầu phân loại đa tầng (MLP — Multi-Layer Perceptron) trên
            vector gộp trung bình chuẩn hóa L2. Một lượt chạy xuất đồng thời xác suất 7 lớp và
            vector 384 chiều phục vụ truy xuất kịch bản.
          </li>
          <li>
            <strong className="font-semibold text-ink">7 lớp phân loại:</strong> Giao dịch/hội thoại
            bình thường (<code className="font-mono text-ink">SAFE_NORMAL</code>), khuyến cáo phòng
            tránh lừa đảo (<code className="font-mono text-ink">SAFE_ADVISORY</code>), giả mạo cơ
            quan chức năng (<code className="font-mono text-ink">SCAM_IMPERSONATION</code>), việc
            nhẹ/đầu tư/vay (<code className="font-mono text-ink">SCAM_TASK_INVEST_LOAN</code>),
            đường dẫn giả mạo/APK/OTP (<code className="font-mono text-ink">SCAM_PHISHING_APK_OTP</code>),
            vay tiền khẩn cấp (<code className="font-mono text-ink">SCAM_URGENT_BORROW</code>) và
            tấn công chèn chỉ thị (<code className="font-mono text-ink">PROMPT_INJECTION</code>).
          </li>
          <li>
            <strong className="font-semibold text-ink">Tối ưu dung lượng và bộ nhớ:</strong> Cắt tỉa
            từ vựng SentencePiece xuống <strong className="text-ink">36.000 token</strong> Việt–Anh
            (chỉ khớp trên tập huấn luyện và kho kịch bản nhằm tránh rò rỉ dữ liệu kiểm thử) rồi
            lượng tử hóa động sang INT8, đạt dung lượng tệp ONNX{" "}
            <strong className="text-ink">34,3 MB</strong>.
          </li>
          <li>
            <strong className="font-semibold text-ink">Tách biệt huấn luyện và vận hành:</strong>{" "}
            Môi trường chạy thật không cài PyTorch hay Transformers; mô hình suy luận trên{" "}
            <code className="font-mono text-ink">onnxruntime</code> CPU với tùy chọn tắt giữ vùng
            đệm bộ nhớ dài hạn để ổn định RAM.
          </li>
          <li>
            <strong className="font-semibold text-ink">Truy xuất tri thức kết hợp (Hybrid KB):</strong>{" "}
            Kết hợp độ tương đồng cosine trên vector 384 chiều với đối khớp cụm từ không phân biệt
            dấu tiếng Việt đối chiếu với <strong className="text-ink">20 kịch bản lừa đảo</strong>{" "}
            phổ biến tại Việt Nam.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Tái sử dụng duy nhất 1 phiên ONNX cho Trợ lý VeriShield:
            </strong>{" "}
            Trợ lý VeriShield dùng chung chính phiên{" "}
            <code className="font-mono text-ink">intfloat/multilingual-e5-small</code> INT8 ONNX sẵn
            có để mã hóa câu hỏi 384 chiều mà không nạp phiên ONNX thứ hai; toàn bộ gói tệp mô hình
            và chỉ mục tri thức đóng gói trong kho mã nguồn có dung lượng{" "}
            <strong className="text-ink">36,11 MB</strong> (nhỏ hơn ngưỡng 50 MB).
          </li>
        </ul>
      </DocSection>

      {/* 6. OCR và phân tích hình ảnh */}
      <DocSection id="ocr-phan-tich-anh" number="06" title="OCR và phân tích hình ảnh">
        <p>
          Phân hệ hình ảnh kết hợp trích xuất văn bản dạng mô-đun (OCR — Optical Character
          Recognition), phân tích dấu hiệu chỉnh sửa hình ảnh và kiểm tra tính nhất quán nghiệp vụ
          của biên lai chuyển khoản Việt Nam:
        </p>

        <DocTable
          caption="Các thành phần OCR và phân tích hình ảnh trong VeriShield AI"
          headers={["Thành phần", "Cơ chế triển khai", "Vai trò phát hiện"]}
          rows={[
            [
              "Công cụ OCR chính: RapidOCR v3 PP-OCRv5 Latin (ONNX CPU)",
              "Dùng bộ trọng số phát hiện chữ và nhận diện ký tự Latin PP-OCRv5 bản nhẹ (12,14 MB, Apache-2.0), đóng gói sẵn ngoại tuyến trong container và tắt bước phân loại xoay dòng dựa trên thực nghiệm loại trừ thành phần (ablation).",
              "Trích xuất văn bản tiếng Việt, số tài khoản, mã giao dịch kèm tọa độ khung chữ phục vụ kiểm tra sai lệch hình học.",
            ],
            [
              "OCR dự phòng có điều kiện (Gemini Multimodal OCR)",
              "Chỉ kích hoạt khi công cụ OCR cục bộ lỗi, quá thời gian, độ tin cậy thấp hoặc ảnh không kèm văn bản/QR nhưng không trích xuất được chữ; có giới hạn chặt về thời gian chờ và số ảnh mỗi lượt.",
              "Khôi phục nội dung trên ảnh mờ, tương phản thấp hoặc xoay ngược mà không làm tăng độ trễ ở trường hợp thông thường.",
            ],
            [
              "Phân tích tính xác thực của hình ảnh (ELA, EXIF/XMP, dHash)",
              "Phân tích sai số nén ảnh (Error Level Analysis — ELA) tạo bản đồ nhiệt bất thường, quét siêu dữ liệu EXIF/XMP tìm dấu vết công cụ chỉnh sửa ảnh và tính mã băm đặc trưng hình ảnh (dHash 64-bit).",
              "Phát hiện vùng ghép số tiền/ký tự, dấu vết phần mềm chỉnh sửa và nhận diện ảnh biên lai đã từng được gửi lặp lại.",
            ],
            [
              "Kiểm tra logic biên lai chuyển khoản",
              "Kiểm tra cấu trúc số tiền (phát hiện trộn lẫn dấu chấm/phẩy), cấu trúc mã tham chiếu giao dịch, tính hợp lý của mốc thời gian theo múi giờ Việt Nam, độ đồng nhất chiều cao dòng chữ OCR và đối chiếu số tài khoản thụ hưởng.",
              "Phát hiện biên lai giả mạo về mặt nghiệp vụ đồng thời giữ nguyên cảnh báo chưa thể xác nhận dòng tiền chỉ từ ảnh chụp.",
            ],
          ]}
        />

        <DocCallout tone="warning" title="Nguyên tắc xác minh biên lai">
          <p>
            Ngay cả khi ảnh chụp biên lai không có dấu hiệu chỉnh sửa và đạt mức rủi ro thấp, hệ
            thống vẫn đánh dấu là ảnh chụp chưa xác thực giao dịch và luôn khuyến cáo người bán đối
            chiếu trực tiếp biến động số dư trên ứng dụng ngân hàng hoặc loa thông báo nhận tiền
            trước khi giao hàng.
          </p>
        </DocCallout>
      </DocSection>

      {/* 7. Phân tích mã VietQR */}
      <DocSection id="phan-tich-vietqr" number="07" title="Phân tích mã VietQR">
        <p>
          Sau khi OpenCV giải mã một hoặc nhiều mã QR trong ảnh, phân hệ kiểm định chuỗi dữ liệu
          chứa trong mã QR theo tiêu chuẩn EMVCo Merchant-Presented QR và quy chuẩn VietQR của NAPAS
          (QĐ 1928/QĐ-NHNN):
        </p>
        <ul className="list-disc space-y-1.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">Kiểm tra toàn vẹn CRC-16/CCITT-FALSE:</strong>{" "}
            Tính mã kiểm tra chu kỳ (Cyclic Redundancy Check — CRC-16) trên toàn bộ khung dữ liệu
            EMVCo để phát hiện chuỗi VietQR bị can thiệp hoặc sai cấu trúc.
          </li>
          <li>
            <strong className="font-semibold text-ink">Giải mã cấu trúc Tag-Length-Value (TLV):</strong>{" "}
            Tách tuần tự các trường định danh dịch vụ NAPAS (tài khoản và thẻ), loại trừ thẻ trùng
            lặp, sai độ dài hoặc trường số tiền không hợp lệ.
          </li>
          <li>
            <strong className="font-semibold text-ink">Đối chiếu mã BIN ngân hàng và ngữ cảnh:</strong>{" "}
            Ánh xạ <strong className="text-ink">18 mã BIN ngân hàng Việt Nam</strong> trong kho tri
            thức, phân biệt mã QR tĩnh và động, phát hiện bẫy <em>&ldquo;quét mã để nhận/hoàn tiền&rdquo;</em>{" "}
            (trong khi mã QR thực chất là lệnh chuyển tiền đi) và kiểm tra sai lệch số tài khoản
            thụ hưởng để phòng chống dán đè mã QR tại quầy.
          </li>
        </ul>
      </DocSection>

      {/* 8. Phân tích đường dẫn và tên miền */}
      <DocSection id="phan-tich-url" number="08" title="Phân tích đường dẫn và tên miền">
        <p>
          Phân hệ phân tích đường dẫn (URL) kết hợp kiểm tra tĩnh, truy vết chuyển hướng an toàn và
          môi trường trình duyệt cách ly nhằm nhận diện trang giả mạo (phishing) và đường dẫn phát
          tán tệp cài đặt độc hại (<code className="font-mono text-ink">.apk</code>):
        </p>

        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Phân tích tĩnh tên miền:</strong> Chuẩn hóa
            tên miền quốc tế hóa (IDN/Punycode), khử ký tự đồng hình (homoglyph), đo độ tương đồng
            chuỗi (khoảng cách Levenshtein) với danh mục{" "}
            <strong className="text-ink">17 thương hiệu ngân hàng, ví điện tử và cơ quan chính thống</strong>{" "}
            tại Việt Nam, đánh giá tên miền cấp cao rủi ro cao và phát hiện đường dẫn thu thập OTP
            hoặc tải tệp <code className="font-mono text-ink">.apk</code>.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Truy vết chuyển hướng ràng buộc IP công cộng (IP Pinning):
            </strong>{" "}
            Kiểm tra từng bước chuyển hướng HTTP và ràng buộc kết nối TCP trực tiếp vào địa chỉ IP
            công cộng đã được kiểm duyệt, ngăn tấn công đổi ánh xạ DNS (DNS Rebinding) và giả mạo
            yêu cầu phía máy chủ (SSRF — Server-Side Request Forgery).
          </li>
          <li>
            <strong className="font-semibold text-ink">Trình duyệt cách ly (Playwright Sandbox):</strong>{" "}
            Chỉ kích hoạt đối với đường dẫn đáng ngờ và hợp lệ về chính sách mạng. Môi trường cách
            ly cô lập phân giải DNS, vô hiệu hóa các kênh truyền nền (WebSocket, EventSource,
            WebRTC, Beacon), định tuyến mọi yêu cầu tài nguyên phụ qua bộ lọc IP công cộng có giới
            hạn dung lượng/thời gian chờ, và phân tích DOM tìm biểu mẫu mật khẩu, OTP, thẻ ngân hàng
            hoặc liên kết tải <code className="font-mono text-ink">.apk</code>.
          </li>
          <li>
            <strong className="font-semibold text-ink">Cách ly đường dẫn chỉ xuất hiện trong OCR:</strong>{" "}
            Đường dẫn trích xuất đơn thuần từ văn bản ảnh chụp chỉ được kiểm tra tĩnh,{" "}
            <strong>không bao giờ</strong> tự động gửi truy vấn mạng hay mở trong trình duyệt cách
            ly để tránh bị kẻ tấn công lợi dụng qua ảnh chứa liên kết độc hại.
          </li>
        </ul>
      </DocSection>

      {/* 9. AI đa phương thức */}
      <DocSection id="ai-da-phuong-thuc" number="09" title="AI đa phương thức">
        <p>
          Tầng 2 sử dụng mô hình AI đa phương thức (LLM/VLM — Large Language / Vision-Language
          Model) nhằm bổ sung khả năng giải thích ngữ cảnh tiếng Việt tự nhiên, nhận diện thủ đoạn
          thao túng tâm lý, kiểm tra bất thường thị giác trên biên lai và gợi ý phản hồi an toàn:
        </p>
        <ul className="list-disc space-y-1.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">Tích hợp đa giao thức:</strong> Hỗ trợ song
            song Google GenAI SDK và cổng API tương thích OpenAI, ràng buộc kết quả trả về theo
            lược đồ JSON cố định để tầng hiệu chuẩn xử lý xác định.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Cách ly dữ liệu chống tấn công chèn chỉ thị (Prompt Injection):
            </strong>{" "}
            Loại bỏ ký tự ẩn/đảo chiều và tách biệt rõ ranh giới giữa hướng dẫn hệ thống với nội
            dung người dùng cùng văn bản OCR chưa tin cậy; các tín hiệu kỹ thuật Tầng 1 chỉ truyền
            vào dưới dạng nhãn chuẩn hóa.
          </li>
          <li>
            <strong className="font-semibold text-ink">Chuyển giọng nói thành văn bản hai lớp:</strong>{" "}
            Tệp ghi âm được chuyển thành văn bản cục bộ trước bằng{" "}
            <code className="font-mono text-ink">faster-whisper</code> INT8 (kèm lọc khoảng lặng
            VAD — Voice Activity Detection); nếu Tầng 2 bổ sung được lời thoại rõ hơn, quy trình tự
            động trích xuất lại dấu hiệu và đối chiếu danh sách chặn.
          </li>
          <li>
            <strong className="font-semibold text-ink">Chế độ xử lý dự phòng (Degraded Mode):</strong>{" "}
            Khi chưa cấu hình khóa API, hết thời gian chờ, gặp giới hạn tốc độ hoặc bộ lọc an toàn
            của nhà cung cấp, hệ thống tự động vận hành bằng Tầng 1 cục bộ và vẫn trả kết quả hợp lệ
            kèm trạng thái dự phòng.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Phát luồng văn bản và lọc khối suy luận nội bộ cho Trợ lý VeriShield:
            </strong>{" "}
            Tầng kết nối hỗ trợ phát luồng văn bản thời gian thực (streaming) trên cả Google GenAI
            SDK và cổng tương thích OpenAI, vô hiệu hóa chế độ gọi hàm tự động không kiểm soát, lọc
            bỏ theo luồng các khối suy luận nội bộ (
            <code className="font-mono text-ink">&lt;think&gt;</code>) trước khi chuyển qua cổng kiểm
            duyệt đầu ra, và tự động tổng hợp phản hồi dự phòng từ kho tri thức cục bộ nếu AI gián
            đoạn.
          </li>
        </ul>
      </DocSection>

      {/* 10. Trợ lý VeriShield: RAG lai và cổng an toàn */}
      <DocSection
        id="tro-ly-verishield"
        number="10"
        title="Trợ lý VeriShield: RAG lai và cổng an toàn"
      >
        <p>
          <strong className="font-semibold text-ink">Trợ lý VeriShield</strong> là phân hệ hỏi đáp
          phòng chống lừa đảo gắn ngữ cảnh hồ sơ, được thiết kế gọn nhẹ cho môi trường máy chủ CPU
          đơn nút mà không bổ sung framework RAG nặng (như LangChain) hay cơ sở dữ liệu vector rời.
        </p>

        <h3 className="pt-1 text-sm font-semibold text-ink">
          10.1. Kiến trúc RAG lai cục bộ không phụ thuộc framework nặng
        </h3>
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">
              Tái sử dụng duy nhất 1 phiên E5 INT8 ONNX:
            </strong>{" "}
            Tái sử dụng trực tiếp phiên{" "}
            <code className="font-mono text-ink">intfloat/multilingual-e5-small</code> INT8 ONNX đã
            nạp ở Tầng 1 (xem Mục 05) để mã hóa câu hỏi, giúp giữ nguyên độ gọn nhẹ trên một tiến
            trình CPU.
          </li>
          <li>
            <strong className="font-semibold text-ink">Kho tri thức 121 đoạn chuẩn hóa:</strong>{" "}
            Gồm <strong className="text-ink">20</strong> đoạn quy trình ứng phó sự cố sau lừa đảo
            (SOP — Standard Operating Procedure), <strong className="text-ink">20</strong> đoạn hướng
            dẫn xác minh qua kênh chính thức và <strong className="text-ink">81</strong> mục chuẩn
            hóa từ kho tri thức lừa đảo Việt Nam. Toàn bộ đoạn tri thức có độ dài tối đa{" "}
            <strong className="text-ink">140 token</strong> (nằm gọn dưới giới hạn 192 token của bộ
            mã hóa E5) với tỷ lệ ký tự ngoài từ vựng{" "}
            <code className="font-mono text-ink">&lt;unk&gt;</code> chỉ{" "}
            <strong className="text-ink">0,0488%</strong>.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Lưu vector chuẩn hóa L2 thô (<code className="font-mono text-ink">E_raw</code>) &amp;
              trừ trung bình trong RAM:
            </strong>{" "}
            Chỉ mục trên đĩa lưu nguyên ma trận vector chuẩn hóa L2 thô{" "}
            <code className="font-mono text-ink">E_raw</code> (mã hóa bằng chính mô hình INT8 ONNX
            để tránh lệch số học giữa FP32 và INT8). Khi khởi động, hệ thống thực hiện trừ trung bình
            (Mean-Centering theo kỹ thuật <em>All-but-the-Top</em> nhằm giảm hiện tượng các vector bị
            dồn cụm về cùng một hướng — anisotropy) đúng một lần trong RAM để sử dụng song song cả
            tín hiệu thô lẫn tín hiệu đã cân bằng không gian vector.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Kết hợp BM25 không dấu, Reciprocal Rank Fusion (RRF) và Dual-Signal Scope Gate:
            </strong>{" "}
            Phối hợp xếp hạng từ vựng <strong>BM25</strong> (Best Matching 25) trên văn bản tiếng
            Việt chuẩn hóa bỏ dấu với tìm kiếm ngữ nghĩa E5 đã Mean-Centering thông qua{" "}
            <strong>Reciprocal Rank Fusion (RRF)</strong> (hợp nhất thứ hạng nghịch đảo). Khi hỏi
            đáp không gắn hồ sơ, cổng kiểm soát phạm vi hai tín hiệu (
            <strong>Dual-Signal Scope Gate</strong>, hiệu chuẩn trên tập phát triển tách biệt) kết
            hợp tín hiệu từ vựng và ngữ nghĩa để từ chối câu hỏi ngoài miền phòng chống lừa đảo mà
            không cần tiêu tốn lượt gọi AI bên ngoài.
          </li>
        </ul>

        <h3 className="pt-2 text-sm font-semibold text-ink">
          10.2. Các lớp an toàn phòng thủ theo chiều sâu (Defense-in-Depth)
        </h3>
        <DocTable
          caption="Các lớp bảo vệ phòng thủ theo chiều sâu trong Trợ lý VeriShield"
          headers={["Lớp phòng vệ", "Cơ chế kiến trúc", "Mục tiêu an toàn"]}
          rows={[
            [
              "Kiểm soát truy cập hồ sơ thống nhất",
              "Áp dụng cơ chế khóa phiên HMAC 128-bit (hết hạn sau 2 giờ, không lưu bộ nhớ đệm) đồng bộ cho xem hồ sơ, tải PDF và Trợ lý; riêng Telegram chỉ gửi PDF trong chat 1-1 và khóa hồ sơ cũ (chi tiết tại Mục 16).",
              "Ngăn truy cập trái phép qua mã hồ sơ (IDOR), cô lập hoàn toàn dữ liệu giữa phiên web và Telegram.",
            ],
            [
              "RequestEntityVault & Chốt lọc đầu ra thống nhất (Egress Chokepoint)",
              "Lưu tạm thực thể cần xác minh trong lượt hiện tại (đường dẫn, mã VietQR, SĐT/STK) trên RAM gắn mã tham chiếu (ref_id); mọi luồng dữ liệu rời máy chủ sang AI ngoài (câu hỏi, lịch sử đã hạ quyền, trích đoạn hồ sơ, kết quả công cụ) đều đi qua một chốt lọc thống nhất loại bỏ thông tin nhạy cảm và bọc trong ranh giới dữ liệu chưa tin cậy.",
              "Ngăn rò rỉ PII/OTP/CCCD/mật khẩu/URL/VietQR thô tới AI bên ngoài và chống tấn công chèn chỉ thị gián tiếp.",
            ],
            [
              "Cổng kiểm duyệt đầu ra 3 tầng trước khi phát luồng (Pre-Emission Safety Gate)",
              "Kết hợp bộ lọc luồng <think> và 3 tầng kiểm duyệt trước khi phát văn bản: Tầng 0 trả lời xác định tức thì cho câu hỏi xác nhận tiền về hoặc giao hàng từ biên lai; Tầng 1 đệm toàn văn bản và đóng an toàn khi không đủ tin cậy (fail-closed) với mọi lượt liên quan biên lai, người bán, hồ sơ rủi ro thấp, câu hỏi an toàn tuyệt đối hoặc dấu hiệu chèn chỉ thị. Với câu trả lời thông thường, Tầng 2 chỉ phát từng câu hoàn chỉnh và tự động nâng lên Tầng 1 nếu câu dài hoặc chạm ngữ cảnh biên lai.",
              "Bảo đảm tuyệt đối nguyên tắc xác minh biên lai người bán, ngăn khẳng định an toàn tuyệt đối và chặn số hotline không có căn cứ.",
            ],
            [
              "Bộ công cụ xác minh chỉ đọc theo tham chiếu",
              "Danh sách công cụ cho phép chỉ gồm các thao tác chỉ đọc nhận mã ref_id từ RequestEntityVault: kiểm tra đường dẫn chống SSRF ràng buộc IP công cộng (không chạy trình duyệt ảo), kiểm định mã VietQR EMVCo/CRC-16, tra cứu uy tín IOC chỉ đọc, tra cứu chi tiết bằng chứng hồ sơ gắn phía máy chủ và tìm kiếm kho tri thức RAG.",
              "Ngăn mô hình tự tạo URL nội bộ, bảo vệ tài nguyên CPU/RAM và cấm tuyệt đối mọi thao tác ghi hay quản trị Trung tâm giám sát (/radar).",
            ],
            [
              "Phân tích bằng chứng bổ sung cục bộ tạm thời",
              "Ảnh hoặc ghi âm đính kèm trong khung Trợ lý mặc định chạy hoàn toàn cục bộ trên máy chủ (tắt AI đa phương thức ngoài và tắt OCR dự phòng ngoài, không phát yêu cầu mạng từ mã QR/lời thoại, 0 ghi DB/Radar, vẫn kiểm tra biên lai lặp lại chỉ đọc) và chỉ giữ tạm kết quả đã che giấu trong bộ nhớ tối đa 15 phút.",
              "Tách biệt hoàn toàn kiểm tra bổ sung riêng tư với lưu trữ và bên thứ ba; chỉ gửi media ra AI ngoài khi người dùng chủ động đánh dấu đồng ý và chỉ lưu hồ sơ con (kèm khóa phiên riêng) khi bấm lưu tường minh.",
            ],
          ]}
        />
      </DocSection>

      {/* 11. Mạng lưới liên kết gian lận */}
      <DocSection id="mang-luoi-lien-ket" number="11" title="Mạng lưới liên kết gian lận">
        <p>
          Các hồ sơ có mức rủi ro đáng kể (ngoại trừ phiên mô phỏng) sẽ cập nhật tần suất xuất hiện
          và mối liên kết đồng xuất hiện giữa các dấu hiệu nghi vấn (IOC — Indicator of Compromise,
          gồm số điện thoại, số tài khoản, tên miền) theo nhóm chiến dịch vào cơ sở dữ liệu SQLite
          WAL.
        </p>
        <ul className="list-disc space-y-1.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">
              Giả danh hóa và che giấu ngay tại tầng lưu trữ:
            </strong>{" "}
            Các nút đồ thị sử dụng mã băm một chiều (HMAC-SHA256 có khóa bí mật trong môi trường vận
            hành) làm khóa liên kết và chỉ hiển thị nhãn đã che giấu (như{" "}
            <code className="font-mono text-ink">091****678</code>,{" "}
            <code className="font-mono text-ink">19****01</code>,{" "}
            <code className="font-mono text-ink">na****.top</code>).
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Đồ thị SVG tùy biến hiệu năng cao không phụ thuộc thư viện nặng:
            </strong>{" "}
            Trang{" "}
            <Link
              href="/radar"
              className="text-sky-300 underline decoration-sky-500/40 underline-offset-2 hover:text-sky-200"
            >
              /radar
            </Link>{" "}
            sử dụng bố cục phân cụm theo lưới tuyến tính{" "}
            <code className="font-mono text-ink">O(N)</code>, cập nhật mượt theo khung hình (
            <code className="font-mono text-ink">requestAnimationFrame</code>) trên một lớp SVG duy
            nhất, hỗ trợ thu phóng quanh con trỏ, kéo mượt 1:1, vừa khung, toàn màn hình, lọc theo
            loại đối tượng và chuyển đổi bảng dữ liệu.
          </li>
          <li>
            <strong className="font-semibold text-ink">Tách bạch dữ liệu mẫu và dữ liệu thực:</strong>{" "}
            Chiến dịch mẫu phục vụ trình diễn được gắn nhãn riêng và không tự động nạp trong môi trường
            vận hành thực tế.
          </li>
        </ul>
      </DocSection>

      {/* 12. Quy trình phòng chống gian lận khép kín */}
      <DocSection
        id="quy-trinh-khep-kin"
        number="12"
        title="Quy trình phòng chống gian lận khép kín"
      >
        <p>
          VeriShield AI kết nối kết quả phát hiện đơn lẻ thành vòng lặp vận hành phòng chống gian
          lận khép kín (Closed-Loop Fraud Operations):
        </p>
        <p className="rounded-lg border border-border-subtle bg-surface-subtle/70 px-3.5 py-2.5 font-mono text-xs text-ink">
          Phát hiện dấu hiệu → Gom cụm chiến dịch → Kiểm tra bằng chứng → Xác nhận từng đối tượng
          &amp; thời hạn (TTL) → Áp dụng quy tắc chặn → Mô phỏng kiểm chứng → Thu hồi hoặc hết hiệu lực
        </p>
        <ul className="list-disc space-y-1.5 pl-5">
          <li>
            <strong className="font-semibold text-ink">Xác nhận từng đối tượng có kiểm soát:</strong>{" "}
            Người vận hành phải chọn rõ từng dấu hiệu cụ thể, ghi nhận lý do, chọn thời hạn hiệu lực
            tạm thời (TTL — Time to Live, mặc định 30 phút) và qua bước xác thực quản trị phía máy
            chủ.
          </li>
          <li>
            <strong className="font-semibold text-ink">Chống chặn nhầm thực thể chính thống:</strong>{" "}
            Các tên miền ngân hàng, cơ quan nhà nước và định danh sạch được bảo vệ sẽ bị từ chối khi
            tạo quy tắc chặn (<code className="font-mono text-ink">HTTP 409</code>) và ghi nhận vào
            nhật ký kiểm toán.
          </li>
          <li>
            <strong className="font-semibold text-ink">Phạm vi hiệu lực:</strong> Khi quy tắc có
            hiệu lực, mọi lượt kiểm tra khớp mã băm (bao gồm cả tên miền con của tên miền bị chặn)
            sẽ lập tức kích hoạt cảnh báo rủi ro rất cao trong VeriShield. Hệ thống không tự ý phong
            tỏa tài khoản ngân hàng của người dùng khi chưa có tích hợp cổng thanh toán chính thức.
          </li>
        </ul>
      </DocSection>

      {/* 13. Công nghệ sử dụng */}
      <DocSection id="cong-nghe-su-dung" number="13" title="Công nghệ sử dụng">
        <DocTable
          caption="Các nhóm công nghệ sử dụng trong VeriShield AI"
          headers={["Thành phần", "Công nghệ chính", "Vai trò cụ thể"]}
          rows={[
            [
              "Giao diện Web",
              "Next.js 15 (App Router), React 19, TypeScript 5.8 (strict), Tailwind CSS v4, Lucide Icons, Lenis, Motion",
              "Giao diện kiểm tra đa phương thức, ngăn Trợ lý VeriShield (phát luồng SSE + trình hiển thị Markdown thuần React an toàn), hiệu ứng cuộn và xuất hiện mượt, Trung tâm giám sát /radar và trang tài liệu; không dùng thư viện biểu đồ, đồ thị hay Markdown bên ngoài.",
            ],
            [
              "Máy chủ API",
              "Python 3.12, FastAPI, Pydantic v2, Uvicorn, HTTPX, python-multipart",
              "Cung cấp REST/SSE API, xác thực khóa phiên hồ sơ HMAC 128-bit và lớp ASGI middleware kiểm soát dung lượng, tần suất và bảo mật.",
            ],
            [
              "Học máy cục bộ & Phân tích tệp",
              "ONNX Runtime (CPU), HuggingFace Tokenizers, NumPy, RapidOCR v3 (PP-OCRv5 Latin), faster-whisper (INT8), OpenCV-headless, Pillow, PyAV, Playwright Chromium, fpdf2",
              "Phân loại 7 lớp E5 INT8, truy xuất RAG lai cục bộ (E5 + BM25 + RRF không cần LangChain/Vector DB), trích xuất OCR, chuyển giọng nói thành văn bản, phân tích ảnh/QR, trình duyệt cách ly và tạo báo cáo PDF tiếng Việt.",
            ],
            [
              "AI đa phương thức (Tùy chọn)",
              "Google GenAI SDK & bộ kết nối API tương thích OpenAI",
              "Suy luận ngữ cảnh Tầng 2, OCR dự phòng có giới hạn ngân sách và phát luồng phản hồi (kèm lọc <think>) cho Trợ lý VeriShield.",
            ],
            [
              "Lưu trữ & Hạ tầng",
              "SQLite 3 (WAL mode), Caddy 2.8, Docker & Docker Compose",
              "Lưu báo cáo đã che giấu, đồ thị dấu hiệu băm, quy tắc TTL và máy chủ trung gian (reverse proxy) xử lý mã hóa TLS/CSP.",
            ],
            [
              "Huấn luyện & Kiểm thử (ngoại tuyến)",
              "PyTorch, Transformers, scikit-learn, pytest, ruff, mypy --strict, node --test",
              "Chỉ dùng trong bước huấn luyện, xuất mô hình ONNX, thử nghiệm loại trừ thành phần (ablation) cho RAG và kiểm định tự động; tách rời khỏi môi trường vận hành.",
            ],
          ]}
        />
      </DocSection>

      {/* 14. Kiến trúc triển khai */}
      <DocSection id="kien-truc-trien-khai" number="14" title="Kiến trúc triển khai">
        <p>
          Hệ thống được đóng gói bằng Docker Compose thành 3 dịch vụ tối giản quyền hạn, phù hợp vận
          hành gọn nhẹ trên một máy chủ cấu hình phổ thông (4 GB RAM):
        </p>

        <DocTable
          caption="Cấu trúc 3 dịch vụ trong môi trường triển khai"
          headers={["Dịch vụ", "Ảnh Docker & Phân quyền", "Vai trò vận hành"]}
          rows={[
            [
              "Máy chủ trung gian (caddy)",
              "caddy:2.8-alpine (giảm đặc quyền tối đa, chỉ giữ quyền mở cổng mạng)",
              "Xử lý kết nối mã hóa HTTPS (TLS), chuyển hướng HTTP sang HTTPS, gắn tiêu đề HSTS/CSP, giới hạn dung lượng yêu cầu và truyền phát SSE không lưu đệm.",
            ],
            [
              "Giao diện Web (frontend)",
              "node:22-alpine (chạy dưới tài khoản không có quyền root, loại bỏ toàn bộ quyền hạn Linux mở rộng)",
              "Chạy bản đóng gói Next.js độc lập (standalone) nội bộ trong mạng Docker kèm kiểm tra sức khỏe định kỳ.",
            ],
            [
              "Máy chủ phân tích (backend)",
              "python:3.12-slim-bookworm (chạy dưới tài khoản không có quyền root, loại bỏ toàn bộ quyền hạn Linux mở rộng)",
              "Chạy FastAPI cùng các mô hình cục bộ (E5 INT8 ONNX, RapidOCR PP-OCRv5 và Whisper tiny) được đóng gói sẵn ngoại tuyến trong ảnh container, gắn ổ đĩa lưu trữ SQLite WAL.",
            ],
          ]}
        />
      </DocSection>

      {/* 15. Đánh giá hiệu năng và kết quả thực nghiệm */}
      <DocSection
        id="danh-gia-hieu-nang"
        number="15"
        title="Đánh giá hiệu năng và kết quả thực nghiệm"
      >
        <p>
          Toàn bộ số liệu dưới đây được trích xuất trực tiếp từ các tệp kết quả thực nghiệm lưu
          trong kho mã nguồn. Các chỉ số được thống nhất ký hiệu theo chuẩn đánh giá học máy và hệ
          thống: <strong>Precision</strong> (độ chính xác dương), <strong>Recall</strong> (độ phủ),{" "}
          <strong>F1-score</strong> / <strong>Macro-F1</strong>, <strong>Accuracy</strong> (độ chính
          xác tổng thể), <strong>R@k</strong> (Recall@k — độ phủ ở top-k kết quả truy xuất),{" "}
          <strong>MRR@5</strong> (thứ hạng nghịch đảo trung bình ở top 5), <strong>nDCG@3</strong> (chất
          lượng xếp hạng top 3 có tính trọng số vị trí), <strong>FRR</strong> (tỷ lệ từ chối nhầm
          câu hỏi hợp lệ trong phạm vi), <strong>Tỷ lệ từ chối ngoài phạm vi (OOD Reject)</strong>,{" "}
          <strong>CER</strong> (Character Error Rate — tỷ lệ lỗi ký tự),{" "}
          <strong>WER</strong> (Word Error Rate — tỷ lệ lỗi từ), <strong>P50 / P95</strong> (độ trễ
          trung vị và phân vị thứ 95) và <strong>Peak RSS</strong> (đỉnh bộ nhớ RAM tiến trình).
        </p>

        <DocCallout tone="info" title="Phạm vi dữ liệu và lưu ý diễn giải kết quả">
          <p>
            Toàn bộ bộ dữ liệu đánh giá hiện tại{" "}
            <strong>hoàn toàn sử dụng dữ liệu tổng hợp tiếng Việt</strong> (không chứa dữ liệu cá
            nhân thật). Kết quả chỉ phản ánh hiệu năng trên bộ dữ liệu kiểm thử nội bộ; kết quả
            40/40 ở phần 15.2 <strong>không thể suy rộng thành độ chính xác 100%</strong> trên lưu
            lượng giao dịch thực tế ngoài môi trường thử nghiệm.
          </p>
        </DocCallout>

        <h3 className="pt-2 text-sm font-semibold text-ink">
          15.1. Đánh giá mô hình E5-Small INT8 ONNX (tập kiểm thử tách nhóm mẫu câu, n = 364)
        </h3>
        <p className="text-xs text-ink-muted">
          Tập dữ liệu tổng hợp chia tách hoàn toàn theo nhóm mẫu câu giữa huấn luyện, đánh giá và
          kiểm thử (52 mẫu/lớp × 7 lớp). Kích thước mô hình lượng tử hóa:{" "}
          <strong className="text-ink">34,3 MB</strong>. So sánh trên tập kiểm thử: PyTorch FP32 đạt{" "}
          <strong className="text-ink">Macro-F1 = 0,9472</strong>; bản ONNX INT8 đạt{" "}
          <strong className="text-ink">Macro-F1 = 0,9314</strong> và{" "}
          <strong className="text-ink">Accuracy = 93,13%</strong> (Macro Precision = 0,9423; Macro
          Recall = 0,9313).
        </p>
        <DocTable
          caption="Kết quả phân loại chi tiết theo 7 lớp của mô hình E5-Small INT8 ONNX trên tập kiểm thử tổng hợp (n = 364)"
          headers={["Lớp phân loại", "Precision", "Recall", "F1-score", "Số mẫu"]}
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
          15.2. Đánh giá toàn bộ quy trình (End-to-End) trên 40 tình huống tổng hợp tiếng Việt
        </h3>
        <p className="text-xs text-ink-muted">
          Bộ dữ liệu kiểm thử gồm 40 tình huống tổng hợp (28 tình huống lừa đảo/tấn công và 12 tình
          huống bình thường/khuyến cáo an toàn), chạy đầy đủ quy trình với E5 ONNX cục bộ và Google
          Gemini API hoặc cổng API tương thích OpenAI (40/40 phản hồi thành công).
        </p>
        <DocTable
          caption="Kết quả đánh giá toàn bộ quy trình trên 40 tình huống tổng hợp tiếng Việt"
          headers={["Chỉ số đánh giá", "Kết quả đo lường", "Chi tiết quan sát trên bộ mẫu"]}
          rows={[
            [
              "Precision / Recall / F1-score / Accuracy (nhị phân)",
              "1,000 / 1,000 / 1,000 / 100%",
              "Phân loại đúng 40/40 tình huống tổng hợp (TP = 28, TN = 12, FP = 0, FN = 0); chỉ có giá trị trong phạm vi bộ mẫu thử nghiệm.",
            ],
            [
              "Tỷ lệ cảnh báo nhầm trên tin khuyến cáo (Advisory FPR)",
              "0,0%",
              "5/5 tin khuyến cáo an toàn được phân loại mức rủi ro thấp (1–5/100).",
            ],
            [
              "Nhóm tấn công chèn chỉ thị (Prompt Injection)",
              "3/3 tình huống",
              "Cả 3 tình huống đều kích hoạt cờ phát hiện tĩnh và đạt mức cảnh báo rủi ro cao.",
            ],
            [
              "Nhóm biên lai giả và bẫy VietQR",
              "4/4 biên lai · 3/3 VietQR",
              "Đều kích hoạt bằng chứng kỹ thuật Tầng 1 và giữ nguyên cảnh báo xác minh số dư.",
            ],
            [
              "Độ trễ E5-Small INT8 ONNX (CPU)",
              "P50 = 10 ms · P95 = 13 ms",
              "Đo trực tiếp trên từng lượt suy luận trong quy trình phân tích.",
            ],
            [
              "Độ trễ toàn bộ quy trình (End-to-End, có gọi AI)",
              "P50 = 7.176 ms · P95 = 10.077 ms",
              "Phần lớn thời gian thuộc độ trễ mạng của dịch vụ AI (P50 = 7.119 ms; P95 = 9.878 ms).",
            ],
          ]}
        />

        <h3 className="pt-2 text-sm font-semibold text-ink">
          15.3. Thực nghiệm so sánh công cụ OCR tiếng Việt (n = 25 ảnh tổng hợp, đo cô lập tiến trình)
        </h3>
        <p className="text-xs text-ink-muted">
          Đo trên 25 ảnh tổng hợp gồm 5 nhóm (tin nhắn, biên lai ngân hàng, mã VietQR, giao diện tối
          và ảnh chất lượng thấp), chạy từng công cụ trong tiến trình riêng trên Windows 11 (Python
          3.13.5, 16 luồng CPU). <strong>CER gốc</strong> là tỷ lệ lỗi ký tự tính trên văn bản tiếng
          Việt đầy đủ dấu (bao gồm sai dấu, sai ký tự, thiếu/thừa ký tự và khoảng trắng);{" "}
          <strong>CER bỏ dấu</strong> là tỷ lệ lỗi ký tự sau khi chuẩn hóa bỏ dấu tiếng Việt.
        </p>
        <DocTable
          caption="So sánh thực nghiệm các công cụ OCR tiếng Việt trên 25 ảnh tổng hợp"
          headers={[
            "Công cụ OCR",
            "Giấy phép",
            "CER gốc ↓",
            "CER bỏ dấu ↓",
            "WER ↓",
            "Entity F1-score ↑",
            "P50 / P95",
            "Peak RSS",
            "Kết luận",
          ]}
          rows={[
            [
              "RapidOCR v4 CH (phiên bản cũ)",
              "Apache-2.0",
              "0,2243",
              "0,1054",
              "0,9222",
              "0,7158",
              "1.341,7 / 1.688,8 ms",
              "339,2 MB",
              "Đã thay thế",
            ],
            [
              "RapidOCR v3 PP-OCRv5 Latin (tắt xoay dòng)",
              "Apache-2.0",
              "0,1096",
              "0,0294 (biên lai: 0,0112)",
              "0,4994",
              "0,8041",
              "733,5 / 1.032,1 ms",
              "336,2 MB",
              "Chọn làm công cụ chính (12,14 MB)",
            ],
            [
              "RapidOCR v3 PP-OCRv5 Latin (bật xoay dòng)",
              "Apache-2.0",
              "0,1933",
              "0,1251",
              "0,5162",
              "0,7912",
              "749,2 / 1.069,0 ms",
              "340,5 MB",
              "Loại (lật nhầm dòng ngắn)",
            ],
            [
              "MinerU v4.2.3 Basic ONNX",
              "LicenseRef-MinerU-Open-Source-License (Apache-2.0 + điều khoản thương mại có điều kiện)",
              "0,0906",
              "0,0554",
              "0,4465",
              "0,9400",
              "1.209,8 / 1.312,2 ms",
              "948,4 MB",
              "Không dùng ở vận hành (2,77 GB đĩa)",
            ],
            [
              "Gemini Multimodal OCR",
              "API thương mại",
              "0,0000",
              "0,0000",
              "0,0000",
              "1,0000",
              "5.182,0 / 12.350,0 ms",
              "112,2 MB (máy gọi API)",
              "Dự phòng có điều kiện",
            ],
          ]}
        />

        <h3 className="pt-2 text-sm font-semibold text-ink">
          15.4. Thực nghiệm đánh giá tầng truy xuất RAG của Trợ lý VeriShield (7 cấu hình đối chứng)
        </h3>
        <p className="text-xs text-ink-muted">
          Đánh giá trên bộ dữ liệu{" "}
          <strong className="text-ink">100% tổng hợp gồm 159 câu hỏi tiếng Việt</strong> đối chiếu
          trên kho tri thức <strong className="text-ink">121 đoạn chuẩn hóa</strong> (20 SOP ứng
          phó sự cố + 20 hướng dẫn xác minh + 81 mục từ kho tri thức lừa đảo Việt Nam; tối đa 140
          token; tỷ lệ <code className="font-mono text-ink-secondary">&lt;unk&gt; = 0,0488%</code>),
          tách bạch hoàn toàn giữa <strong className="text-ink">tập phát triển Dev (62 ca:</strong>{" "}
          39 trong phạm vi + 23 ngoài phạm vi, chỉ dùng hiệu chuẩn cổng phạm vi) và{" "}
          <strong className="text-ink">tập kiểm thử độc lập Held-out Test (97 ca:</strong> 64
          trong phạm vi + 33 ngoài phạm vi), độ trùng lặp từ vựng tối đa giữa hai tập{" "}
          <strong className="text-ink">max Jaccard = 0,4615</strong> (&lt; 0,55). Độ trễ mã hóa
          câu hỏi trên phiên E5-Small INT8 ONNX CPU dùng chung đạt{" "}
          <strong className="text-ink">P50 = 4,85 ms</strong>,{" "}
          <strong className="text-ink">P95 = 6,77 ms</strong> (trung bình 4,79 ms).
        </p>
        <DocTable
          caption="Kết quả thử nghiệm loại trừ thành phần (7 cấu hình) của tầng truy xuất RAG trên tập Held-out Test tổng hợp (n = 97)"
          headers={[
            "Cấu hình (Baseline)",
            "R@1 ↑",
            "R@3 ↑",
            "MRR@5 ↑",
            "nDCG@3 ↑",
            "SOP R@3 ↑",
            "R@3 không dấu ↑",
            "Gated R@3 ↑",
            "Từ chối nhầm (FRR) ↓",
            "Chặn ngoài miền ↑",
            "Trễ truy xuất (TB / P95)",
          ]}
          rows={[
            [
              "B0 · BM25 (không gắn hồ sơ)",
              "92,2%",
              "96,9%",
              "0,9401",
              "0,8444",
              "94,1%",
              "100,0%",
              "90,6%",
              "7,8%",
              "100,0%",
              "0,47 / 0,64 ms",
            ],
            [
              "B1 · Raw E5 Cosine (không gắn hồ sơ)",
              "73,4%",
              "84,4%",
              "0,7987",
              "0,6571",
              "82,4%",
              "40,0%",
              "84,4%",
              "3,1%",
              "36,4%",
              "0,46 / 0,66 ms",
            ],
            [
              "B2 · Centered E5 Cosine (không gắn hồ sơ)",
              "70,3%",
              "89,1%",
              "0,7956",
              "0,6892",
              "91,2%",
              "60,0%",
              "68,8%",
              "31,2%",
              "100,0%",
              "0,51 / 0,75 ms",
            ],
            [
              "B3 · BM25 + Raw E5 RRF (không gắn hồ sơ)",
              "84,4%",
              "95,3%",
              "0,9076",
              "0,7736",
              "94,1%",
              "93,3%",
              "92,2%",
              "3,1%",
              "36,4%",
              "0,51 / 0,75 ms",
            ],
            [
              "B4 · BM25 + Centered E5 RRF (không gắn hồ sơ)",
              "87,5%",
              "96,9%",
              "0,9232",
              "0,8134",
              "94,1%",
              "100,0%",
              "67,2%",
              "31,2%",
              "100,0%",
              "0,51 / 0,74 ms",
            ],
            [
              "B5 · B4 + Dual-Signal Gate (không gắn hồ sơ)",
              "87,5%",
              "96,9%",
              "0,9232",
              "0,8134",
              "94,1%",
              "100,0%",
              "95,3%",
              "1,6%",
              "100,0%",
              "0,52 / 0,81 ms",
            ],
            [
              "B6 · B5 + Case Hint Boost (gắn hồ sơ)",
              "87,5%",
              "98,4%",
              "0,9271",
              "0,8486",
              "97,1%",
              "100,0%",
              "96,9%",
              "1,6%",
              "100,0%",
              "0,51 / 0,68 ms",
            ],
          ]}
        />
        <ul className="list-disc space-y-1.5 pl-5 text-xs text-ink-muted">
          <li>
            <strong className="text-ink-secondary">Hạn chế của E5 thô và E5 cân bằng không gian đơn lẻ:</strong>{" "}
            <strong className="text-ink">Raw E5 Cosine (B1)</strong> chịu hiện tượng các vector bị
            dồn cụm về cùng một hướng (anisotropy) nên tỷ lệ từ chối đúng câu hỏi ngoài phạm vi chỉ
            đạt <strong className="text-ink">36,4%</strong> và độ phủ câu hỏi tiếng Việt không dấu
            tụt xuống <strong className="text-ink">40,0%</strong>. Khi áp dụng Mean-Centering đơn lẻ
            (<strong className="text-ink">B2</strong>) hoặc chưa có cổng hai tín hiệu (
            <strong className="text-ink">B4</strong>), tỷ lệ chặn câu hỏi ngoài miền đạt 100,0%
            nhưng tỷ lệ từ chối nhầm câu hỏi hợp lệ tăng vọt lên{" "}
            <strong className="text-ink">31,2%</strong>, kéo{" "}
            <code className="font-mono text-ink-secondary">Gated R@3</code> xuống 68,8% / 67,2%.
          </li>
          <li>
            <strong className="text-ink-secondary">Lợi ích thực nghiệm của cấu hình B5 và B6:</strong>{" "}
            Kết hợp BM25 không dấu + Centered E5 RRF + Dual-Signal Scope Gate (
            <strong className="text-ink">B5</strong>) giảm mạnh tỷ lệ từ chối nhầm xuống{" "}
            <strong className="text-ink">1,6%</strong> (so với 7,8% ở BM25 đơn lẻ B0 và 31,2% ở
            B2/B4), đồng thời giữ <strong className="text-ink">100,0%</strong> chặn câu hỏi ngoài
            miền, <strong className="text-ink">100,0%</strong> R@3 không dấu và nâng Gated R@3 lên{" "}
            <strong className="text-ink">95,3%</strong>. Khi gắn ngữ cảnh hồ sơ đang xem (
            <strong className="text-ink">B6</strong>), hệ thống đạt{" "}
            <strong className="text-ink">R@3 = 98,4%</strong>,{" "}
            <strong className="text-ink">nDCG@3 = 0,8486</strong>,{" "}
            <strong className="text-ink">SOP R@3 = 97,1%</strong> và{" "}
            <strong className="text-ink">Gated R@3 = 96,9%</strong> với độ trễ truy xuất thuần chỉ{" "}
            <strong className="text-ink">0,51–0,52 ms</strong> (P95{" "}
            <strong className="text-ink">0,68–0,81 ms</strong>).
          </li>
        </ul>

        <p className="text-xs text-ink-muted">
          <strong className="text-ink-secondary">Nội dung chưa đo lường:</strong> Chưa thực hiện thử
          nghiệm chịu tải đồng thời kéo dài trên môi trường sản xuất và chưa đánh giá trên tập dữ
          liệu giao dịch tài chính thực tế.
        </p>
      </DocSection>

      {/* 16. Các biện pháp bảo mật */}
      <DocSection id="bien-phap-bao-mat" number="16" title="Các biện pháp bảo mật">
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">
              Kiểm soát truy cập hồ sơ thống nhất và tách biệt kênh Telegram:
            </strong>{" "}
            Mỗi hồ sơ phân tích trên web được cấp khóa phiên truy cập ký HMAC 128-bit (tự động hết
            hạn sau 2 giờ, phản hồi luôn tắt lưu bộ nhớ đệm) để bảo vệ đồng bộ đường đọc hồ sơ, tải
            báo cáo PDF và trò chuyện với Trợ lý VeriShield; kênh Telegram chỉ gửi PDF trực tiếp
            trong khung chat riêng 1-1 tới đúng chủ phiên, không cấp liên kết PDF công khai và khóa
            mặc định các hồ sơ cũ.
          </li>
          <li>
            <strong className="font-semibold text-ink">Kiểm soát tệp tải lên và chống cạn kiệt tài nguyên:</strong>{" "}
            Giới hạn dung lượng nội dung yêu cầu theo luồng (streaming), từ chối tệp vượt ngưỡng (
            <code className="font-mono text-ink">HTTP 413</code>) hoặc tệp giả định dạng/hỏng (
            <code className="font-mono text-ink">HTTP 400</code>), kết hợp giới hạn giải nén ảnh và
            giải mã âm thanh.
          </li>
          <li>
            <strong className="font-semibold text-ink">Phòng chống SSRF đa lớp:</strong> Chặn toàn bộ
            dải địa chỉ không công khai (loopback, mạng nội bộ RFC1918, CGNAT, link-local/metadata
            đám mây, multicast, địa chỉ IPv4 ánh xạ IPv6 và các biến thể mã hóa IP) từ URL ban đầu,
            từng bước chuyển hướng cho tới mọi yêu cầu phụ trong trình duyệt cách ly (và công cụ
            kiểm tra URL không chạy trình duyệt ảo của Trợ lý), kèm ràng buộc kết nối vào IP công
            cộng đã kiểm tra.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Phòng vệ tấn công chèn chỉ thị (Prompt Injection), chốt lọc đầu ra và kiểm duyệt 3 tầng:
            </strong>{" "}
            Cách ly văn bản người dùng, văn bản trích xuất từ ảnh và lịch sử trò chuyện đã hạ quyền
            khỏi chỉ dẫn hệ thống; áp dụng <code className="font-mono text-ink">RequestEntityVault</code>{" "}
            và chốt lọc đầu ra thống nhất để chặn PII/URL/VietQR thô rời backend trong Trợ lý; lọc
            luồng <code className="font-mono text-ink">&lt;think&gt;</code> và hậu kiểm đầu ra 3
            tầng trước khi phát luồng; hiển thị câu trả lời trên giao diện bằng trình phân tích
            Markdown thuần React không chèn HTML trực tiếp để chống XSS.
          </li>
          <li>
            <strong className="font-semibold text-ink">Bảo vệ thao tác quản trị và giảm thiểu PII:</strong>{" "}
            So sánh khóa xác thực theo thời gian hằng chống tấn công dò thời gian (timing attack),
            áp dụng giới hạn tần suất chặt hơn cho thao tác ghi quy tắc, cô lập hoàn toàn công cụ
            chỉ đọc của Trợ lý khỏi thao tác quản trị <code className="font-mono text-ink">/radar</code>,
            chặn sử dụng khóa yếu/mặc định ở môi trường vận hành, băm HMAC-SHA256 cho dấu hiệu trên
            đồ thị và ghi nhật ký kiểm toán không chứa dữ liệu thô.
          </li>
          <li>
            <strong className="font-semibold text-ink">Cô lập hạ tầng và tiêu đề bảo mật HTTP:</strong>{" "}
            Thực thi container bằng tài khoản không có quyền root, gỡ bỏ các Linux capabilities không
            cần thiết, bật HSTS, CSP và kiểm định định kỳ bằng các bộ kiểm thử tự động về bảo mật.
          </li>
        </ul>
      </DocSection>

      {/* 17. Giới hạn của hệ thống */}
      <DocSection id="gioi-han-he-thong" number="17" title="Giới hạn của hệ thống">
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Không thay thế xác minh dòng tiền ngân hàng:</strong>{" "}
            Mọi kết quả và câu trả lời từ Trợ lý VeriShield chỉ mang tính hỗ trợ tham khảo; phân tích
            ảnh biên lai không thể chứng minh tiền đã ghi có vào tài khoản và hệ thống không có quyền
            can thiệp trực tiếp vào giao dịch ngân hàng hay ví điện tử.
          </li>
          <li>
            <strong className="font-semibold text-ink">Phạm vi dữ liệu huấn luyện tổng hợp:</strong>{" "}
            Mô hình E5 INT8, kho tri thức Trợ lý và các bộ dữ liệu kiểm thử (bao gồm thử nghiệm loại
            trừ thành phần cho RAG 159 ca) đều xây dựng từ dữ liệu tổng hợp và thông báo khuyến cáo
            công khai; các kịch bản lừa đảo biến thể mới vẫn cần cập nhật định kỳ.
          </li>
          <li>
            <strong className="font-semibold text-ink">Giới hạn OCR và nhận diện giọng nói cục bộ:</strong>{" "}
            Trên bộ 25 ảnh tổng hợp, mô hình{" "}
            <code className="font-mono text-ink">latin_PP-OCRv5_rec_mobile</code> đạt CER gốc 0,1096
            và CER sau khi bỏ dấu 0,0294 (cho thấy phần đáng kể lỗi ký tự rơi vào dấu tiếng Việt
            trên chữ nhỏ hoặc ảnh nén mờ, trong khi ký tự chữ/số cơ bản chính xác cao hơn nhiều). Do
            tắt bước xoay dòng để tránh lật nhầm chữ ngắn, ảnh xoay ngược 180 độ phụ thuộc vào OCR
            dự phòng hoặc thị giác Tầng 2. Mô hình{" "}
            <code className="font-mono text-ink">faster-whisper tiny</code> ưu tiên tiết kiệm RAM
            nên độ chính xác giảm trên bản ghi nhiều tạp âm.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Giới hạn mở rộng, phiên truy cập không đăng nhập và quản lý vòng đời dữ liệu:
            </strong>{" "}
            Bộ giới hạn tần suất lưu trên bộ nhớ cục bộ phù hợp mô hình đơn tiến trình (cần kho dùng
            chung như Redis khi mở rộng nhiều worker); trang{" "}
            <code className="font-mono text-ink">/radar</code> chưa tích hợp SSO/RBAC doanh nghiệp;
            hồ sơ đã có khóa phiên truy cập riêng (tự hết hạn sau 2 giờ, không cần tài khoản đăng
            nhập dài hạn), nhưng hệ thống chưa có lịch tự động xóa định kỳ cho hồ sơ đã lưu và chưa
            có chức năng để người dùng tự xóa dữ liệu trên máy chủ.
          </li>
        </ul>
      </DocSection>

      {/* 18. Thư viện và giấy phép sử dụng */}
      <DocSection id="thu-vien-giay-phep" number="18" title="Thư viện và giấy phép sử dụng">
        <p>
          VeriShield AI chỉ đưa vào môi trường vận hành các thư viện và mô hình mã nguồn mở sử dụng
          giấy phép nguồn mở tự do (permissive) hoặc LGPL-3.0. Phân hệ Trợ lý VeriShield tái sử
          dụng hoàn toàn ngăn xếp phần mềm sẵn có mà không bổ sung framework RAG, cơ sở dữ liệu
          vector hay thư viện dựng Markdown bên ngoài. Các thành phần có điều khoản hạn chế nghiên
          cứu (như <code className="font-mono text-ink">uitnlp/visobert</code>), giấy phép copyleft
          ràng buộc mạnh (<code className="font-mono text-ink">vinai/phobert*</code> — AGPL-3.0)
          hoặc giấy phép bổ sung điều kiện thương mại/hiển thị bắt buộc (như{" "}
          <code className="font-mono text-ink">MinerU</code> theo{" "}
          <code className="font-mono text-ink">LicenseRef-MinerU-Open-Source-License</code> — cho
          phép sử dụng thương mại có điều kiện kèm giới hạn quy mô và yêu cầu ghi nhận thương hiệu
          bắt buộc) không được đóng gói trong môi trường chạy thật.
        </p>

        <DocTable
          caption="Danh mục dự án, mô hình AI, thư viện và giấy phép sử dụng đã đối chiếu"
          headers={["Nhóm", "Thành phần", "Giấy phép", "Ghi chú bản quyền & đối chiếu"]}
          rows={[
            [
              "Dự án",
              "VeriShield AI",
              "MIT",
              "Copyright (c) 2026 Trần Chí Vỹ (xem tệp LICENSE tại thư mục gốc kho mã nguồn).",
            ],
            [
              "Mô hình AI cục bộ",
              "intfloat/multilingual-e5-small · faster-whisper (v1.2.1) / CTranslate2 (v4.9.1) / OpenAI Whisper",
              "MIT",
              "Mô hình nền phân loại ngữ nghĩa tiếng Việt 384 chiều và công cụ chuyển giọng nói thành văn bản INT8.",
            ],
            [
              "Mô hình & Công cụ OCR",
              "RapidOCR v3 (v3.10.0) · PaddleOCR PP-OCRv5 (ch_PP-OCRv5_det_mobile & latin_PP-OCRv5_rec_mobile)",
              "Apache-2.0",
              "Xác minh từ thông tin gói cài đặt và kho nguồn chính thức của RapidOCR / PaddleOCR.",
            ],
            [
              "AI bên thứ ba (tùy chọn)",
              "Google Gemini API (thư viện google-genai SDK: Apache-2.0)",
              "API thương mại / Apache-2.0 (SDK)",
              "Tầng suy luận tùy chọn; hệ thống vẫn vận hành bằng Tầng 1 cục bộ khi không cấu hình.",
            ],
            [
              "Thư viện Backend",
              "FastAPI, Pydantic, pydantic-settings, ONNX Runtime (MIT) · Uvicorn, HTTPX, idna (BSD-3-Clause) · PyAV (BSD-3-Clause; thư viện FFmpeg đi kèm theo LGPL-3.0-or-later) · NumPy (BSD-3-Clause cùng thành phần 0BSD/MIT/Zlib/CC0-1.0) · Pillow (MIT-CMU) · Tokenizers, OpenCV-headless, Playwright, python-multipart (Apache-2.0) · fpdf2 (LGPL-3.0-only)",
              "MIT / BSD-3-Clause / MIT-CMU / Apache-2.0 / LGPL-3.0",
              "Đối chiếu trực tiếp từ thông tin gói cài đặt thực tế trong môi trường vận hành.",
            ],
            [
              "Thư viện Frontend",
              "Next.js 15, React 19, Tailwind CSS v4, Lenis (cuộn mượt), Motion (hiệu ứng xuất hiện) (MIT) · TypeScript 5.8 (Apache-2.0) · Lucide React (ISC)",
              "MIT / Apache-2.0 / ISC",
              "Đối chiếu từ khai báo phụ thuộc của ứng dụng web. Các hiệu ứng nhỏ (bộ đếm số, quầng sáng thẻ, vẽ luồng sơ đồ) do nhóm tự viết, không sao chép mã nguồn bên thứ ba.",
            ],
            [
              "Phông chữ",
              "DejaVuSans.ttf (báo cáo PDF) · Inter & JetBrains Mono (giao diện web)",
              "Bitstream Vera / SIL OFL-1.1",
              "DejaVuSans: Fonts (c) 2003 Bitstream, Inc.; Arev glyphs (c) 2006 Tavmjong Bah; phần chỉnh sửa DejaVu thuộc Public Domain. Inter và JetBrains Mono đóng gói sẵn qua next/font.",
            ],
            [
              "Cơ sở dữ liệu & Máy chủ trung gian",
              "SQLite 3 (Public Domain) · Caddy 2 (Apache-2.0)",
              "Public Domain / Apache-2.0",
              "Lưu trữ SQLite WAL và máy chủ trung gian (reverse proxy) xử lý kết nối HTTPS (TLS).",
            ],
          ]}
        />

        <p className="pt-2 text-xs text-ink-muted">
          Xem cách dữ liệu của bạn được tiếp nhận, che giấu và lưu trữ tại trang{" "}
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
