import type { Metadata } from "next";
import Link from "next/link";

import { DataLifecycleSvg } from "@/components/docs/DataLifecycleSvg";
import {
  DocCallout,
  DocSection,
  DocsShell,
  DocTable,
} from "@/components/docs/DocsShell";
import type { TocItem } from "@/components/docs/DocsToc";

export const metadata: Metadata = {
  title: "Chính sách quyền riêng tư — VeriShield AI",
  description: "Tìm hiểu cách VeriShield thu thập, xử lý và bảo vệ thông tin của bạn.",
};

const PRIVACY_TOC: readonly TocItem[] = [
  { id: "tong-quan", number: "01", label: "Tổng quan và phạm vi áp dụng" },
  { id: "loai-du-lieu", number: "02", label: "Các loại dữ liệu được thu thập" },
  { id: "muc-dich-xu-ly", number: "03", label: "Mục đích xử lý dữ liệu" },
  { id: "quy-trinh-xu-ly", number: "04", label: "Quy trình tiếp nhận và xử lý" },
  { id: "bao-ve-pii", number: "05", label: "Biện pháp bảo vệ thông tin cá nhân" },
  { id: "ben-thu-ba", number: "06", label: "Dịch vụ bên thứ ba và chuyển dữ liệu" },
  { id: "luu-tru-xoa", number: "07", label: "Chính sách lưu trữ và xóa dữ liệu" },
  { id: "cookies-truy-cap", number: "08", label: "Cookies và dữ liệu truy cập" },
  { id: "quyen-nguoi-dung", number: "09", label: "Quyền của người dùng" },
  { id: "lien-he", number: "10", label: "Thông tin liên hệ" },
  { id: "thay-doi", number: "11", label: "Thay đổi chính sách" },
];

export default function PrivacyPage() {
  return (
    <DocsShell
      breadcrumbLabel="Quyền riêng tư"
      title="Chính sách quyền riêng tư"
      description="Tìm hiểu cách VeriShield thu thập, xử lý và bảo vệ thông tin của bạn."
      metaItems={[
        { label: "Phạm vi", value: "Ứng dụng Web, API phân tích, Telegram Bot và trang Giám sát gian lận" },
        { label: "Cơ sở tài liệu", value: "Đối chiếu trực tiếp từ mã nguồn hệ thống" },
        { label: "Trạng thái công bố", value: "Tài liệu kỹ thuật minh bạch — một số mục quản trị cần chủ dự án hoàn thiện" },
      ]}
      tocItems={PRIVACY_TOC}
    >
      <DocCallout tone="warning" title="Lưu ý về phạm vi tài liệu và các mục đang chờ xác nhận quản trị">
        <p>
          Tài liệu này mô tả chính xác cách mã nguồn VeriShield AI hiện tại tiếp nhận, xử lý, che
          giấu và lưu trữ dữ liệu. Tài liệu không khẳng định hệ thống đã hoàn tất quy trình chứng
          nhận bảo mật hoặc tuân thủ pháp lý chính thức.
        </p>
        <p>
          Các mục về <strong>đơn vị chịu trách nhiệm dữ liệu</strong>,{" "}
          <strong>thời hạn lưu trữ cố định cho hồ sơ kiểm tra</strong>,{" "}
          <strong>quy trình tiếp nhận yêu cầu xóa dữ liệu</strong> và{" "}
          <strong>địa chỉ liên hệ chính thức</strong> hiện chưa được ấn định trong mã nguồn và cần
          chủ dự án xác nhận trước khi phát hành chính sách pháp lý chính thức.
        </p>
      </DocCallout>

      {/* 1. Tổng quan và phạm vi áp dụng */}
      <DocSection id="tong-quan" number="01" title="Tổng quan và phạm vi áp dụng">
        <p>
          Chính sách này áp dụng khi bạn sử dụng các kênh tương tác của{" "}
          <strong className="font-semibold text-ink">VeriShield AI</strong>, bao gồm: giao diện web
          kiểm tra dấu hiệu lừa đảo tại <code className="font-mono text-ink">/</code>, không gian
          giám sát và mô phỏng quy tắc tại <code className="font-mono text-ink">/radar</code>, các
          điểm cuối API phục vụ phân tích/báo cáo PDF và kênh Telegram Bot (nếu được cấu hình trong
          môi trường triển khai).
        </p>
        <p>
          VeriShield AI là công cụ hỗ trợ đánh giá rủi ro dấu hiệu lừa đảo tài chính trực tuyến; hệ
          thống không yêu cầu tạo tài khoản người dùng phổ thông và không kết nối trực tiếp vào tài
          khoản ngân hàng hay ví điện tử của bạn. Tuy nhiên, nội dung bạn chủ động gửi lên để kiểm
          tra có thể chứa thông tin định danh cá nhân (như số điện thoại, số tài khoản, họ tên hoặc
          ảnh chụp màn hình giao dịch), vì vậy bạn nên cân nhắc che bớt các dữ liệu nhạy cảm không
          cần thiết trước khi tải lên.
        </p>
      </DocSection>

      {/* 2. Các loại dữ liệu được thu thập */}
      <DocSection id="loai-du-lieu" number="02" title="Các loại dữ liệu được thu thập">
        <p>
          Hệ thống chỉ xử lý dữ liệu do bạn chủ động cung cấp cho phiên kiểm tra và dữ liệu kỹ
          thuật tối thiểu để bảo vệ dịch vụ khỏi lạm dụng:
        </p>

        <DocTable
          caption="Phân loại dữ liệu đầu vào và dữ liệu kỹ thuật trong VeriShield AI"
          headers={["Nhóm dữ liệu", "Thành phần cụ thể", "Trạng thái lưu vào cơ sở dữ liệu"]}
          rows={[
            [
              "Nội dung văn bản và đường dẫn",
              "Tin nhắn, mô tả tình huống, đường dẫn trang web, ngữ cảnh tùy chọn (số tiền dự kiến chuyển, số tài khoản đối chiếu của cửa hàng, trạng thái đang nghe điện thoại).",
              "Không lưu nguyên bản đầu vào thô thành bảng riêng; kết quả phân tích (tóm tắt, bằng chứng, trích đoạn, đường dẫn) được lưu trong bảng cases sau khi chạy bộ che giấu SĐT/STK.",
            ],
            [
              "Hình ảnh tải lên",
              "Tối đa 4 ảnh mỗi lượt (JPG, PNG, WebP, GIF; ≤ 10 MB/tệp, tổng tệp đính kèm ≤ 20 MB), bao gồm ảnh chụp tin nhắn, biên lai chuyển khoản hoặc mã VietQR.",
              "Không lưu tệp ảnh gốc, bản đồ nhiệt ELA hay ảnh chụp sandbox trong cơ sở dữ liệu. Tên tệp gốc được đổi thành tên chung (evidence.<định dạng>). Văn bản OCR đã che SĐT/STK và mã băm ảnh dHash (nếu là biên lai) được lưu.",
            ],
            [
              "Tệp ghi âm cuộc gọi",
              "Tối đa 2 tệp âm thanh mỗi lượt (WAV, MP3, M4A, OGG, WebM; ≤ 10 MB/tệp).",
              "Không lưu tệp âm thanh gốc trong cơ sở dữ liệu. Tệp tạm cục bộ dùng cho bước gỡ băng tiếng Việt được xóa ngay sau khi xử lý. Lời thoại trích xuất được che SĐT/STK trước khi lưu trong hồ sơ.",
            ],
            [
              "Dữ liệu qua Telegram Bot (nếu bật)",
              "Nội dung tin nhắn văn bản, ảnh, tệp ghi âm chuyển tiếp tới bot và mã cập nhật webhook (update_id).",
              "Lưu mã update_id, mã hồ sơ liên kết và nội dung phản hồi đã che giấu trong bảng telegram_updates nhằm tránh xử lý trùng lặp khi Telegram gửi lại webhook.",
            ],
            [
              "Dữ liệu vận hành & bảo mật",
              "Địa chỉ IP kết nối (dùng cho giới hạn tần suất trên RAM), lịch sử thao tác quản trị trên /radar (tạo/thu hồi/đặt lại quy tắc chặn hoặc xác thực thất bại).",
              "Bộ giới hạn tần suất lưu tạm trên RAM (tối đa 4.096 địa chỉ IP gần nhất, tự hết hạn theo cửa sổ 60 giây). Nhật ký kiểm toán radar_audit_logs chỉ lưu mã băm rút gọn 16 ký tự của IP, không lưu IP thô.",
            ],
          ]}
        />
      </DocSection>

      {/* 3. Mục đích xử lý dữ liệu */}
      <DocSection id="muc-dich-xu-ly" number="03" title="Mục đích xử lý dữ liệu">
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Đánh giá rủi ro lừa đảo theo yêu cầu:</strong>{" "}
            Trích xuất văn bản từ hình ảnh (OCR), gỡ băng cuộc gọi (STT), giải mã mã VietQR, kiểm
            tra dấu hiệu chỉnh sửa biên lai, đánh giá đường dẫn đáng ngờ và tổng hợp mức rủi ro kèm
            khuyến nghị ứng phó.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Phát hiện biên lai dùng lại và chuỗi chiến dịch gian lận:
            </strong>{" "}
            Đối chiếu mã băm cảm nhận (<code className="font-mono text-ink">dHash</code>) và mã tham
            chiếu giao dịch trên biên lai; tổng hợp tần suất xuất hiện và liên kết giữa các dấu hiệu
            rủi ro cao (điểm rủi ro ≥ 45) dưới dạng mã băm một chiều và nhãn đã che giấu trên{" "}
            <Link href="/radar" className="text-sky-300 underline decoration-sky-500/40 underline-offset-2 hover:text-sky-200">
              trang Giám sát gian lận
            </Link>
            .
          </li>
          <li>
            <strong className="font-semibold text-ink">Hỗ trợ tải báo cáo bằng chứng PDF:</strong>{" "}
            Truy xuất lại hồ sơ đã che giấu SĐT/STK theo mã hồ sơ (<code className="font-mono text-ink">case_id</code>)
            để tạo báo cáo PDF tiếng Việt phục vụ người dùng lưu trữ hoặc trình báo cơ quan chức năng.
          </li>
          <li>
            <strong className="font-semibold text-ink">Bảo vệ an toàn hạ tầng và kiểm toán quản trị:</strong>{" "}
            Chống gửi yêu cầu quá tải (rate limiting), phát hiện tấn công tiêm lệnh AI (prompt
            injection), chặn truy cập trái phép vào mạng nội bộ (SSRF) và ghi nhật ký kiểm toán các
            thao tác quản lý quy tắc chặn.
          </li>
        </ul>
      </DocSection>

      {/* 4. Quy trình tiếp nhận và xử lý */}
      <DocSection id="quy-trinh-xu-ly" number="04" title="Quy trình tiếp nhận và xử lý">
        <p>
          Khi bạn gửi nội dung kiểm tra, dữ liệu đi qua chuỗi xử lý phân tầng theo thời gian thực.
          Sơ đồ dưới đây phản ánh đúng luồng xử lý, điểm chạm ngoài biên và điểm che giấu dữ liệu
          trong mã nguồn hiện hành:
        </p>

        <DataLifecycleSvg />

        <div className="space-y-2.5 pt-1">
          <h3 className="text-sm font-semibold text-ink">Chi tiết các điểm xử lý quan trọng</h3>
          <ul className="list-disc space-y-2 pl-5">
            <li>
              <strong className="font-semibold text-ink">Xử lý hình ảnh trên bộ nhớ (RAM):</strong>{" "}
              Bước xác thực kích thước/định dạng, phân tích ELA/EXIF/dHash, giải mã QR và OCR cục bộ
              (<code className="font-mono text-ink">RapidOCR</code>) đều giải mã trực tiếp từ bộ đệm
              byte trong RAM và không ghi ảnh người dùng xuống đĩa.
            </li>
            <li>
              <strong className="font-semibold text-ink">Tệp tạm cho tệp ghi âm:</strong> Khi bước
              gỡ băng nội bộ (<code className="font-mono text-ink">faster-whisper</code>) hoạt động,
              dữ liệu âm thanh được ghi ra một tệp tạm của hệ điều hành để bộ giải mã đọc, sau đó
              được xóa ngay trong khối <code className="font-mono text-ink">finally</code> bất kể
              quá trình gỡ băng thành công hay lỗi.
            </li>
            <li>
              <strong className="font-semibold text-ink">Chế độ mô phỏng không ghi dữ liệu:</strong>{" "}
              Các phiên chạy từ tính năng <em>Mô phỏng giao dịch</em> trên{" "}
              <code className="font-mono text-ink">/radar</code> gắn cờ{" "}
              <code className="font-mono text-ink">is_simulation=true</code>; hệ thống vẫn đối chiếu
              quy tắc chặn đang hiệu lực nhưng bỏ qua hoàn toàn bước ghi vào bảng hồ sơ, đồ thị dấu
              hiệu và dấu vân tay biên lai.
            </li>
          </ul>
        </div>
      </DocSection>

      {/* 5. Biện pháp bảo vệ thông tin cá nhân */}
      <DocSection id="bao-ve-pii" number="05" title="Biện pháp bảo vệ thông tin cá nhân">
        <p>
          VeriShield AI áp dụng nhiều lớp giảm thiểu và che giấu dữ liệu ngay trong tầng ứng dụng
          và tầng lưu trữ:
        </p>

        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Che giấu tự động số điện thoại và số tài khoản:</strong>{" "}
            Hàm <code className="font-mono text-ink">redact_report_pii</code> và{" "}
            <code className="font-mono text-ink">scrub_free_text_pii</code> che các chữ số ở giữa
            của số điện thoại Việt Nam (ví dụ <code className="font-mono text-ink">091****678</code>)
            và số tài khoản ngân hàng (ví dụ <code className="font-mono text-ink">19****01</code>),
            bao gồm cả các dạng viết có dấu cách, dấu chấm hoặc gạch ngang, trên toàn bộ trường tóm
            tắt, văn bản OCR, lời thoại, bằng chứng, đường dẫn và báo cáo PDF.
          </li>
          <li>
            <strong className="font-semibold text-ink">Ẩn dữ liệu thanh toán VietQR và tệp nhị phân:</strong>{" "}
            Chuỗi VietQR thô được thay bằng nhãn ẩn định danh, tải trọng QR bị ẩn trên hồ sơ lưu
            trữ, tên tệp gốc bị loại bỏ và toàn bộ ảnh gốc, bản đồ nhiệt ELA, ảnh chụp trang web
            cách ly cùng thẻ phần mềm EXIF bị xóa trước khi ghi vào bảng{" "}
            <code className="font-mono text-ink">cases</code>.
          </li>
          <li>
            <strong className="font-semibold text-ink">Băm một chiều cho đồ thị và danh sách chặn:</strong>{" "}
            Các bảng công khai trên <code className="font-mono text-ink">/radar</code> không lưu số
            điện thoại, số tài khoản hay tên miền đầy đủ ở dạng rõ. Hệ thống lưu mã băm một chiều (
            <code className="font-mono text-ink">HMAC-SHA256</code> có khóa bí mật trong môi trường
            production hoặc khi cấu hình <code className="font-mono text-ink">IOC_HMAC_SECRET</code>
            ; dự phòng <code className="font-mono text-ink">SHA-256</code> ở môi trường demo/phát
            triển chưa cấu hình khóa riêng) kèm nhãn hiển thị đã che giấu.
          </li>
          <li>
            <strong className="font-semibold text-ink">Truyền tải mã hóa và tiêu đề bảo mật:</strong>{" "}
            Môi trường triển khai dùng <code className="font-mono text-ink">HTTPS/TLS</code> tự động
            qua Caddy, chuyển hướng cưỡng bức HTTP sang HTTPS và gắn các tiêu đề bảo mật tiêu chuẩn
            (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
          </li>
        </ul>

        <DocCallout tone="caution" title="Minh bạch về giới hạn của cơ chế che giấu tự động">
          <p>
            Hệ thống <strong>không tuyên bố &ldquo;không lưu bất kỳ dữ liệu cá nhân nào&rdquo;</strong>.
            Cụ thể:
          </p>
          <ul className="list-disc space-y-1 pl-4">
            <li>
              Bảng <code className="font-mono text-ink">cases</code> lưu báo cáo JSON đã che SĐT và
              STK, nhưng các đoạn văn bản tự do trong <code className="font-mono text-ink">ocr_text</code>,{" "}
              <code className="font-mono text-ink">transcript</code>,{" "}
              <code className="font-mono text-ink">summary_vi</code> hoặc{" "}
              <code className="font-mono text-ink">evidence</code> vẫn có thể chứa thông tin định
              danh phi số học (như họ tên cá nhân, địa chỉ, email, nội dung chuyển khoản hoặc mã
              tham chiếu giao dịch) nếu xuất hiện trong dữ liệu bạn gửi.
            </li>
            <li>
              Hồ sơ đã lưu hiện có thể được truy xuất qua mã hồ sơ ngẫu nhiên 12 ký tự hex (
              <code className="font-mono text-ink">case_id</code>) để phục vụ xem lại và tải báo cáo
              PDF; hiện chưa có cơ chế xác thực phiên người dùng riêng cho từng hồ sơ.
            </li>
          </ul>
        </DocCallout>
      </DocSection>

      {/* 6. Dịch vụ bên thứ ba và việc chuyển dữ liệu */}
      <DocSection id="ben-thu-ba" number="06" title="Dịch vụ bên thứ ba và việc chuyển dữ liệu">
        <p>
          Tùy theo cấu hình của môi trường triển khai và thao tác của người dùng, dữ liệu có thể
          được chuyển tới các bên thứ ba sau đây:
        </p>

        <DocTable
          caption="Các dịch vụ bên thứ ba có thể nhận dữ liệu trong quá trình xử lý"
          headers={["Dịch vụ / Bên tiếp nhận", "Điều kiện kích hoạt", "Dữ liệu được gửi đi", "Ghi chú kiểm soát"]}
          rows={[
            [
              "Nhà cung cấp AI đa phương thức (Google Gemini API hoặc cổng API tương thích OpenAI do người vận hành cấu hình)",
              "Khi khóa API AI được cấu hình cho Tầng 2 suy luận, hoặc khi kích hoạt OCR dự phòng (OCR cục bộ lỗi/quá giờ, độ tin cậy < 0,45 hoặc ảnh không kèm chữ).",
              "Văn bản người dùng gửi, văn bản OCR (bọc trong thẻ cách ly), tối đa 4 ảnh gốc và tệp âm thanh (≤ 10 MB) — gửi ở dạng nguyên bản trước bước che giấu lưu trữ.",
              "Hệ thống hỗ trợ chạy hoàn toàn nội bộ ở chế độ dự phòng Tầng 1 nếu không cấu hình khóa API. Việc lưu giữ/xử lý tại nhà cung cấp AI tuân theo chính sách của nhà cung cấp tương ứng.",
            ],
            [
              "Máy chủ web đích của đường dẫn công khai",
              "Khi người dùng trực tiếp nhập URL hoặc gửi mã QR chứa URL và tính năng kiểm tra mạng/sandbox đang bật.",
              "Yêu cầu HTTP GET từ máy chủ VeriShield (tối đa 5 bước chuyển hướng) và tải trang trong trình duyệt Chromium cách ly nếu điểm rủi ro tĩnh ≥ 40.",
              "Tuyệt đối không gửi truy vấn mạng tới URL chỉ xuất hiện trong văn bản OCR từ ảnh; chặn toàn bộ địa chỉ IP nội bộ/riêng tư.",
            ],
            [
              "Telegram (api.telegram.org)",
              "Chỉ khi người dùng chủ động gửi hoặc chuyển tiếp nội dung qua Telegram Bot (nếu bot được bật).",
              "Tin nhắn, tệp đính kèm gửi tới bot và thông điệp kết quả do hệ thống trả về.",
              "Dữ liệu trao đổi trên ứng dụng Telegram chịu sự điều chỉnh của chính sách quyền riêng tư của Telegram.",
            ],
          ]}
        />
      </DocSection>

      {/* 7. Chính sách lưu trữ và xóa dữ liệu */}
      <DocSection id="luu-tru-xoa" number="07" title="Chính sách lưu trữ và xóa dữ liệu">
        <p>
          Trạng thái lưu giữ dữ liệu thực tế trong cơ sở dữ liệu SQLite WAL và bộ nhớ hiện tại như
          sau:
        </p>

        <DocTable
          caption="Cơ chế lưu giữ và hết hạn dữ liệu theo từng bảng lưu trữ thực tế"
          headers={["Kho lưu trữ / Bảng dữ liệu", "Cơ chế hết hạn hoặc xóa tự động hiện có", "Ghi chú thực tế"]}
          rows={[
            [
              "Quy tắc chặn tạm thời (block_rules)",
              "Có TTL tự động (mặc định 30 phút, cấu hình từ 1 đến 1.440 phút) và hỗ trợ thu hồi thủ công có xác thực quản trị.",
              "Hết hiệu lực ngay khi quá mốc expires_at.",
            ],
            [
              "Nhật ký kiểm toán quản trị (radar_audit_logs)",
              "Tự động giới hạn và xóa bản ghi cũ, chỉ giữ tối đa 200 sự kiện gần nhất.",
              "Chỉ chứa nhãn đã che giấu và mã băm IP rút gọn.",
            ],
            [
              "Bộ đếm giới hạn tần suất (RAM)",
              "Lưu trong bộ nhớ tạm theo cửa sổ trượt 60 giây, giới hạn tối đa 4.096 IP gần nhất.",
              "Mất hoàn toàn khi tiến trình khởi động lại.",
            ],
            [
              "Tệp âm thanh tạm cục bộ (OS temp)",
              "Xóa ngay lập tức sau khi kết thúc phiên gỡ băng trong cùng yêu cầu xử lý.",
              "Không giữ lại tệp âm thanh gốc.",
            ],
            [
              "Hồ sơ kiểm tra (cases), đồ thị IOC (ioc_sightings, campaigns), dấu vân tay biên lai (receipt_hashes), cache webhook (telegram_updates)",
              "Chưa có tác vụ dọn dẹp tự động theo thời hạn (TTL) và chưa có chức năng tự xóa cho người dùng cuối.",
              "Cần chủ dự án xác định thời hạn lưu trữ chính thức và bổ sung cơ chế tự động xóa định kỳ trước khi vận hành chính thức diện rộng.",
            ],
          ]}
        />

        <p className="text-xs text-ink-muted">
          Ngoài cơ sở dữ liệu ứng dụng, thư mục bộ nhớ đệm mô hình cục bộ (
          <code className="font-mono text-ink-secondary">/app/ocr_cache</code>,{" "}
          <code className="font-mono text-ink-secondary">/app/whisper_cache</code>) chỉ chứa tệp
          trọng số mô hình tĩnh phục vụ suy luận và không lưu dữ liệu người dùng.
        </p>
      </DocSection>

      {/* 8. Cookies và dữ liệu truy cập */}
      <DocSection id="cookies-truy-cap" number="08" title="Cookies và dữ liệu truy cập">
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Không dùng cookies theo dõi hay quảng cáo:</strong>{" "}
            Mã nguồn giao diện web VeriShield AI hiện không thiết lập cookie theo dõi hành vi, không
            nhúng mã phân tích của bên thứ ba (như Google Analytics hay pixel quảng cáo) và không
            lưu nội dung người dùng vào <code className="font-mono text-ink">localStorage</code> hay{" "}
            <code className="font-mono text-ink">sessionStorage</code>.
          </li>
          <li>
            <strong className="font-semibold text-ink">Phông chữ tự lưu cục bộ:</strong> Phông chữ{" "}
            <code className="font-mono text-ink">Inter</code> và{" "}
            <code className="font-mono text-ink">JetBrains Mono</code> được đóng gói sẵn cùng ứng
            dụng lúc xây dựng (<code className="font-mono text-ink">next/font</code>), trình duyệt
            không gửi yêu cầu tải phông chữ tới máy chủ ngoài trong lúc bạn truy cập.
          </li>
          <li>
            <strong className="font-semibold text-ink">Dữ liệu truy cập tầng máy chủ:</strong> Khi
            truy cập website hoặc gọi API, máy chủ biên (Caddy) và ứng dụng backend tiếp nhận siêu
            dữ liệu kết nối HTTP chuẩn (địa chỉ IP, thời điểm truy cập, đường dẫn yêu cầu, mã phản
            hồi) để định tuyến HTTPS, chống lạm dụng và chẩn đoán sự cố vận hành theo cấu hình nhật
            ký của hạ tầng máy chủ.
          </li>
        </ul>
      </DocSection>

      {/* 9. Quyền của người dùng */}
      <DocSection id="quyen-nguoi-dung" number="09" title="Quyền của người dùng">
        <p>Khi sử dụng VeriShield AI, bạn có thể chủ động kiểm soát thông tin của mình theo các cách sau:</p>
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Quyền tối thiểu hóa dữ liệu trước khi gửi:</strong>{" "}
            Bạn có thể xóa họ tên, địa chỉ, hình ảnh giấy tờ tùy thân hoặc thông tin riêng tư không
            liên quan khỏi tin nhắn/ảnh chụp trước khi tải lên kiểm tra.
          </li>
          <li>
            <strong className="font-semibold text-ink">Quyền trải nghiệm không dùng dữ liệu thật:</strong>{" "}
            Bạn có thể dùng các tình huống mẫu tổng hợp trên trang chủ hoặc tính năng{" "}
            <em>Mô phỏng giao dịch</em> trên <code className="font-mono text-ink">/radar</code>{" "}
            (không ghi vào cơ sở dữ liệu).
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Yêu cầu tra cứu, chỉnh sửa hoặc xóa hồ sơ đã lưu:
            </strong>{" "}
            Hiện hệ thống chưa tích hợp cổng tự phục vụ để người dùng trực tiếp xóa bản ghi{" "}
            <code className="font-mono text-ink">case_id</code> trong cơ sở dữ liệu. Quy trình tiếp
            nhận, xác minh chủ thể và thực thi yêu cầu xóa dữ liệu cần được chủ dự án thiết lập và
            công bố kênh tiếp nhận chính thức trước khi vận hành chính thức.
          </li>
        </ul>
      </DocSection>

      {/* 10. Thông tin liên hệ */}
      <DocSection id="lien-he" number="10" title="Thông tin liên hệ">
        <DocCallout tone="info" title="Mục cần chủ dự án bổ sung trước khi công bố chính thức">
          <p>
            Trong mã nguồn hiện tại chưa khai báo pháp nhân/đơn vị vận hành chính thức, địa chỉ
            email phụ trách quyền riêng tư (Privacy/DPO) hay kênh tiếp nhận yêu cầu xóa dữ liệu.
          </p>
          <p>
            Trước khi công bố chính sách quyền riêng tư cho người dùng đại chúng, chủ dự án cần điền
            đầy đủ: (1) Tên đơn vị hoặc cá nhân chịu trách nhiệm vận hành, (2) Địa chỉ email liên hệ
            về quyền riêng tư và báo cáo sự cố bảo mật, (3) Thời gian phản hồi dự kiến đối với yêu
            cầu xóa dữ liệu.
          </p>
        </DocCallout>
      </DocSection>

      {/* 11. Thay đổi chính sách */}
      <DocSection id="thay-doi" number="11" title="Thay đổi chính sách">
        <p>
          Chính sách này sẽ được cập nhật khi VeriShield AI thay đổi luồng xử lý dữ liệu, tích hợp
          nhà cung cấp AI mới, bổ sung chính sách lưu giữ/xóa tự động hoặc hoàn thiện các thông tin
          quản trị và liên hệ. Mọi phiên bản cập nhật sẽ được công bố trực tiếp tại trang{" "}
          <code className="font-mono text-ink">/privacy</code> cùng ghi nhận phạm vi thay đổi.
        </p>
        <p className="pt-2 text-xs text-ink-muted">
          Xem thêm chi tiết về kiến trúc xử lý, kiểm soát bảo mật và giới hạn kỹ thuật tại trang{" "}
          <Link
            href="/technical"
            className="font-medium text-sky-300 underline decoration-sky-500/40 underline-offset-2 hover:text-sky-200"
          >
            Công nghệ và kiến trúc hệ thống
          </Link>
          .
        </p>
      </DocSection>
    </DocsShell>
  );
}
