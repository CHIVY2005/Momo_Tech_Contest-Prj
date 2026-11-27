import type { Metadata } from "next";
import Link from "next/link";

import { DataLifecycleSvg } from "@/components/docs/DataLifecycleSvg";
import { DrawOnView } from "@/components/motion/DrawOnView";
import {
  DocCallout,
  DocSection,
  DocsShell,
  DocTable,
} from "@/components/docs/DocsShell";
import type { TocItem } from "@/components/docs/DocsToc";

export const metadata: Metadata = {
  title: "Chính sách quyền riêng tư (Bản dự thảo) — VeriShield AI",
  description:
    "Tìm hiểu cách VeriShield AI thu thập, xử lý, che giấu, lưu trữ và bảo vệ thông tin khi bạn kiểm tra dấu hiệu lừa đảo.",
};

const PRIVACY_TOC: readonly TocItem[] = [
  { id: "tong-quan", number: "01", label: "Tổng quan và phạm vi áp dụng" },
  { id: "du-lieu-thu-thap", number: "02", label: "Dữ liệu được thu thập" },
  { id: "muc-dich-xu-ly", number: "03", label: "Mục đích xử lý dữ liệu" },
  { id: "quy-trinh-xu-ly", number: "04", label: "Quy trình xử lý dữ liệu" },
  { id: "bao-ve-thong-tin", number: "05", label: "Bảo vệ thông tin cá nhân" },
  { id: "dich-vu-ben-thu-ba", number: "06", label: "Dịch vụ bên thứ ba" },
  { id: "luu-tru-xoa-du-lieu", number: "07", label: "Lưu trữ và xóa dữ liệu" },
  { id: "cookie-truy-cap", number: "08", label: "Cookie và dữ liệu truy cập" },
  { id: "quyen-nguoi-dung", number: "09", label: "Quyền của người dùng" },
  { id: "thong-tin-lien-he", number: "10", label: "Thông tin liên hệ" },
  { id: "cap-nhat-chinh-sach", number: "11", label: "Cập nhật chính sách" },
];

export default function PrivacyPage() {
  return (
    <DocsShell
      breadcrumbLabel="Quyền riêng tư"
      title="Chính sách quyền riêng tư"
      description="Tìm hiểu cách VeriShield AI thu thập, xử lý, che giấu và bảo vệ thông tin khi bạn sử dụng dịch vụ."
      metaItems={[
        { label: "Trạng thái tài liệu", value: "Bản dự thảo (chờ hoàn thiện thông tin quản trị và liên hệ)" },
        {
          label: "Phạm vi áp dụng",
          value: "Trang web kiểm tra, Trợ lý VeriShield, Trung tâm giám sát, API và Telegram Bot",
        },
      ]}
      tocItems={PRIVACY_TOC}
    >
      <DocCallout tone="warning" title="Bản dự thảo — Thông tin minh bạch về trạng thái chính sách">
        <p>
          Tài liệu này là <strong>bản dự thảo chính sách quyền riêng tư</strong>, mô tả trung thực
          cách hệ thống VeriShield AI hiện đang xử lý dữ liệu. Tài liệu không phải là tuyên bố chứng
          nhận bảo mật hay xác nhận tuân thủ pháp lý chính thức.
        </p>
        <p>
          Một số nội dung quản trị — bao gồm <strong>đơn vị vận hành chịu trách nhiệm dữ liệu</strong>,{" "}
          <strong>thời hạn lưu trữ cố định cho hồ sơ đã lưu</strong>,{" "}
          <strong>quy trình tiếp nhận yêu cầu xóa dữ liệu</strong> và{" "}
          <strong>kênh liên hệ chính thức</strong> — hiện chưa được ấn định và cần chủ dự án bổ sung
          trước khi phát hành chính thức.
        </p>
      </DocCallout>

      {/* 1. Tổng quan và phạm vi áp dụng */}
      <DocSection id="tong-quan" number="01" title="Tổng quan và phạm vi áp dụng">
        <p>
          Chính sách này áp dụng khi bạn sử dụng{" "}
          <strong className="font-semibold text-ink">VeriShield AI</strong> trên trang web kiểm tra
          dấu hiệu lừa đảo, khung hỏi đáp{" "}
          <strong className="font-semibold text-ink">Trợ lý VeriShield</strong>, trang{" "}
          <Link
            href="/radar"
            className="text-sky-300 underline decoration-sky-500/40 underline-offset-2 hover:text-sky-200"
          >
            Giám sát gian lận
          </Link>
          , tính năng tải báo cáo PDF hoặc kênh Telegram Bot (khi được bật).
        </p>
        <p>
          VeriShield AI là công cụ hỗ trợ kiểm tra rủi ro trước khi chuyển tiền. Hệ thống không yêu
          cầu bạn đăng ký tài khoản cá nhân và không kết nối trực tiếp vào tài khoản ngân hàng hay
          ví điện tử của bạn. Đặc biệt, ảnh chụp biên lai chuyển khoản không bao giờ được xem là
          bằng chứng tiền đã về tài khoản; cả hệ thống và Trợ lý VeriShield luôn yêu cầu người bán
          kiểm tra số dư thực tế trên ứng dụng ngân hàng hoặc loa thông báo biến động số dư
          (Soundbox) trước khi giao hàng.
        </p>
        <p>
          Tuy nhiên, tin nhắn, ảnh chụp màn hình hoặc tệp ghi âm bạn gửi lên có thể chứa thông tin
          cá nhân (như họ tên, số điện thoại, số tài khoản, địa chỉ hoặc email). Bạn nên che bớt các
          thông tin riêng tư không cần thiết trước khi tải lên.
        </p>
      </DocSection>

      {/* 2. Dữ liệu được thu thập */}
      <DocSection id="du-lieu-thu-thap" number="02" title="Dữ liệu được thu thập">
        <p>
          Hệ thống chỉ tiếp nhận nội dung bạn chủ động gửi để kiểm tra và một phần dữ liệu kỹ thuật
          tối thiểu nhằm chống lạm dụng dịch vụ:
        </p>

        <DocTable
          caption="Các nhóm dữ liệu được tiếp nhận và trạng thái lưu trữ tại VeriShield AI"
          headers={["Loại dữ liệu", "Nội dung bạn gửi hoặc phát sinh", "Cách hệ thống lưu trữ hiện tại"]}
          rows={[
            [
              "Văn bản và đường dẫn",
              "Nội dung tin nhắn, mô tả tình huống, đường dẫn trang web và thông tin tùy chọn bạn điền thêm (số tiền dự kiến chuyển, số tài khoản đối chiếu, trạng thái đang nghe điện thoại).",
              "Không lưu bản gốc thành kho dữ liệu riêng. Báo cáo phân tích kết quả được lưu trong cơ sở dữ liệu ứng dụng sau khi chạy bước che giấu số điện thoại và số tài khoản.",
            ],
            [
              "Hình ảnh tải lên",
              "Tối đa 4 ảnh mỗi lượt (JPG, PNG, WebP, GIF; tối đa 10 MB mỗi ảnh, tổng đính kèm không quá 20 MB) như ảnh tin nhắn, biên lai chuyển khoản hoặc mã VietQR.",
              "Ảnh gốc không được lưu trong cơ sở dữ liệu ứng dụng. Tên tệp gốc bị loại bỏ. Chỉ văn bản đọc từ ảnh (sau khi che số điện thoại/số tài khoản) và mã đặc trưng hình ảnh của biên lai được lưu.",
            ],
            [
              "Tệp ghi âm cuộc gọi",
              "Tối đa 2 tệp âm thanh mỗi lượt (WAV, MP3, M4A, OGG, WebM; tối đa 10 MB mỗi tệp).",
              "Âm thanh gốc không được lưu trong cơ sở dữ liệu ứng dụng. Tệp tạm dùng để chuyển giọng nói thành văn bản được xóa ngay sau khi xử lý. Nội dung lời thoại đã che số điện thoại/số tài khoản được lưu trong báo cáo.",
            ],
            [
              "Hội thoại với Trợ lý VeriShield",
              "Câu hỏi bạn nhập trong khung Trợ lý, lịch sử hội thoại ngắn trong phiên đang mở (tối đa 6 lượt gần nhất) và ngữ cảnh hồ sơ bạn đang xem.",
              "Không lưu nội dung hội thoại vào cơ sở dữ liệu máy chủ. Lịch sử trò chuyện chỉ nằm tạm trong bộ nhớ phiên trình duyệt hiện tại và bạn có thể bấm nút \"Xóa hội thoại\" bất cứ lúc nào.",
            ],
            [
              "Bằng chứng bổ sung trong Trợ lý VeriShield",
              "Tối đa 1 hình ảnh hoặc 1 tệp ghi âm (≤ 10 MB) bạn chủ động đính kèm trong khung Trợ lý để kiểm tra thêm.",
              "Mặc định xử lý hoàn toàn cục bộ trên máy chủ VeriShield: không gửi tệp media tới AI bên ngoài, không phát yêu cầu mạng ra bên ngoài từ mã QR hay bản ghi âm, không ghi vào cơ sở dữ liệu hay Radar cộng đồng, và chỉ giữ kết quả đã ẩn danh tạm thời trong bộ nhớ tối đa 15 phút. Chỉ lưu thành hồ sơ bổ sung hoặc đóng góp vào Radar khi bạn chủ động xác nhận.",
            ],
            [
              "Nội dung qua Telegram Bot",
              "Tin nhắn văn bản, ảnh hoặc tệp ghi âm bạn chuyển tiếp cho bot (nếu bot được triển khai).",
              "Lưu mã nhận diện tin nhắn của Telegram, mã hồ sơ liên quan và nội dung phản hồi đã che giấu để tránh gửi kết quả trùng lặp. Báo cáo PDF chỉ được gửi trực tiếp trong khung trò chuyện riêng 1-1 với đúng người gửi yêu cầu (không cấp đường dẫn PDF công khai và không phát hành PDF trong nhóm chat).",
            ],
            [
              "Dữ liệu kỹ thuật và vận hành",
              "Địa chỉ IP kết nối (để giới hạn tần suất gửi yêu cầu) và nhật ký các thao tác quản trị quy tắc chặn trên trang Giám sát gian lận.",
              "Thông tin giới hạn tần suất chỉ giữ tạm trong bộ nhớ máy chủ và tự xóa sau thời gian ngắn. Nhật ký quản trị chỉ lưu mã băm rút gọn của địa chỉ IP, không lưu địa chỉ IP nguyên bản.",
            ],
          ]}
        />
      </DocSection>

      {/* 3. Mục đích xử lý dữ liệu */}
      <DocSection id="muc-dich-xu-ly" number="03" title="Mục đích xử lý dữ liệu">
        <p>Dữ liệu bạn cung cấp chỉ được sử dụng cho các mục đích trực tiếp sau:</p>
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Đánh giá rủi ro lừa đảo theo yêu cầu:</strong>{" "}
            Đọc chữ từ hình ảnh, chuyển giọng nói thành văn bản, kiểm tra mã VietQR, phát hiện dấu
            hiệu chỉnh sửa biên lai, kiểm tra đường dẫn đáng ngờ và đưa ra khuyến nghị xử lý.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Phát hiện biên lai gửi lặp lại và chuỗi dấu hiệu lừa đảo:
            </strong>{" "}
            Đối chiếu dấu hiệu lặp lại của ảnh biên lai hoặc mã giao dịch; tổng hợp các dấu hiệu rủi
            ro cao dưới dạng đã băm và che giấu trên trang Giám sát gian lận.
          </li>
          <li>
            <strong className="font-semibold text-ink">Hỗ trợ xem lại và tải báo cáo PDF:</strong>{" "}
            Giúp bạn xem lại kết quả phân tích hoặc tải tệp PDF tiếng Việt trong phiên truy cập của
            riêng hồ sơ đó (hoặc trực tiếp trong khung trò chuyện riêng 1-1 trên Telegram) để lưu trữ
            và đối chiếu khi cần thiết.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Hỏi đáp phòng chống lừa đảo cùng Trợ lý VeriShield:
            </strong>{" "}
            Giải thích dễ hiểu các dấu hiệu cảnh báo trong hồ sơ đang xem, hướng dẫn xử lý khẩn cấp
            khi lỡ chuyển tiền hoặc lộ thông tin, kiểm tra an toàn đường dẫn/mã VietQR/dấu hiệu nghi
            vấn theo yêu cầu và phân tích bằng chứng bổ sung ở chế độ cục bộ mặc định.
          </li>
          <li>
            <strong className="font-semibold text-ink">Bảo vệ an toàn hệ thống:</strong> Ngăn chặn
            gửi yêu cầu quá tải, phát hiện hành vi chèn chỉ thị độc hại vào AI, chặn truy cập vào
            mạng nội bộ và ghi nhận thao tác quản trị.
          </li>
        </ul>
      </DocSection>

      {/* 4. Quy trình xử lý dữ liệu */}
      <DocSection id="quy-trinh-xu-ly" number="04" title="Quy trình xử lý dữ liệu">
        <p>
          Mỗi lượt kiểm tra đi qua 4 bước chính: tiếp nhận dữ liệu, phân tích tạm thời (kèm tùy chọn
          chuyển dữ liệu ra bên ngoài khi cần), lọc che giấu thông tin và lưu báo cáo kết quả. Riêng
          nhánh <strong className="font-semibold text-ink">Trợ lý VeriShield</strong> lọc và ẩn danh
          thông tin nhạy cảm trước khi gọi mô hình AI bên ngoài, đồng thời xử lý bằng chứng bổ sung
          theo mặc định hoàn toàn cục bộ trên máy chủ.
        </p>

        <DrawOnView>
          <DataLifecycleSvg />
        </DrawOnView>

        <ul className="list-disc space-y-2 pl-5 pt-1">
          <li>
            <strong className="font-semibold text-ink">Hình ảnh được xử lý trên bộ nhớ tạm:</strong>{" "}
            Ảnh tải lên được đọc chữ, giải mã mã QR và kiểm tra dấu hiệu chỉnh sửa trực tiếp trong
            bộ nhớ máy chủ, không ghi tệp ảnh gốc xuống ổ đĩa lưu trữ.
          </li>
          <li>
            <strong className="font-semibold text-ink">Tệp âm thanh tạm được xóa ngay:</strong>{" "}
            Khi chuyển giọng nói thành văn bản, hệ thống chỉ tạo tệp tạm trong lúc xử lý và xóa ngay
            lập tức khi hoàn tất hoặc khi có lỗi xảy ra.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Trợ lý VeriShield lọc dữ liệu nhạy cảm trước khi gọi AI:
            </strong>{" "}
            Trợ lý chỉ hoạt động trong ngữ cảnh hồ sơ đang xem (được bảo vệ bằng khóa phiên riêng)
            hoặc các câu hỏi phòng chống lừa đảo. Mọi số điện thoại, số tài khoản, CCCD, mã OTP,
            mật khẩu, email, đường dẫn web và chuỗi VietQR đều được lọc và ẩn danh trước khi gửi tới
            mô hình AI bên ngoài; khi cần kiểm tra đường dẫn hoặc mã VietQR, máy chủ xử lý nội bộ
            qua mã tham chiếu tạm thời.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Bằng chứng bổ sung trong Trợ lý mặc định xử lý hoàn toàn cục bộ:
            </strong>{" "}
            Khi bạn đính kèm ảnh hoặc ghi âm trong khung Trợ lý, mặc định máy chủ VeriShield phân
            tích hoàn toàn nội bộ — không gửi tệp media tới AI bên ngoài, không phát yêu cầu mạng ra
            bên ngoài từ mã QR hay bản ghi âm, không ghi vào cơ sở dữ liệu hay Radar cộng đồng, và
            chỉ giữ kết quả đã ẩn danh tạm thời trong bộ nhớ tối đa 15 phút. Việc gửi tệp media tới
            AI bên ngoài hoặc lưu thành hồ sơ bổ sung / đóng góp ẩn danh vào Radar cộng đồng chỉ xảy
            ra khi bạn chủ động đánh dấu đồng ý hoặc bấm nút{" "}
            <em>&ldquo;Lưu hồ sơ bổ sung &amp; tải PDF&rdquo;</em>.
          </li>
          <li>
            <strong className="font-semibold text-ink">Chế độ mô phỏng không lưu hồ sơ:</strong>{" "}
            Các lượt kiểm thử trong khu vực <em>Mô phỏng giao dịch</em> trên trang Giám sát gian lận
            không ghi hồ sơ vào cơ sở dữ liệu và không làm thay đổi thống kê hệ thống.
          </li>
        </ul>
      </DocSection>

      {/* 5. Bảo vệ thông tin cá nhân */}
      <DocSection id="bao-ve-thong-tin" number="05" title="Bảo vệ thông tin cá nhân">
        <p>
          Để bạn hiểu rõ mức độ bảo vệ thực tế, dưới đây là cách VeriShield AI áp dụng từng biện
          pháp kỹ thuật và sự khác biệt giữa chúng:
        </p>

        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">
              Kiểm soát truy cập hồ sơ thống nhất:
            </strong>{" "}
            Mỗi hồ sơ phân tích trên trang web được cấp một khóa phiên truy cập riêng (tự động hết
            hạn sau 2 giờ), áp dụng thống nhất khi xem lại hồ sơ, tải báo cáo PDF hoặc trò chuyện
            với Trợ lý VeriShield theo hồ sơ đó; mọi phản hồi chứa thông tin hồ sơ đều tắt lưu bộ
            nhớ đệm. Trên Telegram, báo cáo PDF chỉ được gửi trực tiếp trong khung trò chuyện riêng
            1-1 với đúng người gửi yêu cầu (không cung cấp đường link PDF công khai và không phát
            hành PDF trong nhóm chat). Các hồ sơ cũ tạo trước khi có cơ chế khóa phiên được mặc định
            khóa truy cập.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Che giấu thông tin (Masking / Redaction):
            </strong>{" "}
            Hệ thống tự động che phần chữ số ở giữa của số điện thoại Việt Nam (ví dụ{" "}
            <code className="font-mono text-ink">091****678</code>) và số tài khoản ngân hàng (ví dụ{" "}
            <code className="font-mono text-ink">19****01</code>) trước khi lưu báo cáo hoặc xuất
            tệp PDF. Tên tệp gốc, dữ liệu gốc của mã VietQR và hình ảnh gốc cũng bị loại bỏ khỏi bản
            lưu trữ. Riêng trong Trợ lý VeriShield, toàn bộ dữ liệu trước khi gửi tới mô hình AI bên
            ngoài (câu hỏi hiện tại, lịch sử trò chuyện, trích đoạn hồ sơ và kết quả tra cứu) đều
            được lọc và ẩn danh thêm CCCD, số thẻ, mã OTP, mật khẩu, email, đường dẫn web và chuỗi
            VietQR.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Giả danh hóa (Pseudonymization) và băm một chiều (Hashing):
            </strong>{" "}
            Trên trang Giám sát gian lận và danh sách chặn, số điện thoại, số tài khoản hoặc tên
            miền nghi vấn được chuyển thành mã băm một chiều (có khóa bí mật trên môi trường vận
            hành chính thức) kết hợp nhãn hiển thị đã che giấu. Cách làm này không hiển thị trực
            tiếp dữ liệu gốc nhưng vẫn cho phép hệ thống nhận biết khi cùng một dấu hiệu xuất hiện
            nhiều lần.
          </li>
          <li>
            <strong className="font-semibold text-ink">Mã hóa đường truyền (Encryption):</strong>{" "}
            Dữ liệu trao đổi giữa thiết bị của bạn và máy chủ VeriShield AI được mã hóa qua giao
            thức HTTPS/TLS cùng các tiêu đề bảo mật tiêu chuẩn trên trình duyệt.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Không khẳng định &ldquo;ẩn danh hoàn toàn&rdquo; (Anonymization):
            </strong>{" "}
            Ẩn danh hóa hoàn toàn đòi hỏi không thể nhận diện lại cá nhân từ dữ liệu đã lưu dưới mọi
            hình thức. VeriShield AI không đưa ra cam kết này vì dữ liệu văn bản tự do trong báo cáo
            vẫn có thể chứa thông tin định danh cá nhân.
          </li>
        </ul>

        <DocCallout tone="caution" title="Những giới hạn quan trọng cần lưu ý">
          <ul className="list-disc space-y-1.5 pl-4">
            <li>
              <strong>Báo cáo phân tích vẫn có thể chứa thông tin cá nhân chưa được che giấu:</strong>{" "}
              Bước che giấu tự động khi lưu báo cáo chính hiện tập trung vào số điện thoại và số tài
              khoản. Các thông tin cá nhân như họ tên, địa chỉ, email, nội dung chuyển khoản hoặc mã
              tham chiếu giao dịch vẫn có thể còn xuất hiện trong phần tóm tắt, bằng chứng, chữ đọc
              từ ảnh hoặc lời thoại được lưu trong báo cáo.
            </li>
            <li>
              <strong>Giới hạn của khóa phiên truy cập không cần đăng nhập:</strong> Mỗi hồ sơ trên
              web được bảo vệ bằng khóa phiên truy cập riêng (tự động hết hạn sau 2 giờ và chỉ giữ
              tạm trong tab trình duyệt hiện tại). Nếu đóng tab, tải lại trang hoặc quá 2 giờ, bạn
              cần phân tích lại để đối chiếu hồ sơ (hoặc dùng Trợ lý ở chế độ hỏi đáp chung). Hệ
              thống không có tài khoản đăng nhập dài hạn, vì vậy bất kỳ ai sử dụng chung thiết bị
              trong khi tab đang mở vẫn có thể xem hồ sơ đó.
            </li>
            <li>
              <strong>Minh bạch biên lai người bán:</strong> Ảnh chụp biên lai không bao giờ được
              xem là bằng chứng tiền đã về tài khoản; ngay cả khi không phát hiện dấu hiệu chỉnh
              sửa, Trợ lý và hệ thống luôn yêu cầu kiểm tra số dư thực tế trên ứng dụng ngân hàng
              hoặc loa thông báo biến động số dư (Soundbox) trước khi giao hàng.
            </li>
          </ul>
        </DocCallout>
      </DocSection>

      {/* 6. Dịch vụ bên thứ ba */}
      <DocSection id="dich-vu-ben-thu-ba" number="06" title="Dịch vụ bên thứ ba">
        <p>
          Tùy theo cấu hình máy chủ và nội dung bạn gửi, một phần dữ liệu có thể được chuyển ra bên
          ngoài hệ thống tới các dịch vụ sau:
        </p>

        <DocTable
          caption="Các bên thứ ba có thể tiếp nhận dữ liệu trong quá trình phân tích"
          headers={["Bên tiếp nhận", "Khi nào dữ liệu được gửi", "Dữ liệu nào được chuyển đi", "Lưu ý kiểm soát"]}
          rows={[
            [
              "Nhà cung cấp AI đa phương thức (Google Gemini hoặc cổng API AI do đơn vị vận hành cấu hình)",
              "Khi dịch vụ AI được bật cho lượt phân tích chính ban đầu, đọc chữ dự phòng khi công cụ nội bộ gặp lỗi, hoặc khi bạn trò chuyện với Trợ lý VeriShield.",
              <ul key="ai-egress-list" className="list-disc space-y-1 pl-4">
                <li>
                  <strong className="font-semibold text-ink">Lượt phân tích chính:</strong> văn bản,
                  văn bản trích từ ảnh, ảnh gốc và tệp ghi âm (có thể gửi dạng nguyên bản trước bước
                  che giấu để lưu trữ).
                </li>
                <li>
                  <strong className="font-semibold text-ink">Trợ lý VeriShield (hỏi đáp):</strong>{" "}
                  chỉ gửi nội dung đã lọc và ẩn danh SĐT, STK, CCCD, số thẻ, OTP, mật khẩu, email,
                  đường dẫn web và chuỗi VietQR.
                </li>
                <li>
                  <strong className="font-semibold text-ink">Bằng chứng bổ sung trong Trợ lý:</strong>{" "}
                  mặc định <strong>không gửi</strong> ảnh hay ghi âm tới AI bên ngoài (xử lý 100%
                  cục bộ).
                </li>
              </ul>,
              "Tệp ảnh/ghi âm bổ sung trong Trợ lý chỉ được gửi tới AI bên ngoài khi bạn chủ động đánh dấu ô đồng ý trước khi gửi. Nếu máy chủ không kết nối AI bên ngoài, hệ thống vẫn hoạt động cục bộ. Dữ liệu gửi đi tuân theo chính sách quyền riêng tư của nhà cung cấp AI.",
            ],
            [
              "Trang web đích của đường dẫn công khai",
              "Khi bạn trực tiếp nhập đường dẫn trang web, gửi ảnh mã QR ở lượt phân tích chính hoặc yêu cầu Trợ lý VeriShield kiểm tra một đường dẫn công khai.",
              "Yêu cầu truy cập từ máy chủ VeriShield để kiểm tra chuyển hướng (hoặc mở xem trước cách ly ở lượt phân tích chính; Trợ lý chỉ kiểm tra an toàn mà không mở trình duyệt).",
              "Hệ thống chặn truy cập mọi địa chỉ mạng nội bộ, không tự mở đường dẫn chỉ có trong chữ ảnh chụp, và không phát yêu cầu mạng ra ngoài từ mã QR hay bản ghi âm khi phân tích bằng chứng bổ sung ở chế độ cục bộ mặc định.",
            ],
            [
              "Telegram",
              "Chỉ khi bạn chủ động nhắn tin hoặc chuyển tiếp nội dung cho Telegram Bot.",
              "Nội dung tin nhắn, tệp đính kèm bạn gửi cho bot, kết quả phân tích và tệp báo cáo PDF (chỉ gửi trực tiếp trong khung chat riêng 1-1 với đúng người gửi, không cấp link công khai và không phát PDF trong nhóm chat).",
              "Dữ liệu trao đổi trên ứng dụng Telegram tuân theo chính sách quyền riêng tư của Telegram.",
            ],
          ]}
        />
      </DocSection>

      {/* 7. Lưu trữ và xóa dữ liệu */}
      <DocSection id="luu-tru-xoa-du-lieu" number="07" title="Lưu trữ và xóa dữ liệu">
        <p>
          Trạng thái lưu giữ và xóa dữ liệu thực tế trong hệ thống hiện tại được phân biệt rõ như
          sau:
        </p>

        <DocTable
          caption="Tình trạng lưu giữ và xóa dữ liệu theo từng loại thông tin"
          headers={["Loại dữ liệu", "Cơ chế xóa hoặc hết hạn hiện có", "Ghi chú thực tế"]}
          rows={[
            [
              "Ảnh gốc và tệp ghi âm gốc",
              "Không lưu trong cơ sở dữ liệu ứng dụng.",
              "Ảnh xử lý trên bộ nhớ tạm; tệp âm thanh tạm được xóa ngay sau khi chuyển thành văn bản.",
            ],
            [
              "Lịch sử hội thoại Trợ lý VeriShield",
              "Không lưu trong cơ sở dữ liệu máy chủ; chỉ giữ tạm trong phiên trình duyệt hiện tại và xóa ngay khi bấm \"Xóa hội thoại\", đổi hồ sơ hoặc đóng tab.",
              "Lưu ý trung thực: nút \"Xóa hội thoại\" chỉ xóa hội thoại trong trình duyệt hiện tại, không xóa các hồ sơ phân tích bạn đã lưu trên máy chủ và không thu hồi được nội dung (đã lọc/ẩn danh) từng gửi tới nhà cung cấp AI bên ngoài ở các lượt trước.",
            ],
            [
              "Bằng chứng bổ sung tạm thời trong Trợ lý & khóa phiên truy cập hồ sơ",
              "Kết quả bằng chứng bổ sung đã ẩn danh chỉ giữ tạm trong bộ nhớ máy chủ tối đa 15 phút; khóa phiên truy cập hồ sơ tự động hết hạn sau 2 giờ.",
              "Chỉ ghi thành hồ sơ bổ sung vào cơ sở dữ liệu (và chỉ đóng góp dấu hiệu ẩn danh vào Radar cộng đồng) khi bạn chủ động bấm \"Lưu hồ sơ bổ sung & tải PDF\" và tự chọn đóng góp.",
            ],
            [
              "Bộ đếm giới hạn tần suất truy cập",
              "Chỉ lưu tạm trong bộ nhớ máy chủ và tự động hết hạn sau thời gian ngắn.",
              "Bị xóa hoàn toàn khi máy chủ khởi động lại.",
            ],
            [
              "Nhật ký thao tác quản trị",
              "Tự động xóa các bản ghi cũ để chỉ giữ lại một số lượng giới hạn sự kiện gần nhất.",
              "Chỉ chứa nhãn đã che giấu và mã băm rút gọn của địa chỉ IP.",
            ],
            [
              "Quy tắc chặn tạm thời trên trang Giám sát gian lận",
              "Có thời hạn hiệu lực tự động (mặc định 30 phút) và có thể bị quản trị viên thu hồi thủ công.",
              "Cần phân biệt: khi quá thời hạn, quy tắc lập tức hết hiệu lực áp dụng nhưng bản ghi quy tắc vẫn chưa tự động bị xóa khỏi cơ sở dữ liệu cho đến khi được thu hồi, ghi đè hoặc đặt lại.",
            ],
            [
              "Hồ sơ báo cáo đã lưu, dấu hiệu tổng hợp trên mạng lưới, mã đặc trưng biên lai và lịch sử phản hồi Telegram",
              "Hiện chưa có cơ chế tự động xóa định kỳ theo thời hạn và chưa có chức năng để người dùng tự xóa.",
              "Chủ dự án cần xác định thời hạn lưu trữ chính thức và bổ sung cơ chế xóa định kỳ trước khi vận hành rộng rãi.",
            ],
          ]}
        />

        <p className="text-xs text-ink-muted">
          Các tệp mô hình AI chạy cục bộ trên máy chủ chỉ chứa dữ liệu mô hình tĩnh phục vụ phân
          tích, không lưu thông tin người dùng.
        </p>
      </DocSection>

      {/* 8. Cookie và dữ liệu truy cập */}
      <DocSection id="cookie-truy-cap" number="08" title="Cookie và dữ liệu truy cập">
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Không dùng cookie theo dõi hay quảng cáo:</strong>{" "}
            Giao diện web VeriShield AI hiện không đặt cookie theo dõi hành vi, không cài công cụ
            phân tích quảng cáo của bên thứ ba và không lưu nội dung bạn nhập vào bộ nhớ lưu trữ lâu
            dài của trình duyệt. Khóa phiên truy cập hồ sơ (hết hạn sau 2 giờ) và lịch sử trò chuyện
            với Trợ lý VeriShield chỉ tồn tại tạm thời trong bộ nhớ phiên đang mở của tab trình
            duyệt và tự xóa khi bạn bấm <em>&ldquo;Xóa hội thoại&rdquo;</em>, tải lại trang hoặc
            đóng tab.
          </li>
          <li>
            <strong className="font-semibold text-ink">Phông chữ đóng gói sẵn:</strong> Phông chữ
            hiển thị được đóng gói cùng ứng dụng nên trình duyệt không cần gửi yêu cầu tải phông chữ
            từ máy chủ bên ngoài khi bạn truy cập.
          </li>
          <li>
            <strong className="font-semibold text-ink">Nhật ký kết nối tầng máy chủ:</strong> Khi
            truy cập trang web, máy chủ web trung gian (reverse proxy) và máy chủ ứng dụng vẫn tiếp
            nhận thông tin kết nối chuẩn (địa chỉ IP, thời điểm truy cập, đường dẫn yêu cầu, trạng
            thái phản hồi) để duy trì kết nối HTTPS, chống quá tải và xử lý sự cố vận hành.
          </li>
        </ul>
      </DocSection>

      {/* 9. Quyền của người dùng */}
      <DocSection id="quyen-nguoi-dung" number="09" title="Quyền của người dùng">
        <p>Khi sử dụng VeriShield AI, bạn có thể chủ động hạn chế rủi ro lộ thông tin bằng cách:</p>
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong className="font-semibold text-ink">Chủ động lược bỏ thông tin nhạy cảm:</strong>{" "}
            Xóa họ tên, địa chỉ, ảnh giấy tờ tùy thân hoặc chi tiết cá nhân không cần thiết khỏi tin
            nhắn và ảnh chụp trước khi gửi kiểm tra.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Kiểm soát hội thoại và bằng chứng bổ sung trong Trợ lý VeriShield:
            </strong>{" "}
            Bạn có thể bấm nút <em>&ldquo;Xóa hội thoại&rdquo;</em> bất cứ lúc nào để dọn nội dung
            trò chuyện trên trình duyệt, giữ nguyên mặc định xử lý cục bộ khi đính kèm ảnh hoặc ghi
            âm bổ sung (không gửi tới AI bên ngoài và không ghi cơ sở dữ liệu), đồng thời tự quyết
            định có bấm <em>&ldquo;Lưu hồ sơ bổ sung &amp; tải PDF&rdquo;</em> hay đóng góp ẩn danh
            vào Radar cộng đồng hay không.
          </li>
          <li>
            <strong className="font-semibold text-ink">Dùng thử bằng dữ liệu mẫu:</strong> Sử dụng
            các tình huống mẫu có sẵn trên trang chủ hoặc khu vực <em>Mô phỏng giao dịch</em> trên
            trang Giám sát gian lận mà không cần gửi dữ liệu cá nhân thật.
          </li>
          <li>
            <strong className="font-semibold text-ink">
              Giới hạn hiện tại đối với yêu cầu chỉnh sửa hoặc xóa hồ sơ:
            </strong>{" "}
            Hệ thống hiện chưa có chức năng quản lý dữ liệu dành cho người dùng để tự tra cứu danh
            sách hoặc tự xóa hồ sơ đã lưu. Quy trình tiếp nhận, xác minh và xử lý yêu cầu xóa dữ
            liệu cần được chủ dự án hoàn thiện và công bố kèm kênh liên hệ chính thức.
          </li>
        </ul>
      </DocSection>

      {/* 10. Thông tin liên hệ */}
      <DocSection id="thong-tin-lien-he" number="10" title="Thông tin liên hệ">
        <DocCallout tone="info" title="Thông tin đang chờ chủ dự án xác nhận và bổ sung">
          <p>
            Bản dự thảo này chưa công bố tên đơn vị vận hành, địa chỉ email phụ trách quyền riêng tư
            hay quy trình tiếp nhận yêu cầu xóa dữ liệu vì các thông tin này chưa được chủ dự án ấn
            định chính thức.
          </p>
          <p>
            Trước khi công bố chính sách chính thức cho người dùng rộng rãi, chủ dự án cần bổ sung:
            (1) Đơn vị hoặc cá nhân chịu trách nhiệm vận hành và bảo vệ dữ liệu, (2) Kênh liên hệ
            chính thức tiếp nhận thắc mắc về quyền riêng tư và yêu cầu xóa hồ sơ, (3) Thời hạn lưu
            trữ và quy trình phản hồi cụ thể.
          </p>
        </DocCallout>
      </DocSection>

      {/* 11. Cập nhật chính sách */}
      <DocSection id="cap-nhat-chinh-sach" number="11" title="Cập nhật chính sách">
        <p>
          Nội dung trang này sẽ được cập nhật khi VeriShield AI hoàn thiện thông tin đơn vị vận
          hành, bổ sung cơ chế xóa dữ liệu định kỳ, thêm chức năng quản lý dữ liệu cho người dùng
          hoặc thay đổi cách tích hợp dịch vụ bên thứ ba. Phiên bản mới nhất sẽ luôn được hiển thị
          công khai tại trang này.
        </p>
        <p className="pt-2 text-xs text-ink-muted">
          Để tìm hiểu sâu hơn về kiến trúc hệ thống, mô hình AI và các biện pháp bảo mật, vui lòng
          xem trang{" "}
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
