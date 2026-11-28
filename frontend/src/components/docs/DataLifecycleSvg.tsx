export function DataLifecycleSvg() {
  return (
    <figure className="overflow-x-auto rounded-xl border border-border-subtle bg-surface-deep/90 p-4">
      <svg
        viewBox="0 0 960 676"
        role="img"
        aria-labelledby="data-lifecycle-title data-lifecycle-desc"
        className="h-auto w-full min-w-[700px]"
      >
        <title id="data-lifecycle-title">Sơ đồ vòng đời dữ liệu trong VeriShield AI</title>
        <desc id="data-lifecycle-desc">
          Luồng xử lý dữ liệu từ khi người dùng gửi nội dung qua trang web, Trợ lý VeriShield hoặc
          Telegram Bot, phân tích cục bộ trên bộ nhớ máy chủ, lọc và che giấu thông tin nhạy cảm
          trong Trợ lý, xử lý mặc định hoàn toàn cục bộ cho bằng chứng bổ sung, đến bước che giấu số
          điện thoại, số tài khoản và lưu báo cáo kết quả có khóa phiên truy cập.
        </desc>

        <defs>
          <marker
            id="dl-arrow-slate"
            viewBox="0 0 10 10"
            refX="8.5"
            refY="5"
            markerWidth="6.5"
            markerHeight="6.5"
            orient="auto-start-reverse"
          >
            <path d="M 0 1.5 L 8.5 5 L 0 8.5 z" fill="#64748b" />
          </marker>
          <marker
            id="dl-arrow-amber"
            viewBox="0 0 10 10"
            refX="8.5"
            refY="5"
            markerWidth="6.5"
            markerHeight="6.5"
            orient="auto-start-reverse"
          >
            <path d="M 0 1.5 L 8.5 5 L 0 8.5 z" fill="#f59e0b" />
          </marker>
          <marker
            id="dl-arrow-cyan"
            viewBox="0 0 10 10"
            refX="8.5"
            refY="5"
            markerWidth="6.5"
            markerHeight="6.5"
            orient="auto-start-reverse"
          >
            <path d="M 0 1.5 L 8.5 5 L 0 8.5 z" fill="#38bdf8" />
          </marker>
          <marker
            id="dl-arrow-emerald"
            viewBox="0 0 10 10"
            refX="8.5"
            refY="5"
            markerWidth="6.5"
            markerHeight="6.5"
            orient="auto-start-reverse"
          >
            <path d="M 0 1.5 L 8.5 5 L 0 8.5 z" fill="#10b981" />
          </marker>
        </defs>

        {/* Stage 1: Ingestion */}
        <rect x="16" y="20" width="196" height="162" rx="10" fill="#121a29" stroke="#273449" strokeWidth="1.5" />
        <text x="30" y="42" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          01 · TIẾP NHẬN
        </text>
        <text x="30" y="62" fill="#f1f5f9" fontSize="12.5" fontWeight="700">
          Kênh bạn gửi nội dung
        </text>
        <text x="30" y="84" fill="#cbd5e1" fontSize="10.2">• Trang web (mã hóa HTTPS)</text>
        <text x="30" y="101" fill="#cbd5e1" fontSize="10.2">• Trợ lý VeriShield (2 giờ)</text>
        <text x="30" y="118" fill="#cbd5e1" fontSize="10.2">• Telegram Bot (PDF chat 1-1)</text>
        <text x="30" y="141" fill="#94a3b8" fontSize="10">Tin nhắn, đường dẫn, 4 ảnh</text>
        <text x="30" y="157" fill="#94a3b8" fontSize="10">&amp; 2 ghi âm (≤ 10 MB/tệp)</text>

        {/* Arrow 1 -> 2 */}
        <line x1="212" y1="101" x2="240" y2="101" stroke="#64748b" strokeWidth="1.6" markerEnd="url(#dl-arrow-slate)" />

        {/* Stage 2: Local Processing */}
        <rect x="246" y="20" width="234" height="162" rx="10" fill="#121a29" stroke="#364761" strokeWidth="1.5" />
        <text x="260" y="42" fill="#38bdf8" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          02 · XỬ LÝ TẠM THỜI
        </text>
        <text x="260" y="62" fill="#f1f5f9" fontSize="12.5" fontWeight="700">
          Phân tích nội bộ trên máy chủ
        </text>
        <text x="260" y="85" fill="#cbd5e1" fontSize="10.4">• Ảnh: đọc chữ, mã QR và dấu hiệu</text>
        <text x="260" y="101" fill="#94a3b8" fontSize="10.1">  chỉnh sửa trực tiếp trong bộ nhớ</text>
        <text x="260" y="122" fill="#cbd5e1" fontSize="10.4">• Văn bản: phân loại dấu hiệu lừa đảo</text>
        <text x="260" y="142" fill="#cbd5e1" fontSize="10.4">• Ghi âm: chuyển thành văn bản rồi</text>
        <text x="260" y="158" fill="#94a3b8" fontSize="10.1">  xóa ngay tệp âm thanh tạm</text>

        {/* Arrow 2 -> 3 */}
        <line x1="480" y1="101" x2="510" y2="101" stroke="#64748b" strokeWidth="1.6" markerEnd="url(#dl-arrow-slate)" />

        {/* Stage 3: Redaction & Hashing */}
        <rect x="516" y="20" width="204" height="162" rx="10" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.55" strokeWidth="1.5" />
        <text x="530" y="42" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          03 · CHE GIẤU &amp; BĂM
        </text>
        <text x="530" y="62" fill="#f1f5f9" fontSize="12.5" fontWeight="700">
          Lọc dữ liệu trước khi lưu
        </text>
        <text x="530" y="85" fill="#cbd5e1" fontSize="10.4">• Che số điện thoại (091****678)</text>
        <text x="530" y="102" fill="#cbd5e1" fontSize="10.4">• Che số tài khoản (19****01)</text>
        <text x="530" y="119" fill="#cbd5e1" fontSize="10.4">• Loại bỏ ảnh gốc và ghi âm gốc</text>
        <text x="530" y="136" fill="#cbd5e1" fontSize="10.4">• Ẩn dữ liệu gốc của mã VietQR</text>
        <text x="530" y="153" fill="#cbd5e1" fontSize="10.4">• Băm một chiều dấu hiệu rủi ro</text>

        {/* Arrow 3 -> 4 */}
        <line x1="720" y1="101" x2="748" y2="101" stroke="#f59e0b" strokeWidth="1.6" markerEnd="url(#dl-arrow-amber)" />

        {/* Stage 4: Storage */}
        <rect x="754" y="20" width="190" height="162" rx="10" fill="#0f1624" stroke="#364761" strokeWidth="1.5" />
        <text x="768" y="42" fill="#10b981" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          04 · LƯU TRỮ
        </text>
        <text x="768" y="62" fill="#f1f5f9" fontSize="12.5" fontWeight="700">
          Cơ sở dữ liệu ứng dụng
        </text>
        <text x="768" y="85" fill="#cbd5e1" fontSize="10.2">• Báo cáo đã che SĐT &amp; STK</text>
        <text x="768" y="102" fill="#cbd5e1" fontSize="10.2">• Dấu hiệu rủi ro (dạng băm)</text>
        <text x="768" y="119" fill="#cbd5e1" fontSize="10.2">• Quy tắc chặn tạm thời</text>
        <text x="768" y="136" fill="#cbd5e1" fontSize="10.2">• Khóa phiên truy cập (2 giờ)</text>
        <text x="768" y="156" fill="#94a3b8" fontSize="10">• Mô phỏng &amp; chat: không lưu</text>

        {/* Branch down from Stage 2 to External Services */}
        <line x1="330" y1="182" x2="330" y2="242" stroke="#38bdf8" strokeWidth="1.6" strokeDasharray="4 3" markerEnd="url(#dl-arrow-cyan)" />
        <path
          d="M 330 216 L 718 216 L 718 242"
          fill="none"
          stroke="#38bdf8"
          strokeWidth="1.5"
          strokeDasharray="4 3"
          markerEnd="url(#dl-arrow-cyan)"
        />
        <text x="24" y="212" fill="#38bdf8" fontSize="10.2" fontWeight="600">
          Chuyển dữ liệu ra bên ngoài (khi kích hoạt)
        </text>

        {/* Return path from External AI back to Stage 3 */}
        <path
          d="M 436 248 L 436 198 L 618 198 L 618 188"
          fill="none"
          stroke="#64748b"
          strokeWidth="1.5"
          strokeDasharray="4 3"
          markerEnd="url(#dl-arrow-slate)"
        />

        {/* External Box Left: Third-party AI */}
        <rect x="16" y="248" width="454" height="190" rx="10" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.45" strokeWidth="1.5" />
        <text x="32" y="270" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          DỊCH VỤ BÊN NGOÀI A · NHÀ CUNG CẤP AI (TÙY CHỌN)
        </text>
        <text x="32" y="291" fill="#f1f5f9" fontSize="12.2" fontWeight="700">
          Dịch vụ AI phân tích ngữ cảnh, đọc chữ dự phòng &amp; Trợ lý
        </text>
        <text x="32" y="313" fill="#cbd5e1" fontSize="10.3">
          • Lượt phân tích chính: có thể nhận văn bản, ảnh và ghi âm nguyên bản
        </text>
        <text x="32" y="329" fill="#cbd5e1" fontSize="10.3">
          TRƯỚC bước che giấu dùng cho lưu trữ (khi dịch vụ AI được bật).
        </text>
        <text x="32" y="351" fill="#cbd5e1" fontSize="10.3">
          • Trợ lý VeriShield: chỉ nhận văn bản đã lọc &amp; che giấu dữ liệu.
        </text>
        <text x="32" y="372" fill="#cbd5e1" fontSize="10.3">
          • Bằng chứng bổ sung trong Trợ lý: mặc định KHÔNG gửi ảnh/âm thanh.
        </text>
        <text x="32" y="396" fill="#94a3b8" fontSize="10.1">
          Nếu máy chủ không kết nối AI bên ngoài: hệ thống xử lý hoàn toàn cục bộ.
        </text>
        <text x="32" y="418" fill="#f59e0b" fontSize="10.1">
          Khuyến nghị: Che bớt họ tên, giấy tờ riêng tư không cần thiết trước khi gửi.
        </text>

        {/* External Box Right: Public URLs & Telegram */}
        <rect x="490" y="248" width="454" height="190" rx="10" fill="#121a29" stroke="#38bdf8" strokeOpacity="0.45" strokeWidth="1.5" />
        <text x="506" y="270" fill="#38bdf8" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          DỊCH VỤ BÊN NGOÀI B · TRANG WEB ĐÍCH &amp; TELEGRAM
        </text>
        <text x="506" y="291" fill="#f1f5f9" fontSize="12.2" fontWeight="700">
          Kiểm tra đường dẫn công khai &amp; kênh Telegram Bot
        </text>
        <text x="506" y="313" fill="#cbd5e1" fontSize="10.3">
          • Chỉ truy cập kiểm tra đường dẫn công khai bạn trực tiếp nhập, từ mã QR
        </text>
        <text x="506" y="329" fill="#cbd5e1" fontSize="10.3">
          ở lượt chính hoặc yêu cầu Trợ lý kiểm tra; chặn hoàn toàn mạng nội bộ.
        </text>
        <text x="506" y="351" fill="#cbd5e1" fontSize="10.3">
          • Không tự mở đường dẫn chỉ xuất hiện trong chữ đọc từ ảnh chụp.
        </text>
        <text x="506" y="375" fill="#cbd5e1" fontSize="10.3">
          • Telegram Bot: báo cáo PDF chỉ gửi trực tiếp trong chat riêng 1-1 với
        </text>
        <text x="506" y="391" fill="#cbd5e1" fontSize="10.3">
          đúng người gửi (không đường dẫn công khai, không gửi trong nhóm).
        </text>
        <text x="506" y="416" fill="#94a3b8" fontSize="10.1">
          Trao đổi trên Telegram tuân theo chính sách quyền riêng tư của Telegram.
        </text>

        {/* Connector from Assistant Box Left UP to External AI Box A */}
        <line
          x1="210"
          y1="480"
          x2="210"
          y2="444"
          stroke="#10b981"
          strokeWidth="1.6"
          strokeDasharray="4 3"
          markerEnd="url(#dl-arrow-emerald)"
        />
        <text x="222" y="465" fill="#10b981" fontSize="10.1" fontWeight="600">
          Chỉ gửi văn bản đã lọc &amp; che giấu
        </text>

        <text x="506" y="465" fill="#10b981" fontSize="10.1" fontWeight="600">
          Mặc định cục bộ · Chỉ gửi AI ngoài hoặc lưu khi bạn đồng ý
        </text>

        {/* Row 3 Left: VeriShield Assistant */}
        <rect x="16" y="480" width="454" height="180" rx="10" fill="#0f1624" stroke="#10b981" strokeOpacity="0.55" strokeWidth="1.5" />
        <text x="32" y="502" fill="#10b981" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TRỢ LÝ VERISHIELD · HỎI ĐÁP PHÒNG CHỐNG LỪA ĐẢO
        </text>
        <text x="32" y="523" fill="#f1f5f9" fontSize="12.2" fontWeight="700">
          Lọc thông tin nhạy cảm &amp; lưu tạm trên phiên trình duyệt
        </text>
        <text x="32" y="546" fill="#cbd5e1" fontSize="10.3">
          • Hoạt động theo khóa phiên hồ sơ (hết hạn sau 2 giờ, tắt bộ nhớ đệm)
        </text>
        <text x="32" y="567" fill="#cbd5e1" fontSize="10.2">
          • Lọc &amp; che SĐT, STK, CCCD, OTP, mật khẩu, email, đường dẫn &amp; VietQR
        </text>
        <text x="32" y="588" fill="#cbd5e1" fontSize="10.3">
          • Lịch sử chỉ giữ trong phiên trình duyệt hiện tại (nút &ldquo;Xóa hội thoại&rdquo;)
        </text>
        <text x="32" y="611" fill="#f59e0b" fontSize="10.2">
          • Biên lai: luôn kiểm tra số dư thực tế / loa báo nhận tiền trước khi giao
        </text>
        <text x="32" y="635" fill="#94a3b8" fontSize="10">
          Xóa hội thoại chỉ dọn trình duyệt, không thu hồi lượt đã gửi AI ngoài.
        </text>

        {/* Arrow from Assistant to Ephemeral Evidence */}
        <line x1="470" y1="570" x2="484" y2="570" stroke="#64748b" strokeWidth="1.6" markerEnd="url(#dl-arrow-slate)" />

        {/* Row 3 Right: Ephemeral Local-Only Additional Evidence */}
        <rect x="490" y="480" width="454" height="180" rx="10" fill="#0f1624" stroke="#38bdf8" strokeOpacity="0.55" strokeWidth="1.5" />
        <text x="506" y="502" fill="#38bdf8" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          BẰNG CHỨNG BỔ SUNG TRONG TRỢ LÝ · MẶC ĐỊNH CỤC BỘ
        </text>
        <text x="506" y="523" fill="#f1f5f9" fontSize="12.2" fontWeight="700">
          Xử lý tạm thời trên máy chủ (không gửi AI ngoài, không lưu)
        </text>
        <text x="506" y="546" fill="#cbd5e1" fontSize="10.3">
          • Đính kèm tối đa 1 ảnh hoặc 1 tệp ghi âm (≤ 10 MB) trong khung Trợ lý
        </text>
        <text x="506" y="567" fill="#cbd5e1" fontSize="10.3">
          • Mặc định 100% cục bộ: không gửi ảnh/âm thanh ra ngoài, không phát
        </text>
        <text x="506" y="583" fill="#cbd5e1" fontSize="10.3">
          yêu cầu mạng từ QR/ghi âm và không ghi DB hay Giám sát gian lận
        </text>
        <text x="506" y="606" fill="#cbd5e1" fontSize="10.3">
          • Chỉ giữ tạm kết quả đã che giấu trong bộ nhớ máy chủ tối đa 15 phút
        </text>
        <text x="506" y="630" fill="#10b981" fontSize="10.2">
          • Gửi AI ngoài hoặc lưu hồ sơ &amp; đóng góp dấu hiệu chỉ khi bạn chọn
        </text>
      </svg>
      <figcaption className="mt-3 border-t border-border-subtle/60 pt-2.5 text-[11px] leading-relaxed text-ink-muted">
        Hình ảnh minh họa phân tích của phiên kiểm tra hiện tại (như ảnh phân tích dấu hiệu chỉnh
        sửa hoặc ảnh xem trước trang web đáng ngờ) chỉ hiển thị tạm thời trên màn hình kết quả và
        không được lưu vào cơ sở dữ liệu ứng dụng. Hội thoại Trợ lý VeriShield chỉ giữ tạm trên thẻ
        trình duyệt, còn bằng chứng bổ sung mặc định xử lý hoàn toàn cục bộ và tự xóa khỏi bộ nhớ
        tạm sau tối đa 15 phút nếu bạn không bấm lưu.
      </figcaption>
    </figure>
  );
}
