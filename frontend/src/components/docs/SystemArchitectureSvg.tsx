export function SystemArchitectureSvg() {
  return (
    <figure className="overflow-x-auto rounded-xl border border-border-subtle bg-surface-deep/90 p-4">
      <svg
        viewBox="0 0 960 760"
        role="img"
        aria-labelledby="sys-arch-title sys-arch-desc"
        className="h-auto w-full min-w-[700px]"
      >
        <title id="sys-arch-title">Kiến trúc tổng thể hệ thống VeriShield AI</title>
        <desc id="sys-arch-desc">
          Sơ đồ kiến trúc gồm kênh giao tiếp Web Next.js (kèm Trợ lý VeriShield) và Telegram Bot
          (PDF chỉ trong chat 1-1), Reverse Proxy Caddy 2 xử lý kết nối TLS, tầng API FastAPI với
          khóa phiên HMAC 128-bit, quy trình phân tích ba tầng, vòng lặp giám sát gian lận khép kín
          trên SQLite WAL và phân hệ Trợ lý VeriShield (Hybrid E5 và BM25 RAG, kho thực thể theo
          tham chiếu, công cụ chỉ đọc, bằng chứng bổ sung cục bộ tạm thời và cổng kiểm duyệt đầu ra
          3 tầng).
        </desc>

        <defs>
          <marker
            id="sa-arrow-slate"
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
            id="sa-arrow-cyan"
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
            id="sa-arrow-amber"
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
            id="sa-arrow-emerald"
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

        {/* Row 1 Left: Client Channels */}
        <rect x="20" y="14" width="212" height="48" rx="9" fill="#121a29" stroke="#364761" strokeWidth="1.4" />
        <text x="34" y="34" fill="#f1f5f9" fontSize="12" fontWeight="700">Ứng dụng Web (Next.js 15)</text>
        <text x="34" y="51" fill="#94a3b8" fontSize="10.1">Kiểm tra (/) · Trợ lý · /radar</text>

        <rect x="20" y="70" width="212" height="48" rx="9" fill="#121a29" stroke="#364761" strokeWidth="1.4" />
        <text x="34" y="90" fill="#f1f5f9" fontSize="12" fontWeight="700">Telegram Bot (tùy chọn)</text>
        <text x="34" y="107" fill="#94a3b8" fontSize="10.1">Webhook bí mật · PDF chat 1-1</text>

        {/* Merge bus from clients to Reverse Proxy */}
        <path
          d="M 232 38 L 260 38 L 260 94 L 232 94"
          fill="none"
          stroke="#64748b"
          strokeWidth="1.5"
        />
        <line x1="260" y1="66" x2="294" y2="66" stroke="#64748b" strokeWidth="1.5" markerEnd="url(#sa-arrow-slate)" />

        {/* Row 1 Middle: Caddy Reverse Proxy */}
        <rect x="300" y="26" width="276" height="80" rx="10" fill="#121a29" stroke="#38bdf8" strokeOpacity="0.6" strokeWidth="1.5" />
        <text x="316" y="48" fill="#38bdf8" fontSize="10" fontWeight="700" fontFamily="var(--font-mono), monospace">
          REVERSE PROXY (EDGE)
        </text>
        <text x="316" y="68" fill="#f1f5f9" fontSize="12.5" fontWeight="700">Caddy 2</text>
        <text x="316" y="88" fill="#94a3b8" fontSize="10.5">TLS termination · HSTS · CSP · Giới hạn tải</text>

        <line x1="576" y1="66" x2="614" y2="66" stroke="#38bdf8" strokeWidth="1.5" markerEnd="url(#sa-arrow-cyan)" />

        {/* Row 1 Right: FastAPI Gateway */}
        <rect x="620" y="26" width="320" height="80" rx="10" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.6" strokeWidth="1.5" />
        <text x="636" y="48" fill="#f59e0b" fontSize="10" fontWeight="700" fontFamily="var(--font-mono), monospace">
          API GATEWAY &amp; MIDDLEWARE
        </text>
        <text x="636" y="68" fill="#f1f5f9" fontSize="12.5" fontWeight="700">FastAPI + ASGI Security Middleware</text>
        <text x="636" y="88" fill="#94a3b8" fontSize="10.3">Khóa phiên HMAC 128-bit · Rate limit · SSE</text>

        {/* Connector down to Pipeline */}
        <line x1="780" y1="106" x2="780" y2="140" stroke="#f59e0b" strokeWidth="1.6" markerEnd="url(#sa-arrow-amber)" />

        {/* Main Pipeline Container */}
        <rect x="20" y="146" width="920" height="240" rx="12" fill="#0f1624" stroke="#273449" strokeWidth="1.5" />
        <text x="36" y="169" fill="#cbd5e1" fontSize="10.8" fontWeight="700" fontFamily="var(--font-mono), monospace">
          QUY TRÌNH PHÂN TÍCH (4 GIAI ĐOẠN TUẦN TỰ · PHÁT TIẾN ĐỘ SSE)
        </text>

        {/* Tier 1 Box */}
        <rect x="36" y="184" width="332" height="186" rx="10" fill="#121a29" stroke="#38bdf8" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="50" y="206" fill="#38bdf8" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TẦNG 1 · PHÂN TÍCH CỤC BỘ (GIAI ĐOẠN 1–3)
        </text>
        <text x="50" y="227" fill="#cbd5e1" fontSize="10.5">• Kiểm tra định dạng tệp, magic bytes &amp; kích thước</text>
        <text x="50" y="245" fill="#cbd5e1" fontSize="10.5">• Phân tích ảnh (ELA, EXIF/XMP, dHash) &amp; đọc QR</text>
        <text x="50" y="263" fill="#cbd5e1" fontSize="10.5">• Kiểm định VietQR EMVCo TLV &amp; CRC-16</text>
        <text x="50" y="281" fill="#cbd5e1" fontSize="10.5">• Công cụ OCR: RapidOCR PP-OCRv5 Latin (ONNX)</text>
        <text x="50" y="299" fill="#cbd5e1" fontSize="10.5">• Chuyển giọng nói (faster-whisper) &amp; Guardrails</text>
        <text x="50" y="317" fill="#cbd5e1" fontSize="10.5">• Phân tích URL &amp; trình duyệt cách ly (chống SSRF)</text>
        <text x="50" y="335" fill="#cbd5e1" fontSize="10.5">• Mô hình E5-Small INT8 ONNX &amp; truy xuất tri thức</text>
        <text x="50" y="353" fill="#94a3b8" fontSize="10.2">• Kiểm tra logic biên lai &amp; chống gửi lại ảnh cũ</text>

        {/* Arrow T1 -> T2 */}
        <line x1="368" y1="277" x2="396" y2="277" stroke="#64748b" strokeWidth="1.6" markerEnd="url(#sa-arrow-slate)" />

        {/* Tier 2 Box */}
        <rect x="402" y="184" width="240" height="186" rx="10" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="416" y="206" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TẦNG 2 · AI ĐA PHƯƠNG THỨC
        </text>
        <text x="416" y="227" fill="#cbd5e1" fontSize="10.5">• Chạy ở đầu Giai đoạn 4 (tùy chọn)</text>
        <text x="416" y="245" fill="#cbd5e1" fontSize="10.5">• Hỗ trợ Google Gemini API hoặc</text>
        <text x="416" y="261" fill="#cbd5e1" fontSize="10.5">  cổng API tương thích OpenAI</text>
        <text x="416" y="282" fill="#cbd5e1" fontSize="10.5">• Cách ly dữ liệu chưa tin cậy</text>
        <text x="416" y="298" fill="#cbd5e1" fontSize="10.5">  và ràng buộc cấu trúc JSON</text>
        <text x="416" y="319" fill="#cbd5e1" fontSize="10.5">• Thử lại có giới hạn &amp; chuyển khóa</text>
        <text x="416" y="340" fill="#10b981" fontSize="10.2">• Chế độ xử lý dự phòng: tiếp tục</text>
        <text x="416" y="355" fill="#94a3b8" fontSize="10.2">  bằng Tầng 1 nếu AI gián đoạn</text>

        {/* Arrow T2 -> T3 */}
        <line x1="642" y1="277" x2="670" y2="277" stroke="#64748b" strokeWidth="1.6" markerEnd="url(#sa-arrow-slate)" />

        {/* Tier 3 Box */}
        <rect x="676" y="184" width="248" height="186" rx="10" fill="#121a29" stroke="#10b981" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="690" y="206" fill="#10b981" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TẦNG 3 · HIỆU CHUẨN &amp; ỨNG PHÓ
        </text>
        <text x="690" y="227" fill="#cbd5e1" fontSize="10.5">• Hoàn tất Giai đoạn 4 của pipeline</text>
        <text x="690" y="246" fill="#cbd5e1" fontSize="10.5">• Hợp nhất 3 nguồn tín hiệu &amp; áp</text>
        <text x="690" y="262" fill="#cbd5e1" fontSize="10.5">  ngưỡng điểm rủi ro tối thiểu</text>
        <text x="690" y="283" fill="#cbd5e1" fontSize="10.5">• Khuyến nghị ứng phó, tạm dừng</text>
        <text x="690" y="299" fill="#cbd5e1" fontSize="10.5">  30 giây &amp; xác minh biên lai</text>
        <text x="690" y="320" fill="#cbd5e1" fontSize="10.5">• Che giấu SĐT/STK trước khi lưu</text>
        <text x="690" y="339" fill="#cbd5e1" fontSize="10.5">• Xuất báo cáo PDF tiếng Việt</text>

        {/* Bottom Layer: Storage & Closed-Loop Radar */}
        <line x1="800" y1="370" x2="800" y2="424" stroke="#10b981" strokeWidth="1.6" markerEnd="url(#sa-arrow-emerald)" />

        <rect x="504" y="430" width="436" height="94" rx="10" fill="#121a29" stroke="#10b981" strokeOpacity="0.55" strokeWidth="1.5" />
        <text x="520" y="452" fill="#10b981" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          LƯU TRỮ DỮ LIỆU · SQLITE 3 (WAL MODE)
        </text>
        <text x="520" y="473" fill="#cbd5e1" fontSize="10.4">
          • Hồ sơ đã che SĐT/STK (khóa phiên HMAC 2 giờ) · IOC băm một chiều
        </text>
        <text x="520" y="491" fill="#94a3b8" fontSize="10.2">
          • Nhóm chiến dịch · Quy tắc chặn tạm thời (TTL) · Mã đặc trưng biên lai
        </text>
        <text x="520" y="509" fill="#94a3b8" fontSize="10.2">
          • Nhật ký kiểm toán quản trị · Lịch sử chống lặp webhook Telegram
        </text>

        {/* Closed-loop arrow from Storage to Radar */}
        <line x1="504" y1="477" x2="462" y2="477" stroke="#38bdf8" strokeWidth="1.6" markerEnd="url(#sa-arrow-cyan)" />

        <rect x="20" y="430" width="436" height="94" rx="10" fill="#121a29" stroke="#38bdf8" strokeOpacity="0.55" strokeWidth="1.5" />
        <text x="36" y="452" fill="#38bdf8" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TRUNG TÂM GIÁM SÁT GIAN LẬN (/radar)
        </text>
        <text x="36" y="473" fill="#cbd5e1" fontSize="10.5">
          • Mạng lưới liên kết theo cụm chiến dịch &amp; đối chiếu dấu hiệu nghi vấn
        </text>
        <text x="36" y="491" fill="#cbd5e1" fontSize="10.5">
          • Áp dụng quy tắc chặn xác nhận từng đối tượng (TTL &amp; chống chặn nhầm)
        </text>
        <text x="36" y="509" fill="#94a3b8" fontSize="10.2">
          • Chế độ mô phỏng giao dịch tách biệt, không ghi vào cơ sở dữ liệu
        </text>

        {/* Feedback loop back up to Tier 1 */}
        <path
          d="M 180 430 L 180 376"
          fill="none"
          stroke="#f59e0b"
          strokeWidth="1.6"
          strokeDasharray="4 3"
          markerEnd="url(#sa-arrow-amber)"
        />
        <text x="192" y="411" fill="#f59e0b" fontSize="10.5" fontWeight="600">
          Đối chiếu quy tắc chặn đang hiệu lực ở lượt kiểm tra mới
        </text>

        {/* Connectors down to VeriShield Assistant Row 4 */}
        <line
          x1="180"
          y1="524"
          x2="180"
          y2="560"
          stroke="#38bdf8"
          strokeWidth="1.5"
          strokeDasharray="4 3"
          markerEnd="url(#sa-arrow-cyan)"
        />
        <text x="192" y="547" fill="#38bdf8" fontSize="10.2" fontWeight="600">
          Tra cứu uy tín IOC chỉ đọc (0 ghi /radar)
        </text>

        <line
          x1="620"
          y1="524"
          x2="620"
          y2="560"
          stroke="#10b981"
          strokeWidth="1.5"
          strokeDasharray="4 3"
          markerEnd="url(#sa-arrow-emerald)"
        />
        <text x="632" y="547" fill="#10b981" fontSize="10.2" fontWeight="600">
          Đọc hồ sơ (khóa HMAC) · Lưu tường minh hồ sơ con
        </text>

        {/* Row 4: VeriShield AI Assistant Container */}
        <rect x="20" y="566" width="920" height="182" rx="12" fill="#0f1624" stroke="#38bdf8" strokeOpacity="0.45" strokeWidth="1.5" />
        <text x="36" y="589" fill="#38bdf8" fontSize="10.6" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TRỢ LÝ VERISHIELD · HỎI ĐÁP NGỮ CẢNH &amp; BẰNG CHỨNG BỔ SUNG (PHÁT LUỒNG SSE)
        </text>

        {/* Assistant Box 1: Hybrid E5+BM25 RAG */}
        <rect x="36" y="602" width="282" height="132" rx="10" fill="#121a29" stroke="#38bdf8" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="50" y="623" fill="#38bdf8" fontSize="10" fontWeight="700" fontFamily="var(--font-mono), monospace">
          HYBRID RAG &amp; SCOPE GATE
        </text>
        <text x="50" y="644" fill="#cbd5e1" fontSize="10.2">• Tái sử dụng 1 phiên E5 INT8 ONNX</text>
        <text x="50" y="662" fill="#cbd5e1" fontSize="10.2">• Lưu E_raw · Mean-Centering (RAM)</text>
        <text x="50" y="680" fill="#cbd5e1" fontSize="10.2">• BM25 tiếng Việt không dấu + RRF</text>
        <text x="50" y="698" fill="#cbd5e1" fontSize="10.2">• 121 đoạn KB · Dual-Signal Gate</text>
        <text x="50" y="716" fill="#94a3b8" fontSize="10">• Không LangChain / Vector DB rời</text>

        {/* Arrow A1 -> A2 */}
        <line x1="318" y1="668" x2="342" y2="668" stroke="#64748b" strokeWidth="1.5" markerEnd="url(#sa-arrow-slate)" />

        {/* Assistant Box 2: Vault, Ref-Only Tools & Local Ephemeral Evidence */}
        <rect x="348" y="602" width="280" height="132" rx="10" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="362" y="623" fill="#f59e0b" fontSize="10" fontWeight="700" fontFamily="var(--font-mono), monospace">
          VAULT, CÔNG CỤ &amp; BẰNG CHỨNG
        </text>
        <text x="362" y="644" fill="#cbd5e1" fontSize="10.2">• RequestEntityVault &amp; Chốt lọc PII</text>
        <text x="362" y="662" fill="#cbd5e1" fontSize="10.2">• Công cụ chỉ đọc theo ref_id:</text>
        <text x="362" y="678" fill="#94a3b8" fontSize="10">  URL chống SSRF (không headless),</text>
        <text x="362" y="694" fill="#94a3b8" fontSize="10">  VietQR EMVCo &amp; tra cứu IOC</text>
        <text x="362" y="714" fill="#10b981" fontSize="10">• Bằng chứng bổ sung cục bộ (15p)</text>

        {/* Arrow A2 -> A3 */}
        <line x1="628" y1="668" x2="652" y2="668" stroke="#64748b" strokeWidth="1.5" markerEnd="url(#sa-arrow-slate)" />

        {/* Assistant Box 3: 3-Tier Output Safety Gate */}
        <rect x="658" y="602" width="266" height="132" rx="10" fill="#121a29" stroke="#10b981" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="672" y="623" fill="#10b981" fontSize="10" fontWeight="700" fontFamily="var(--font-mono), monospace">
          CỔNG KIỂM DUYỆT ĐẦU RA 3 TẦNG
        </text>
        <text x="672" y="644" fill="#cbd5e1" fontSize="10.2">• Lọc luồng &lt;think&gt; trước khi phát</text>
        <text x="672" y="662" fill="#cbd5e1" fontSize="10.2">• Tầng 0: Xác định biên lai tức thì</text>
        <text x="672" y="680" fill="#cbd5e1" fontSize="10.2">• Tầng 1: Đệm toàn văn (fail-closed)</text>
        <text x="672" y="698" fill="#cbd5e1" fontSize="10.2">• Tầng 2: Kiểm duyệt từng câu</text>
        <text x="672" y="716" fill="#94a3b8" fontSize="10">• Dự phòng RAG cục bộ khi AI lỗi</text>
      </svg>
      <figcaption className="mt-3 border-t border-border-subtle/60 pt-2.5 text-[11px] leading-relaxed text-ink-muted">
        Sơ đồ tổng hợp mối liên hệ giữa 3 tầng trách nhiệm (Tầng 1 cục bộ, Tầng 2 AI đa phương thức,
        Tầng 3 hiệu chuẩn và ứng phó), 4 giai đoạn thực thi tuần tự, vòng lặp phản hồi với Trung
        tâm giám sát gian lận và phân hệ Trợ lý VeriShield (RAG lai E5 + BM25, công cụ chỉ đọc theo
        tham chiếu, bằng chứng bổ sung cục bộ tạm thời và cổng kiểm duyệt đầu ra 3 tầng).
      </figcaption>
    </figure>
  );
}
