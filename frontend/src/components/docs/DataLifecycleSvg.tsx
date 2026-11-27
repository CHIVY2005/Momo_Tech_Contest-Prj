export function DataLifecycleSvg() {
  return (
    <figure className="overflow-x-auto rounded-xl border border-border-subtle bg-surface-deep/90 p-4">
      <svg
        viewBox="0 0 960 474"
        role="img"
        aria-labelledby="data-lifecycle-title data-lifecycle-desc"
        className="h-auto w-full min-w-[700px]"
      >
        <title id="data-lifecycle-title">Sơ đồ vòng đời dữ liệu thực tế trong VeriShield AI</title>
        <desc id="data-lifecycle-desc">
          Luồng xử lý từ tiếp nhận dữ liệu đầu vào qua Web hoặc Telegram, kiểm tra cục bộ trong bộ
          nhớ, gửi tùy chọn tới dịch vụ AI đa phương thức hoặc kiểm tra đường dẫn công khai, che
          giấu và băm thông tin định danh trước khi lưu vào cơ sở dữ liệu SQLite WAL.
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
        </defs>

        {/* Stage 1: Ingestion */}
        <rect x="16" y="20" width="194" height="164" rx="10" fill="#121a29" stroke="#273449" strokeWidth="1.5" />
        <text x="30" y="43" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          01 · TIẾP NHẬN
        </text>
        <text x="30" y="64" fill="#f1f5f9" fontSize="12.5" fontWeight="700">
          Kênh gửi dữ liệu
        </text>
        <text x="30" y="87" fill="#cbd5e1" fontSize="10.5">• Web UI (HTTPS / TLS)</text>
        <text x="30" y="105" fill="#cbd5e1" fontSize="10.5">• Telegram Bot (tùy chọn)</text>
        <text x="30" y="128" fill="#94a3b8" fontSize="10.2">Văn bản, URL, tối đa 4 ảnh</text>
        <text x="30" y="145" fill="#94a3b8" fontSize="10.2">và 2 ghi âm (≤ 10 MB/tệp,</text>
        <text x="30" y="162" fill="#94a3b8" fontSize="10.2">tổng đính kèm ≤ 20 MB)</text>

        {/* Arrow 1 -> 2 */}
        <line x1="210" y1="102" x2="240" y2="102" stroke="#64748b" strokeWidth="1.6" markerEnd="url(#dl-arrow-slate)" />

        {/* Stage 2: Local In-Memory Processing */}
        <rect x="246" y="20" width="234" height="164" rx="10" fill="#121a29" stroke="#364761" strokeWidth="1.5" />
        <text x="260" y="43" fill="#38bdf8" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          02 · XỬ LÝ CỤC BỘ (RAM)
        </text>
        <text x="260" y="64" fill="#f1f5f9" fontSize="12.5" fontWeight="700">
          Phân tích Tầng 1 nội bộ
        </text>
        <text x="260" y="87" fill="#cbd5e1" fontSize="10.5">• Ảnh: xử lý hoàn toàn trên RAM</text>
        <text x="260" y="104" fill="#94a3b8" fontSize="10.2">  (ELA, EXIF, dHash, QR, RapidOCR)</text>
        <text x="260" y="124" fill="#cbd5e1" fontSize="10.5">• Văn bản: E5 ONNX &amp; Guardrails</text>
        <text x="260" y="144" fill="#cbd5e1" fontSize="10.5">• Âm thanh: tạo tệp tạm OS cho</text>
        <text x="260" y="161" fill="#94a3b8" fontSize="10.2">  Whisper, xóa ngay trong finally</text>

        {/* Arrow 2 -> 3 (Redaction) */}
        <line x1="480" y1="102" x2="510" y2="102" stroke="#64748b" strokeWidth="1.6" markerEnd="url(#dl-arrow-slate)" />

        {/* Stage 3: Redaction & Hashing */}
        <rect x="516" y="20" width="204" height="164" rx="10" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.55" strokeWidth="1.5" />
        <text x="530" y="43" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          03 · CHE GIẤU &amp; BĂM
        </text>
        <text x="530" y="64" fill="#f1f5f9" fontSize="12.5" fontWeight="700">
          Chuẩn hóa trước khi lưu
        </text>
        <text x="530" y="87" fill="#cbd5e1" fontSize="10.5">• Che SĐT (091****678)</text>
        <text x="530" y="104" fill="#cbd5e1" fontSize="10.5">• Che STK (19****01)</text>
        <text x="530" y="121" fill="#cbd5e1" fontSize="10.5">• Bỏ ảnh/ghi âm gốc &amp; blob</text>
        <text x="530" y="138" fill="#cbd5e1" fontSize="10.5">• Ẩn chuỗi VietQR thô</text>
        <text x="530" y="155" fill="#cbd5e1" fontSize="10.5">• Băm IOC một chiều (HMAC)</text>

        {/* Arrow 3 -> 4 (Storage) */}
        <line x1="720" y1="102" x2="748" y2="102" stroke="#f59e0b" strokeWidth="1.6" markerEnd="url(#dl-arrow-amber)" />

        {/* Stage 4: SQLite WAL Storage */}
        <rect x="754" y="20" width="190" height="164" rx="10" fill="#0f1624" stroke="#364761" strokeWidth="1.5" />
        <text x="768" y="43" fill="#10b981" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          04 · LƯU TRỮ (SQLite)
        </text>
        <text x="768" y="64" fill="#f1f5f9" fontSize="12.5" fontWeight="700">
          Cơ sở dữ liệu WAL
        </text>
        <text x="768" y="87" fill="#cbd5e1" fontSize="10.5">• cases (đã che SĐT/STK)</text>
        <text x="768" y="104" fill="#cbd5e1" fontSize="10.5">• Đồ thị IOC (băm + che)</text>
        <text x="768" y="121" fill="#cbd5e1" fontSize="10.5">• block_rules (TTL 30p)</text>
        <text x="768" y="138" fill="#cbd5e1" fontSize="10.5">• audit_logs (tối đa 200)</text>
        <text x="768" y="158" fill="#94a3b8" fontSize="10.2">• Mô phỏng: không lưu DB</text>

        {/* Clean non-overlapping branch down from Stage 2 to External Boxes */}
        <line x1="330" y1="184" x2="330" y2="246" stroke="#38bdf8" strokeWidth="1.6" strokeDasharray="4 3" markerEnd="url(#dl-arrow-cyan)" />
        <path
          d="M 330 220 L 718 220 L 718 246"
          fill="none"
          stroke="#38bdf8"
          strokeWidth="1.5"
          strokeDasharray="4 3"
          markerEnd="url(#dl-arrow-cyan)"
        />
        <text x="48" y="214" fill="#38bdf8" fontSize="10.2" fontWeight="600">
          Gọi ngoài biên khi được cấu hình / kích hoạt
        </text>

        {/* Clean return path from External A top-right into Stage 3 bottom (no overlap) */}
        <path
          d="M 436 252 L 436 202 L 618 202 L 618 190"
          fill="none"
          stroke="#64748b"
          strokeWidth="1.5"
          strokeDasharray="4 3"
          markerEnd="url(#dl-arrow-slate)"
        />

        {/* External Box Left: Third-party AI */}
        <rect x="16" y="252" width="454" height="204" rx="10" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.45" strokeWidth="1.5" />
        <text x="32" y="275" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          NGOÀI BIÊN A · DỊCH VỤ AI ĐA PHƯƠNG THỨC (TÙY CHỌN)
        </text>
        <text x="32" y="296" fill="#f1f5f9" fontSize="12.2" fontWeight="700">
          Gemini API / Cổng tương thích OpenAI
        </text>
        <text x="32" y="318" fill="#cbd5e1" fontSize="10.5">
          • Nhận văn bản gốc + kết quả OCR (bọc thẻ cách ly), tối đa 4 ảnh
        </text>
        <text x="32" y="335" fill="#cbd5e1" fontSize="10.5">
          và tệp ghi âm (≤ 10 MB) TRƯỚC bước che giấu lưu trữ.
        </text>
        <text x="32" y="356" fill="#cbd5e1" fontSize="10.5">
          • OCR dự phòng (tối đa 2 ảnh/lượt) chỉ gọi khi OCR cục bộ lỗi,
        </text>
        <text x="32" y="373" fill="#cbd5e1" fontSize="10.5">
          quá giờ hoặc độ tin cậy thấp (&lt; 0,45).
        </text>
        <text x="32" y="396" fill="#94a3b8" fontSize="10.2">
          Khi chưa cấu hình khóa API hoặc lỗi: chạy hoàn toàn ở Tầng 1 nội bộ.
        </text>
        <text x="32" y="418" fill="#f59e0b" fontSize="10.2">
          Khuyến nghị: Che bớt dữ liệu nhạy cảm không cần thiết trước khi gửi
        </text>
        <text x="32" y="434" fill="#f59e0b" fontSize="10.2">
          nếu không muốn dữ liệu đi qua nhà cung cấp AI bên thứ ba.
        </text>

        {/* External Box Right: Outbound URL & Telegram */}
        <rect x="490" y="252" width="454" height="204" rx="10" fill="#121a29" stroke="#38bdf8" strokeOpacity="0.45" strokeWidth="1.5" />
        <text x="506" y="275" fill="#38bdf8" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          NGOÀI BIÊN B · KIỂM TRA URL CÔNG KHAI &amp; TELEGRAM
        </text>
        <text x="506" y="296" fill="#f1f5f9" fontSize="12.2" fontWeight="700">
          Truy vấn mạng kiểm soát SSRF &amp; Telegram Bot API
        </text>
        <text x="506" y="318" fill="#cbd5e1" fontSize="10.5">
          • Chỉ truy vấn URL người dùng nhập trực tiếp hoặc giải mã từ mã QR.
        </text>
        <text x="506" y="339" fill="#cbd5e1" fontSize="10.5">
          • Tuyệt đối KHÔNG tự truy cập URL chỉ trích xuất từ văn bản OCR.
        </text>
        <text x="506" y="360" fill="#cbd5e1" fontSize="10.5">
          • Chromium cách ly chỉ mở trang đáng ngờ (điểm ≥ 40), chặn IP nội bộ.
        </text>
        <text x="506" y="384" fill="#cbd5e1" fontSize="10.5">
          • Nếu dùng Telegram Bot: dữ liệu đi qua máy chủ Telegram và bảng
        </text>
        <text x="506" y="401" fill="#94a3b8" fontSize="10.2">
          telegram_updates lưu update_id + phản hồi đã che để chống xử lý lặp.
        </text>
      </svg>
      <figcaption className="mt-3 border-t border-border-subtle/60 pt-2.5 text-[11px] leading-relaxed text-ink-muted">
        Sơ đồ phản ánh luồng xử lý thực tế trong{" "}
        <code className="font-mono text-ink-secondary">pipeline.py</code>,{" "}
        <code className="font-mono text-ink-secondary">repository.py</code> và{" "}
        <code className="font-mono text-ink-secondary">ai_orchestrator.py</code>. Phản hồi HTTP/SSE
        của phiên kiểm tra hiện tại có thể chứa bản đồ nhiệt ELA hoặc ảnh xem trước trang cách ly để
        hiển thị tức thời, nhưng các khối nhị phân này bị loại bỏ trước khi ghi vào cơ sở dữ liệu.
      </figcaption>
    </figure>
  );
}
