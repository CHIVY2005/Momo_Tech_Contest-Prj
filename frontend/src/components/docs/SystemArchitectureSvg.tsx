export function SystemArchitectureSvg() {
  return (
    <figure className="overflow-x-auto rounded-xl border border-border-subtle bg-surface-deep/90 p-4">
      <svg
        viewBox="0 0 960 540"
        role="img"
        aria-labelledby="sys-arch-title sys-arch-desc"
        className="h-auto w-full min-w-[700px]"
      >
        <title id="sys-arch-title">Kiến trúc tổng thể hệ thống VeriShield AI</title>
        <desc id="sys-arch-desc">
          Sơ đồ kiến trúc gồm lớp giao tiếp Web Next.js và Telegram Bot, Reverse Proxy Caddy 2, tầng
          FastAPI cùng Middleware giới hạn tải và tần suất, đường ống phân tích 3 tầng và vòng lặp
          khép kín Giám sát gian lận dựa trên SQLite WAL.
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

        {/* Row 1 Left: Stacked Client Channels */}
        <rect x="20" y="14" width="212" height="48" rx="9" fill="#121a29" stroke="#364761" strokeWidth="1.4" />
        <text x="34" y="34" fill="#f1f5f9" fontSize="12" fontWeight="700">Web App (Next.js 15)</text>
        <text x="34" y="51" fill="#94a3b8" fontSize="10.2">Kiểm tra (/) · Giám sát (/radar)</text>

        <rect x="20" y="70" width="212" height="48" rx="9" fill="#121a29" stroke="#364761" strokeWidth="1.4" />
        <text x="34" y="90" fill="#f1f5f9" fontSize="12" fontWeight="700">Telegram Bot (tùy chọn)</text>
        <text x="34" y="107" fill="#94a3b8" fontSize="10.2">Webhook xác thực secret token</text>

        {/* Clean merge bus from both clients into Edge */}
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
          BIÊN MẠNG (EDGE)
        </text>
        <text x="316" y="68" fill="#f1f5f9" fontSize="12.5" fontWeight="700">Caddy 2 Reverse Proxy</text>
        <text x="316" y="88" fill="#94a3b8" fontSize="10.5">TLS tự động · HSTS · CSP · Giới hạn 22 MB</text>

        <line x1="576" y1="66" x2="614" y2="66" stroke="#38bdf8" strokeWidth="1.5" markerEnd="url(#sa-arrow-cyan)" />

        {/* Row 1 Right: FastAPI Gateway */}
        <rect x="620" y="26" width="320" height="80" rx="10" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.6" strokeWidth="1.5" />
        <text x="636" y="48" fill="#f59e0b" fontSize="10" fontWeight="700" fontFamily="var(--font-mono), monospace">
          API GATEWAY &amp; MIDDLEWARE
        </text>
        <text x="636" y="68" fill="#f1f5f9" fontSize="12.5" fontWeight="700">FastAPI + Pure ASGI Security Guard</text>
        <text x="636" y="88" fill="#94a3b8" fontSize="10.5">Rate limit · Streaming body cap · SSE không đệm</text>

        {/* Connector from API Gateway down to Pipeline container */}
        <line x1="780" y1="106" x2="780" y2="140" stroke="#f59e0b" strokeWidth="1.6" markerEnd="url(#sa-arrow-amber)" />

        {/* Main Pipeline Container */}
        <rect x="20" y="146" width="920" height="240" rx="12" fill="#0f1624" stroke="#273449" strokeWidth="1.5" />
        <text x="36" y="169" fill="#cbd5e1" fontSize="10.8" fontWeight="700" fontFamily="var(--font-mono), monospace">
          ANALYSIS PIPELINE (ASYNC SSE ORCHESTRATOR — backend/app/services/pipeline.py)
        </text>

        {/* Tier 1 Box */}
        <rect x="36" y="184" width="332" height="186" rx="10" fill="#121a29" stroke="#38bdf8" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="50" y="206" fill="#38bdf8" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TẦNG 1 · CỤC BỘ &amp; XÁC ĐỊNH (CPU / RAM)
        </text>
        <text x="50" y="227" fill="#cbd5e1" fontSize="10.5">• Xác thực tệp, Magic Bytes, chống Bomb ảnh/âm thanh</text>
        <text x="50" y="245" fill="#cbd5e1" fontSize="10.5">• Pháp y ảnh: ELA 16×16, EXIF/XMP, dHash, OpenCV QR</text>
        <text x="50" y="263" fill="#cbd5e1" fontSize="10.5">• VietQR EMVCo TLV + kiểm tra CRC-16/CCITT-FALSE</text>
        <text x="50" y="281" fill="#cbd5e1" fontSize="10.5">• OCR: RapidOCR v3 PP-OCRv5 Latin (ONNX offline)</text>
        <text x="50" y="299" fill="#cbd5e1" fontSize="10.5">• STT: faster-whisper INT8 · Guardrails &amp; Prompt Trap</text>
        <text x="50" y="317" fill="#cbd5e1" fontSize="10.5">• URL Inspector + Playwright Sandbox (IP-Pinned)</text>
        <text x="50" y="335" fill="#cbd5e1" fontSize="10.5">• E5-Small INT8 ONNX (7 lớp + 384-d) &amp; Hybrid KB</text>
        <text x="50" y="353" fill="#94a3b8" fontSize="10.2">• Đối chiếu nghiệp vụ biên lai &amp; chống dùng lại ảnh</text>

        {/* Arrow T1 -> T2 */}
        <line x1="368" y1="277" x2="396" y2="277" stroke="#64748b" strokeWidth="1.6" markerEnd="url(#sa-arrow-slate)" />

        {/* Tier 2 Box */}
        <rect x="402" y="184" width="240" height="186" rx="10" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="416" y="206" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TẦNG 2 · AI ĐA PHƯƠNG THỨC
        </text>
        <text x="416" y="227" fill="#cbd5e1" fontSize="10.5">• Google GenAI SDK hoặc cổng</text>
        <text x="416" y="243" fill="#cbd5e1" fontSize="10.5">  OpenAI-compatible cấu hình sẵn</text>
        <text x="416" y="264" fill="#cbd5e1" fontSize="10.5">• Cách ly dữ liệu đầu vào trong</text>
        <text x="416" y="280" fill="#94a3b8" fontSize="10.2">  &lt;UNTRUSTED_USER_CONTENT&gt;</text>
        <text x="416" y="301" fill="#cbd5e1" fontSize="10.5">• Đầu ra JSON theo Schema chặt</text>
        <text x="416" y="319" fill="#cbd5e1" fontSize="10.5">• Retry + Failover khóa dự phòng</text>
        <text x="416" y="340" fill="#10b981" fontSize="10.2">• Degraded Mode: vẫn trả HTTP 200</text>
        <text x="416" y="355" fill="#94a3b8" fontSize="10.2">  bằng Tầng 1 khi AI gián đoạn</text>

        {/* Arrow T2 -> T3 */}
        <line x1="642" y1="277" x2="670" y2="277" stroke="#64748b" strokeWidth="1.6" markerEnd="url(#sa-arrow-slate)" />

        {/* Tier 3 Box */}
        <rect x="676" y="184" width="248" height="186" rx="10" fill="#121a29" stroke="#10b981" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="690" y="206" fill="#10b981" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TẦNG 3 · HIỆU CHUẨN &amp; ỨNG PHÓ
        </text>
        <text x="690" y="227" fill="#cbd5e1" fontSize="10.5">• Risk Calibrator (hợp nhất 3 tín hiệu</text>
        <text x="690" y="243" fill="#cbd5e1" fontSize="10.5">  + sàn bảo mật cứng + trần an toàn)</text>
        <text x="690" y="264" fill="#cbd5e1" fontSize="10.5">• Action Copilot: khóa làm nguội 30s,</text>
        <text x="690" y="280" fill="#cbd5e1" fontSize="10.5">  câu từ chối, cảnh báo gia đình</text>
        <text x="690" y="301" fill="#cbd5e1" fontSize="10.5">• Merchant Honesty Guardrail</text>
        <text x="690" y="320" fill="#cbd5e1" fontSize="10.5">• Xuất báo cáo PDF tiếng Việt (fpdf2)</text>
        <text x="690" y="339" fill="#cbd5e1" fontSize="10.5">• Che giấu SĐT/STK trước khi lưu</text>

        {/* Bottom Layer: Storage & Closed-Loop Radar */}
        <line x1="800" y1="370" x2="800" y2="424" stroke="#10b981" strokeWidth="1.6" markerEnd="url(#sa-arrow-emerald)" />

        <rect x="504" y="430" width="436" height="94" rx="10" fill="#121a29" stroke="#10b981" strokeOpacity="0.55" strokeWidth="1.5" />
        <text x="520" y="452" fill="#10b981" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TẦNG LƯU TRỮ · SQLITE 3 (WAL MODE)
        </text>
        <text x="520" y="473" fill="#cbd5e1" fontSize="10.5">
          • cases (đã che SĐT/STK) · ioc_sightings &amp; ioc_edges (HMAC-SHA256)
        </text>
        <text x="520" y="491" fill="#94a3b8" fontSize="10.2">
          • campaigns · block_rules (TTL mặc định 30p) · receipt_hashes (dHash)
        </text>
        <text x="520" y="509" fill="#94a3b8" fontSize="10.2">
          • radar_audit_logs (200 bản ghi gần nhất) · telegram_updates
        </text>

        {/* Closed-loop arrow from SQLite to Radar */}
        <line x1="504" y1="477" x2="462" y2="477" stroke="#38bdf8" strokeWidth="1.6" markerEnd="url(#sa-arrow-cyan)" />

        <rect x="20" y="430" width="436" height="94" rx="10" fill="#121a29" stroke="#38bdf8" strokeOpacity="0.55" strokeWidth="1.5" />
        <text x="36" y="452" fill="#38bdf8" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          CLOSED-LOOP FRAUD OPS (/radar)
        </text>
        <text x="36" y="473" fill="#cbd5e1" fontSize="10.5">
          • Mạng lưới liên kết cụm chiến dịch &amp; xem bằng chứng IOC
        </text>
        <text x="36" y="491" fill="#cbd5e1" fontSize="10.5">
          • Áp dụng quy tắc chặn đơn mục tiêu (TTL &amp; chống chặn nhầm 409)
        </text>
        <text x="36" y="509" fill="#94a3b8" fontSize="10.2">
          • Mô phỏng giao dịch tách biệt (is_simulation=true) không ghi vào DB
        </text>

        {/* Feedback loop from Radar back up to Tier 1 */}
        <path
          d="M 180 430 L 180 376"
          fill="none"
          stroke="#f59e0b"
          strokeWidth="1.6"
          strokeDasharray="4 3"
          markerEnd="url(#sa-arrow-amber)"
        />
        <text x="192" y="411" fill="#f59e0b" fontSize="10.5" fontWeight="600">
          Đối chiếu quy tắc chặn hiệu lực (≥ 96/100)
        </text>
      </svg>
      <figcaption className="mt-3 border-t border-border-subtle/60 pt-2.5 text-[11px] leading-relaxed text-ink-muted">
        Kiến trúc tổng thể phản ánh trực tiếp cấu trúc monorepo (
        <code className="font-mono text-ink-secondary">frontend/</code>,{" "}
        <code className="font-mono text-ink-secondary">backend/</code>,{" "}
        <code className="font-mono text-ink-secondary">deploy/</code>) và vòng lặp phản hồi giữa
        đường ống phân tích với trung tâm Giám sát gian lận.
      </figcaption>
    </figure>
  );
}
