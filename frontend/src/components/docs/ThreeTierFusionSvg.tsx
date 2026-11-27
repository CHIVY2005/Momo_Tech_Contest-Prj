export function ThreeTierFusionSvg() {
  return (
    <figure className="overflow-x-auto rounded-xl border border-border-subtle bg-surface-deep/90 p-4">
      <svg
        viewBox="0 0 960 310"
        role="img"
        aria-labelledby="tier-fusion-title tier-fusion-desc"
        className="h-auto w-full min-w-[680px]"
      >
        <title id="tier-fusion-title">Cơ chế hợp nhất 3 tín hiệu và các ngưỡng bảo vệ cứng</title>
        <desc id="tier-fusion-desc">
          Sơ đồ công thức hợp nhất điểm từ Tầng 1 xác định (30%), mô hình E5 INT8 ONNX (35%) và AI
          đa phương thức (35%), đi qua bộ ưu tiên quy tắc chặn, trần khuyến cáo an toàn và các sàn
          bảo mật cứng để tạo ra kết luận cuối cùng.
        </desc>

        <defs>
          <marker
            id="tf-arrow"
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
            id="tf-arrow-amber"
            viewBox="0 0 10 10"
            refX="8.5"
            refY="5"
            markerWidth="6.5"
            markerHeight="6.5"
            orient="auto-start-reverse"
          >
            <path d="M 0 1.5 L 8.5 5 L 0 8.5 z" fill="#f59e0b" />
          </marker>
        </defs>

        {/* Left column: 3 Signals */}
        <rect x="16" y="20" width="248" height="76" rx="9" fill="#121a29" stroke="#38bdf8" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="30" y="42" fill="#38bdf8" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TÍN HIỆU 1 · TRỌNG SỐ 0,30
        </text>
        <text x="30" y="61" fill="#f1f5f9" fontSize="12" fontWeight="700">Điểm xác định Tầng 1</text>
        <text x="30" y="80" fill="#94a3b8" fontSize="10.2">max(URL, Sandbox, ELA, VietQR, KB)</text>

        <rect x="16" y="114" width="248" height="76" rx="9" fill="#121a29" stroke="#a78bfa" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="30" y="136" fill="#c4b5fd" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TÍN HIỆU 2 · TRỌNG SỐ 0,35
        </text>
        <text x="30" y="155" fill="#f1f5f9" fontSize="12" fontWeight="700">E5-Small INT8 ONNX</text>
        <text x="30" y="174" fill="#94a3b8" fontSize="10.2">Xác suất lừa đảo 7 lớp (CPU ~10 ms)</text>

        <rect x="16" y="208" width="248" height="76" rx="9" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="30" y="230" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TÍN HIỆU 3 · TRỌNG SỐ 0,35
        </text>
        <text x="30" y="249" fill="#f1f5f9" fontSize="12" fontWeight="700">AI Đa phương thức</text>
        <text x="30" y="268" fill="#94a3b8" fontSize="10.2">Bỏ qua an toàn nếu chế độ dự phòng</text>

        {/* Converging arrows */}
        <path d="M 264 58 L 292 58 L 292 152 L 314 152" fill="none" stroke="#64748b" strokeWidth="1.5" markerEnd="url(#tf-arrow)" />
        <line x1="264" y1="152" x2="314" y2="152" stroke="#64748b" strokeWidth="1.5" markerEnd="url(#tf-arrow)" />
        <path d="M 264 246 L 292 246 L 292 152 L 314 152" fill="none" stroke="#64748b" strokeWidth="1.5" markerEnd="url(#tf-arrow)" />

        {/* Middle: Risk Calibrator & Overrides */}
        <rect x="320" y="20" width="348" height="266" rx="10" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.6" strokeWidth="1.5" />
        <text x="336" y="44" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          RISK CALIBRATOR (risk_calibrator.py)
        </text>
        <text x="336" y="66" fill="#f1f5f9" fontSize="12.5" fontWeight="700">
          Hợp nhất &amp; Cưỡng chế quy tắc an toàn
        </text>

        <text x="336" y="90" fill="#cbd5e1" fontSize="10.8">
          • Đủ 3 nguồn: 0,30·T1 + 0,35·ONNX + 0,35·AI
        </text>
        <text x="336" y="108" fill="#94a3b8" fontSize="10.2">
          • Chế độ dự phòng (không AI): 0,45·T1 + 0,55·ONNX
        </text>
        <text x="336" y="126" fill="#94a3b8" fontSize="10.2">
          • Đang nghe điện thoại (base ≥ 25): cộng thêm +10
        </text>

        <line x1="336" y1="140" x2="652" y2="140" stroke="#273449" strokeWidth="1" />

        <text x="336" y="160" fill="#fb7185" fontSize="10.8" fontWeight="600">
          1. Trùng danh sách chặn Radar → sàn ≥ 96
        </text>
        <text x="336" y="179" fill="#34d399" fontSize="10.8" fontWeight="600">
          2. Khuyến cáo an toàn chính thống → trần ≤ 16
        </text>
        <text x="336" y="198" fill="#fbbf24" fontSize="10.8" fontWeight="600">
          3. Sàn bảo mật xác định (chống hạ điểm):
        </text>
        <text x="346" y="216" fill="#cbd5e1" fontSize="10.2">
          • VietQR bẫy / biên lai dùng lại / lệch STK: ≥ 85
        </text>
        <text x="346" y="234" fill="#cbd5e1" fontSize="10.2">
          • SSRF / giả mạo thương hiệu / Punycode: ≥ 82
        </text>
        <text x="346" y="252" fill="#cbd5e1" fontSize="10.2">
          • Tiêm lệnh AI: ≥ 78 · Sửa ảnh ELA/EXIF: ≥ 45–70
        </text>
        <text x="346" y="270" fill="#cbd5e1" fontSize="10.2">
          • OCR lỗi / ảnh không đọc được chữ (no-AI): ≥ 30–32
        </text>

        {/* Arrow Middle -> Right */}
        <line x1="668" y1="152" x2="700" y2="152" stroke="#f59e0b" strokeWidth="1.6" markerEnd="url(#tf-arrow-amber)" />

        {/* Right: Calibrated Output */}
        <rect x="706" y="34" width="238" height="236" rx="10" fill="#0f1624" stroke="#364761" strokeWidth="1.5" />
        <text x="720" y="58" fill="#10b981" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          KẾT QUẢ HIỆU CHUẨN
        </text>
        <text x="720" y="80" fill="#f1f5f9" fontSize="12.5" fontWeight="700">Thang rủi ro 0 – 100</text>
        <text x="720" y="104" fill="#34d399" fontSize="10.8">• 0 – 24: Mức rủi ro thấp</text>
        <text x="720" y="123" fill="#fbbf24" fontSize="10.8">• 25 – 54: Cần thận trọng</text>
        <text x="720" y="142" fill="#fb923c" fontSize="10.8">• 55 – 79: Rủi ro cao</text>
        <text x="720" y="161" fill="#fb7185" fontSize="10.8">• 80 – 100: Rủi ro rất cao</text>

        <line x1="720" y1="178" x2="928" y2="178" stroke="#273449" strokeWidth="1" />

        <text x="720" y="199" fill="#cbd5e1" fontSize="10.8" fontWeight="600">Biện pháp đi kèm:</text>
        <text x="720" y="218" fill="#94a3b8" fontSize="10.2">• Nhắc tạm dừng 30s (điểm ≥ 55</text>
        <text x="720" y="234" fill="#94a3b8" fontSize="10.2">  hoặc đang gọi điện &amp; điểm ≥ 35)</text>
        <text x="720" y="254" fill="#fbbf24" fontSize="10.2">• Cảnh báo kiểm tra số dư biên lai</text>
      </svg>
      <figcaption className="mt-3 border-t border-border-subtle/60 pt-2.5 text-[11px] leading-relaxed text-ink-muted">
        Nguyên tắc thiết kế: điểm số xác định Tầng 1 dùng hàm{" "}
        <code className="font-mono text-ink-secondary">max()</code> giữa các cảm biến độc lập để
        tránh cộng dồn sai lệch, đồng thời các sàn bảo mật cứng bảo đảm AI Tầng 2 không thể hạ thấp
        cảnh báo khi bằng chứng kỹ thuật đã rõ ràng.
      </figcaption>
    </figure>
  );
}
