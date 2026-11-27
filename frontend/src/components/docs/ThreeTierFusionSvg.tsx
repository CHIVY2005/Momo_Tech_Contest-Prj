export function ThreeTierFusionSvg() {
  return (
    <figure className="overflow-x-auto rounded-xl border border-border-subtle bg-surface-deep/90 p-4">
      <svg
        viewBox="0 0 960 310"
        role="img"
        aria-labelledby="tier-fusion-title tier-fusion-desc"
        className="h-auto w-full min-w-[680px]"
      >
        <title id="tier-fusion-title">Cơ chế tổng hợp 3 nguồn tín hiệu và hiệu chuẩn rủi ro</title>
        <desc id="tier-fusion-desc">
          Sơ đồ cách Tầng 3 hợp nhất 3 nguồn tín hiệu gồm kiểm tra kỹ thuật xác định Tầng 1, mô hình
          phân loại ngữ nghĩa E5-Small INT8 ONNX thuộc Tầng 1 và suy luận AI đa phương thức Tầng 2,
          sau đó áp dụng quy tắc ưu tiên danh sách chặn, giới hạn điểm cho tin khuyến cáo chính
          thống và các ngưỡng điểm rủi ro tối thiểu để ra kết luận cuối cùng.
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
        <rect x="16" y="20" width="256" height="76" rx="9" fill="#121a29" stroke="#38bdf8" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="30" y="42" fill="#38bdf8" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          NGUỒN 1 · TẦNG 1 (XÁC ĐỊNH)
        </text>
        <text x="30" y="61" fill="#f1f5f9" fontSize="12" fontWeight="700">Kiểm tra kỹ thuật cục bộ</text>
        <text x="30" y="80" fill="#94a3b8" fontSize="10.2">max(URL, Sandbox, Ảnh, VietQR, KB)</text>

        <rect x="16" y="114" width="256" height="76" rx="9" fill="#121a29" stroke="#a78bfa" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="30" y="136" fill="#c4b5fd" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          NGUỒN 2 · TẦNG 1 (ML CỤC BỘ)
        </text>
        <text x="30" y="155" fill="#f1f5f9" fontSize="12" fontWeight="700">E5-Small INT8 ONNX</text>
        <text x="30" y="174" fill="#94a3b8" fontSize="10.2">Xác suất phân loại 7 lớp (CPU ~10 ms)</text>

        <rect x="16" y="208" width="256" height="76" rx="9" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.55" strokeWidth="1.4" />
        <text x="30" y="230" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          NGUỒN 3 · TẦNG 2 (TÙY CHỌN)
        </text>
        <text x="30" y="249" fill="#f1f5f9" fontSize="12" fontWeight="700">AI đa phương thức</text>
        <text x="30" y="268" fill="#94a3b8" fontSize="10.2">Tự chuyển chế độ dự phòng nếu gián đoạn</text>

        {/* Converging arrows */}
        <path d="M 272 58 L 296 58 L 296 152 L 318 152" fill="none" stroke="#64748b" strokeWidth="1.5" markerEnd="url(#tf-arrow)" />
        <line x1="272" y1="152" x2="318" y2="152" stroke="#64748b" strokeWidth="1.5" markerEnd="url(#tf-arrow)" />
        <path d="M 272 246 L 296 246 L 296 152 L 318 152" fill="none" stroke="#64748b" strokeWidth="1.5" markerEnd="url(#tf-arrow)" />

        {/* Middle: Tier 3 Risk Calibration */}
        <rect x="324" y="20" width="344" height="266" rx="10" fill="#121a29" stroke="#f59e0b" strokeOpacity="0.6" strokeWidth="1.5" />
        <text x="340" y="44" fill="#f59e0b" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          TẦNG 3 · BỘ HIỆU CHUẨN RỦI RO
        </text>
        <text x="340" y="66" fill="#f1f5f9" fontSize="12.5" fontWeight="700">
          Tổng hợp có trọng số &amp; Quy tắc ưu tiên
        </text>

        <text x="340" y="90" fill="#cbd5e1" fontSize="10.6">
          • Tổ hợp trọng số giữa 3 nguồn (tự tái phân bổ
        </text>
        <text x="348" y="106" fill="#94a3b8" fontSize="10.2">
          giữa hai nguồn Tầng 1 khi chạy chế độ dự phòng).
        </text>
        <text x="340" y="125" fill="#94a3b8" fontSize="10.2">
          • Tăng mức cảnh báo khi người dùng đang nghe điện thoại.
        </text>

        <line x1="340" y1="139" x2="652" y2="139" stroke="#273449" strokeWidth="1" />

        <text x="340" y="159" fill="#fb7185" fontSize="10.6" fontWeight="600">
          1. Trùng quy tắc chặn hiệu lực → Mức rủi ro rất cao
        </text>
        <text x="340" y="178" fill="#34d399" fontSize="10.6" fontWeight="600">
          2. Khuyến cáo an toàn chính thống → Giới hạn mức thấp
        </text>
        <text x="340" y="197" fill="#fbbf24" fontSize="10.6" fontWeight="600">
          3. Ngưỡng điểm rủi ro tối thiểu cho bằng chứng kỹ thuật:
        </text>
        <text x="350" y="215" fill="#cbd5e1" fontSize="10.2">
          • Bẫy VietQR hoàn tiền, biên lai dùng lại, lệch STK
        </text>
        <text x="350" y="233" fill="#cbd5e1" fontSize="10.2">
          • Giả mạo thương hiệu, Punycode, chặn truy cập nội bộ
        </text>
        <text x="350" y="251" fill="#cbd5e1" fontSize="10.2">
          • Tấn công chèn chỉ thị (Prompt Injection) &amp; sửa ảnh
        </text>
        <text x="350" y="269" fill="#cbd5e1" fontSize="10.2">
          • OCR lỗi hoặc không đọc được chữ → giữ mức thận trọng
        </text>

        {/* Arrow Middle -> Right */}
        <line x1="668" y1="152" x2="700" y2="152" stroke="#f59e0b" strokeWidth="1.6" markerEnd="url(#tf-arrow-amber)" />

        {/* Right: Calibrated Output */}
        <rect x="706" y="34" width="238" height="236" rx="10" fill="#0f1624" stroke="#364761" strokeWidth="1.5" />
        <text x="720" y="58" fill="#10b981" fontSize="10.2" fontWeight="700" fontFamily="var(--font-mono), monospace">
          KẾT QUẢ ĐÁNH GIÁ
        </text>
        <text x="720" y="80" fill="#f1f5f9" fontSize="12.5" fontWeight="700">Thang rủi ro 0 – 100</text>
        <text x="720" y="104" fill="#34d399" fontSize="10.8">• 0 – 24: Mức rủi ro thấp</text>
        <text x="720" y="123" fill="#fbbf24" fontSize="10.8">• 25 – 54: Cần thận trọng</text>
        <text x="720" y="142" fill="#fb923c" fontSize="10.8">• 55 – 79: Rủi ro cao</text>
        <text x="720" y="161" fill="#fb7185" fontSize="10.8">• 80 – 100: Rủi ro rất cao</text>

        <line x1="720" y1="178" x2="928" y2="178" stroke="#273449" strokeWidth="1" />

        <text x="720" y="199" fill="#cbd5e1" fontSize="10.8" fontWeight="600">Biện pháp hỗ trợ:</text>
        <text x="720" y="218" fill="#94a3b8" fontSize="10.2">• Nhắc tạm dừng 30 giây khi</text>
        <text x="720" y="234" fill="#94a3b8" fontSize="10.2">  rủi ro cao hoặc đang gọi điện</text>
        <text x="720" y="254" fill="#fbbf24" fontSize="10.2">• Nguyên tắc xác minh biên lai</text>
      </svg>
      <figcaption className="mt-3 border-t border-border-subtle/60 pt-2.5 text-[11px] leading-relaxed text-ink-muted">
        Tầng 1 cung cấp hai nguồn tín hiệu độc lập (kiểm tra kỹ thuật xác định dùng toán tử{" "}
        <code className="font-mono text-ink-secondary">max()</code> để tránh cộng dồn sai lệch, cùng
        mô hình E5-Small INT8 ONNX). Khi có bằng chứng kỹ thuật rõ ràng, ngưỡng điểm rủi ro tối
        thiểu đảm bảo AI Tầng 2 không thể hạ thấp cảnh báo.
      </figcaption>
    </figure>
  );
}
