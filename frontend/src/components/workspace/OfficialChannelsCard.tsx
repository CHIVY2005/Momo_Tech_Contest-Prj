"use client";

import { ExternalLink, PhoneCall, ShieldCheck } from "lucide-react";

const OFFICIAL_CHANNELS = [
  {
    name: "Cổng Cảnh báo An toàn thông tin Việt Nam (NCSC)",
    href: "https://canhbao.khonggianmang.vn",
    description: "Tra cứu và phản ánh trang web, tài khoản hoặc số điện thoại có dấu hiệu giả mạo.",
  },
  {
    name: "Cổng thông tin NAPAS (VietQR chính thức)",
    href: "https://napas.com.vn",
    description: "Tra cứu thông tin chuẩn chuyển nhanh 24/7 và danh sách ngân hàng thành viên.",
  },
] as const;

export function OfficialChannelsCard() {
  return (
    <section
      aria-labelledby="official-channels-heading"
      className="rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-md"
    >
      <div className="mb-2.5 flex items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-emerald-400" aria-hidden="true" />
        <h3 id="official-channels-heading" className="text-xs font-bold text-ink">
          Kênh xác minh chính thức
        </h3>
      </div>

      <ul className="space-y-2 text-xs">
        {OFFICIAL_CHANNELS.map((ch) => (
          <li
            key={ch.href}
            className="rounded-xl border border-border-subtle bg-surface-subtle p-2.5"
          >
            <a
              href={ch.href}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 font-semibold text-sky-300 underline decoration-sky-500/40 underline-offset-2 transition-colors hover:text-sky-200"
            >
              <span>{ch.name}</span>
              <ExternalLink className="h-3 w-3 shrink-0" aria-hidden="true" />
            </a>
            <p className="mt-0.5 text-[11px] leading-relaxed text-ink-muted">{ch.description}</p>
          </li>
        ))}
      </ul>

      <div className="mt-2.5 flex items-start gap-2 rounded-xl border border-border-subtle bg-surface-deep/75 px-3 py-2 text-[11px] text-ink-muted">
        <PhoneCall className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" aria-hidden="true" />
        <p className="leading-relaxed">
          Luôn tự gọi số tổng đài in ở mặt sau thẻ ngân hàng hoặc mở ứng dụng ngân hàng chính thức —
          không gọi theo số điện thoại hay đường dẫn trong tin nhắn lạ.
        </p>
      </div>
    </section>
  );
}
