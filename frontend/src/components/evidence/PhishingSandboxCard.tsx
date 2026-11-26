"use client";

import { GlobeLock, ShieldAlert } from "lucide-react";

import type { SandboxInspection, UrlFinding } from "@/lib/types";

interface PhishingSandboxCardProps {
  urls: UrlFinding[];
  sandbox?: SandboxInspection | null;
}

export function PhishingSandboxCard({ urls, sandbox }: PhishingSandboxCardProps) {
  if (urls.length === 0 && !sandbox) {
    return (
      <p className="text-xs text-slate-400">
        Không có đường dẫn URL nào trong phiên điều tra hiện tại.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      {urls.map((u) => (
        <div
          key={u.url}
          className={`rounded-xl border p-4 ${
            u.risk_points >= 45 || u.is_blocked_ssrf
              ? "border-rose-500/50 bg-rose-500/10"
              : "border-slate-800 bg-[#0b1120]"
          }`}
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-100">
              <GlobeLock className="h-4 w-4 text-sky-400" aria-hidden="true" />
              <span className="break-all font-[family-name:var(--font-mono)]">{u.url}</span>
            </div>
            <span className="rounded bg-slate-900 px-2 py-0.5 font-[family-name:var(--font-mono)] text-[11px] font-semibold text-amber-300">
              Rủi ro URL: {u.risk_points}/100
            </span>
          </div>

          <div className="mt-2.5 flex flex-wrap gap-1.5 text-[11px]">
            <span className="rounded bg-slate-900 px-2 py-0.5 font-[family-name:var(--font-mono)] text-slate-300">
              ASCII: {u.normalized_ascii_domain || u.domain}
            </span>
            {u.is_blocked_ssrf && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 font-semibold text-rose-200">
                ĐÃ CHẶN SSRF (IP Nội bộ / Metadata)
              </span>
            )}
            {u.is_idn_homoglyph && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 font-semibold text-rose-200">
                Tấn công Đồng hình Punycode IDN
              </span>
            )}
            {u.spoofed_brand && (
              <span className="rounded bg-amber-500/20 px-2 py-0.5 font-semibold text-amber-200">
                Mạo danh thương hiệu: {u.spoofed_brand}
              </span>
            )}
            {u.redirect_hops > 0 && (
              <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                Chuyển hướng: {u.redirect_hops} chặng
              </span>
            )}
          </div>

          {u.reasons.length > 0 && (
            <ul className="mt-2.5 list-inside list-disc space-y-1 text-xs text-slate-200">
              {u.reasons.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          )}
        </div>
      ))}

      {sandbox && (
        <div className="rounded-xl border border-amber-500/40 bg-[#0b1120] p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-bold text-amber-200">
              <ShieldAlert className="h-4 w-4 text-amber-400" aria-hidden="true" />
              <span>Buồng Cô lập Trình duyệt Không đầu (Playwright Headless Detonation)</span>
            </div>
            {sandbox.blocked_ssrf ? (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 font-[family-name:var(--font-mono)] text-[11px] font-bold text-rose-200">
                ĐÃ CHẶN SSRF ({sandbox.risk_points}/100)
              </span>
            ) : sandbox.available ? (
              <span className="rounded bg-amber-500/15 px-2 py-0.5 font-[family-name:var(--font-mono)] text-[11px] text-amber-300">
                Điểm Sandbox: {sandbox.risk_points}/100
              </span>
            ) : (
              <span className="rounded bg-slate-800 px-2 py-0.5 font-[family-name:var(--font-mono)] text-[11px] text-slate-300">
                Tạm ngưng / Không khả dụng
              </span>
            )}
          </div>

          <div className="mt-2.5 flex flex-wrap gap-2 text-[11px]">
            {sandbox.blocked_ssrf && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 font-semibold text-rose-200">
                Chặn truy cập mạng nội bộ từ trình duyệt cô lập
              </span>
            )}
            {sandbox.has_password_field && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 text-rose-200">
                Ô thu thập Mật khẩu
              </span>
            )}
            {sandbox.has_otp_field && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 text-rose-200">
                Ô đánh cắp mã OTP / PIN
              </span>
            )}
            {sandbox.has_apk_download && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 text-rose-200">
                Phát tán tệp .APK độc hại
              </span>
            )}
            {sandbox.page_title && (
              <span className="rounded bg-slate-900 px-2 py-0.5 text-slate-300">
                Tiêu đề trang: {sandbox.page_title}
              </span>
            )}
          </div>

          {sandbox.reasons.length > 0 && (
            <ul className="mt-2.5 list-inside list-disc space-y-1 text-xs text-slate-200">
              {sandbox.reasons.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          )}

          {sandbox.screenshot_base64 && (
            <div className="mt-3">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={`data:image/jpeg;base64,${sandbox.screenshot_base64}`}
                alt="Ảnh chụp trang web nghi vấn bên trong buồng cô lập an toàn"
                className="max-h-64 w-full rounded-lg border border-slate-800 bg-slate-950 object-contain"
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
