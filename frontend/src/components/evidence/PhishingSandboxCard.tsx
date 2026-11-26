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
      <p className="text-xs text-slate-400">Không có đường dẫn nào trong lượt kiểm tra này.</p>
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
              <span className="break-all font-mono">{u.url}</span>
            </div>
            <span className="rounded bg-slate-900 px-2 py-0.5 font-mono text-[11px] font-semibold text-amber-300">
              Mức rủi ro đường dẫn: {u.risk_points}/100
            </span>
          </div>

          <div className="mt-2.5 flex flex-wrap gap-1.5 text-[11px]">
            {u.is_blocked_ssrf && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 font-semibold text-rose-200">
                Đã chặn địa chỉ mạng nội bộ không an toàn
              </span>
            )}
            {u.is_idn_homoglyph && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 font-semibold text-rose-200">
                Tên miền dùng ký tự gần giống để đánh lừa
              </span>
            )}
            {u.spoofed_brand && (
              <span className="rounded bg-amber-500/20 px-2 py-0.5 font-semibold text-amber-200">
                Có dấu hiệu giả mạo {u.spoofed_brand}
              </span>
            )}
            {u.redirect_hops > 0 && (
              <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                Chuyển hướng qua {u.redirect_hops} địa chỉ trung gian
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

          <details className="mt-2.5 rounded-lg bg-slate-900/70 px-3 py-2 text-[11px] text-slate-400">
            <summary className="cursor-pointer font-medium text-slate-300 hover:text-slate-100">
              Thông tin kỹ thuật đường dẫn
            </summary>
            <p className="mt-1.5 break-all font-mono leading-relaxed">
              Tên miền chuẩn hóa (ASCII/Punycode): {u.normalized_ascii_domain || u.domain}
              {u.final_url ? ` · Đích cuối: ${u.final_url}` : ""}
              {u.is_blocked_ssrf ? " · Lớp bảo vệ SSRF: Đã chặn" : ""}
            </p>
          </details>
        </div>
      ))}

      {sandbox && (
        <div className="rounded-xl border border-amber-500/40 bg-[#0b1120] p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-bold text-amber-200">
              <ShieldAlert className="h-4 w-4 text-amber-400" aria-hidden="true" />
              <span>Kiểm tra trang web trong môi trường cách ly</span>
            </div>
            {sandbox.blocked_ssrf ? (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 font-mono text-[11px] font-bold text-rose-200">
                Đã chặn địa chỉ nội bộ ({sandbox.risk_points}/100)
              </span>
            ) : sandbox.available ? (
              <span className="rounded bg-amber-500/15 px-2 py-0.5 font-mono text-[11px] text-amber-300">
                Mức rủi ro trang web: {sandbox.risk_points}/100
              </span>
            ) : (
              <span className="rounded bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300">
                Chưa thể mở trang web này
              </span>
            )}
          </div>

          <div className="mt-2.5 flex flex-wrap gap-2 text-[11px]">
            {sandbox.blocked_ssrf && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 font-semibold text-rose-200">
                Đã chặn truy cập mạng nội bộ từ môi trường cách ly
              </span>
            )}
            {sandbox.has_password_field && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 text-rose-200">
                Yêu cầu nhập mật khẩu
              </span>
            )}
            {sandbox.has_otp_field && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 text-rose-200">
                Yêu cầu nhập mã OTP hoặc mã PIN
              </span>
            )}
            {sandbox.has_apk_download && (
              <span className="rounded bg-rose-500/20 px-2 py-0.5 text-rose-200">
                Chứa liên kết tải tệp cài đặt .APK đáng ngờ
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
                alt="Ảnh chụp trang web được mở trong môi trường cách ly an toàn"
                className="max-h-64 w-full rounded-lg border border-slate-800 bg-slate-950 object-contain"
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
