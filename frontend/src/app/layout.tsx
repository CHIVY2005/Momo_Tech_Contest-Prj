import type { Metadata } from "next";
import Link from "next/link";
import { Activity, Radar, ShieldCheck } from "lucide-react";

import "./globals.css";

export const metadata: Metadata = {
  title: "VeriShield AI v2.0 — Điều tra Lừa đảo Đa phương thức & Phòng vệ Ví",
  description:
    "Hệ thống kết hợp Pháp y Chứng từ 4 lớp, Mô hình E5 ONNX nội bộ, Khóa làm nguội 30 giây và Trung tâm Fraud Ops khép kín.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="vi">
      <body className="font-[family-name:var(--font-sans)] text-slate-100 antialiased selection:bg-amber-500/30 selection:text-amber-100">
        <header className="sticky top-0 z-40 border-b border-slate-800/90 bg-[#090e1a]/90 backdrop-blur-md">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6 lg:px-8">
            <Link
              href="/"
              className="group flex items-center gap-3 rounded-lg py-0.5 focus-visible:outline-amber-400"
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-amber-500/40 bg-amber-500/15 text-amber-400 transition-colors group-hover:border-amber-400">
                <ShieldCheck className="h-5 w-5" aria-hidden="true" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-base font-bold tracking-tight text-slate-50">
                    VeriShield AI
                  </span>
                  <span className="rounded border border-sky-500/40 bg-sky-500/15 px-1.5 py-0.5 font-[family-name:var(--font-mono)] text-[11px] font-medium text-sky-300">
                    v2.0
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  Pháp y Đa phương thức · Phòng vệ Phút 89 · Fraud Ops Khép kín
                </p>
              </div>
            </Link>

            <nav aria-label="Điều hướng chính" className="flex items-center gap-2">
              <Link
                href="/"
                className="inline-flex items-center gap-2 rounded-lg border border-slate-700/80 bg-slate-900/90 px-3.5 py-2 text-xs font-semibold text-slate-100 transition-colors hover:border-amber-500/50 hover:bg-slate-800 sm:text-sm"
              >
                <Activity className="h-4 w-4 text-amber-400" aria-hidden="true" />
                <span>Workbench &amp; Ví 30s</span>
              </Link>
              <Link
                href="/radar"
                className="inline-flex items-center gap-2 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3.5 py-2 text-xs font-semibold text-sky-200 transition-colors hover:border-sky-400 hover:bg-sky-500/20 sm:text-sm"
              >
                <Radar className="h-4 w-4 text-sky-400" aria-hidden="true" />
                <span>Fraud Ops Radar</span>
              </Link>
            </nav>
          </div>
        </header>

        <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">{children}</main>

        <footer className="mt-12 border-t border-slate-800/80 bg-[#070b14] py-6">
          <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-2 px-4 text-xs text-slate-400 sm:flex-row sm:items-center sm:px-6 lg:px-8">
            <p>
              <strong className="font-semibold text-slate-200">VeriShield AI v2.0</strong> — Kiến trúc
              3 Tầng (Deterministic Forensics + Pruned E5 INT8 ONNX + Gemini 2.5 Flash).
            </p>
            <p className="font-[family-name:var(--font-mono)] text-[11px] text-slate-400">
              100% Dữ liệu Tổng hợp · Ẩn danh hóa IOC · Không lưu PII thô
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
