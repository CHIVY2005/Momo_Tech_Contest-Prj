import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import Link from "next/link";
import { ShieldCheck } from "lucide-react";

import { TopNav } from "@/components/layout/TopNav";

import "./globals.css";

const inter = Inter({
  subsets: ["latin", "vietnamese"],
  display: "swap",
  variable: "--font-inter",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin", "vietnamese"],
  display: "swap",
  variable: "--font-jetbrains-mono",
});

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
    <html lang="vi" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="font-sans text-ink antialiased selection:bg-amber-500/30 selection:text-amber-100">
        <a href="#main-content" className="skip-link">
          Bỏ qua điều hướng, tới nội dung chính
        </a>

        <header className="sticky top-0 z-40 border-b border-border-subtle/90 bg-canvas/92 backdrop-blur-md">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-2.5 px-4 py-2.5 sm:px-6 sm:py-3 lg:px-8">
            <Link
              href="/"
              className="group flex items-center gap-2.5 rounded-lg py-0.5 focus-visible:outline-amber-400 sm:gap-3"
            >
              <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-amber-500/40 bg-amber-500/15 text-amber-400 transition-colors group-hover:border-amber-400 sm:h-10 sm:w-10">
                <ShieldCheck className="h-5 w-5" aria-hidden="true" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold tracking-tight text-ink sm:text-base">
                    VeriShield AI
                  </span>
                  <span className="tabular-num rounded border border-sky-500/40 bg-sky-500/15 px-1.5 py-0.5 font-mono text-[11px] font-medium text-sky-300">
                    v2.0
                  </span>
                </div>
                <p className="hidden text-xs text-ink-muted sm:block">
                  Pháp y Đa phương thức · Phòng vệ Phút 89 · Fraud Ops Khép kín
                </p>
              </div>
            </Link>

            <TopNav />
          </div>
        </header>

        <main
          id="main-content"
          tabIndex={-1}
          className="mx-auto max-w-7xl px-4 py-5 outline-none sm:px-6 lg:px-8"
        >
          {children}
        </main>

        <footer className="mt-10 border-t border-border-subtle/80 bg-surface-deep py-5">
          <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-2 px-4 text-xs text-ink-muted sm:flex-row sm:items-center sm:px-6 lg:px-8">
            <p>
              <strong className="font-semibold text-ink-secondary">VeriShield AI v2.0</strong> — Kiến
              trúc 3 Tầng (Deterministic Forensics + Pruned E5 INT8 ONNX + Gemini 2.5 Flash).
            </p>
            <p className="font-mono text-[11px] text-ink-muted">
              100% Dữ liệu Tổng hợp · Ẩn danh hóa IOC · Không lưu PII thô
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
