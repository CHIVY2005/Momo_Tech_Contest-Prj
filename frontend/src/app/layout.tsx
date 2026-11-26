import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import Link from "next/link";
import { ShieldCheck } from "lucide-react";

import { TopNav } from "@/components/layout/TopNav";
import { BRAND_COPY } from "@/lib/copy";

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
  title: BRAND_COPY.pageTitle,
  description: BRAND_COPY.pageDescription,
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
                  {BRAND_COPY.tagline}
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
          <div className="mx-auto max-w-7xl space-y-2.5 px-4 text-xs text-ink-muted sm:px-6 lg:px-8">
            <div className="flex flex-col items-start justify-between gap-2 sm:flex-row sm:items-center">
              <p>
                <strong className="font-semibold text-ink-secondary">{BRAND_COPY.name}</strong> —{" "}
                {BRAND_COPY.footerNotice}
              </p>
              <p className="text-[11px] text-ink-muted">{BRAND_COPY.privacySummary}</p>
            </div>
            <details className="text-[11px] text-ink-muted">
              <summary className="inline-flex cursor-pointer items-center font-medium text-ink-secondary hover:text-ink">
                Thông tin kỹ thuật hệ thống
              </summary>
              <p className="mt-1.5 leading-relaxed text-ink-muted">
                {BRAND_COPY.technicalArchitectureSummary}
              </p>
            </details>
          </div>
        </footer>
      </body>
    </html>
  );
}
