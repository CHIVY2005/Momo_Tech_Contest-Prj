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
                <span className="block text-sm font-bold tracking-tight text-ink sm:text-base">
                  {BRAND_COPY.name}
                </span>
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

        <footer className="mt-12 border-t border-border-subtle/80 bg-surface-deep py-6">
          <div className="mx-auto max-w-7xl space-y-3 px-4 text-xs text-ink-muted sm:px-6 lg:px-8">
            <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-baseline">
              <p className="text-ink-secondary">
                <strong className="font-semibold text-ink">{BRAND_COPY.name}</strong> —{" "}
                {BRAND_COPY.footerSummary}
              </p>
              <span className="tabular-num shrink-0 font-mono text-[11px] text-ink-muted">
                Phiên bản {BRAND_COPY.version}
              </span>
            </div>

            <div className="space-y-1 text-[11px] leading-relaxed text-ink-muted">
              <p>{BRAND_COPY.footerLimitation}</p>
              <p>
                <span className="font-medium text-ink-secondary">Quyền riêng tư:</span>{" "}
                {BRAND_COPY.privacySummary}
              </p>
            </div>

            <details className="text-[11px] text-ink-muted">
              <summary className="inline-flex cursor-pointer items-center font-medium text-ink-secondary transition-colors hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-400">
                Thông tin kỹ thuật
              </summary>
              <p className="mt-1.5 max-w-4xl leading-relaxed text-ink-muted">
                {BRAND_COPY.technicalArchitectureSummary}
              </p>
            </details>
          </div>
        </footer>
      </body>
    </html>
  );
}
