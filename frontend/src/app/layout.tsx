import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import Link from "next/link";
import { ShieldCheck } from "lucide-react";

import { MotionProviders } from "@/components/motion/MotionProviders";
import { SiteFooter } from "@/components/layout/SiteFooter";
import { TopNav } from "@/components/layout/TopNav";
import { BRAND_COPY } from "@/lib/copy";

import "lenis/dist/lenis.css";
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
        <MotionProviders>
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

        <SiteFooter />
        </MotionProviders>
      </body>
    </html>
  );
}
