import { ArrowUpRight, ShieldCheck } from "lucide-react";
import Link from "next/link";

import { BRAND_COPY } from "@/lib/copy";

import { FooterTelegramLink } from "./FooterTelegramLink";

const PUBLIC_GITHUB_URL = (process.env.NEXT_PUBLIC_GITHUB_REPO_URL ?? "").trim();
const SAFE_GITHUB_URL = PUBLIC_GITHUB_URL.startsWith("https://github.com/")
  ? PUBLIC_GITHUB_URL
  : null;

export function SiteFooter() {
  return (
    <footer className="mt-14 border-t border-border-subtle/80 bg-surface-deep py-8">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 gap-8 md:grid-cols-12">
          <div className="space-y-2.5 md:col-span-6">
            <Link
              href="/"
              className="inline-flex items-center gap-2 text-sm font-bold tracking-tight text-ink"
            >
              <ShieldCheck className="h-4 w-4 text-amber-400" aria-hidden="true" />
              <span>{BRAND_COPY.name}</span>
            </Link>
            <p className="max-w-md text-xs leading-relaxed text-ink-secondary">
              {BRAND_COPY.footerSummary}
            </p>
            <p className="max-w-xl text-[11px] leading-relaxed text-ink-muted">
              {BRAND_COPY.footerLimitation}
            </p>
          </div>

          <div className="md:col-span-3">
            <h2 className="mb-2.5 text-[11px] font-semibold tracking-wider text-ink-muted uppercase">
              Sản phẩm
            </h2>
            <ul className="space-y-2 text-xs">
              <li>
                <Link
                  href="/"
                  className="text-ink-secondary transition-colors hover:text-ink"
                >
                  Kiểm tra lừa đảo
                </Link>
              </li>
              <li>
                <Link
                  href="/radar"
                  className="text-ink-secondary transition-colors hover:text-ink"
                >
                  Giám sát gian lận
                </Link>
              </li>
              <FooterTelegramLink />
            </ul>
          </div>

          <div className="md:col-span-3">
            <h2 className="mb-2.5 text-[11px] font-semibold tracking-wider text-ink-muted uppercase">
              Thông tin
            </h2>
            <ul className="space-y-2 text-xs">
              <li>
                <Link
                  href="/technical"
                  className="text-ink-secondary transition-colors hover:text-ink"
                >
                  Công nghệ
                </Link>
              </li>
              <li>
                <Link
                  href="/privacy"
                  className="text-ink-secondary transition-colors hover:text-ink"
                >
                  Quyền riêng tư
                </Link>
              </li>
              {SAFE_GITHUB_URL && (
                <li>
                  <a
                    href={SAFE_GITHUB_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-ink-secondary transition-colors hover:text-ink"
                  >
                    <span>GitHub</span>
                    <ArrowUpRight className="h-3 w-3 text-ink-muted" aria-hidden="true" />
                  </a>
                </li>
              )}
            </ul>
          </div>
        </div>
      </div>
    </footer>
  );
}
