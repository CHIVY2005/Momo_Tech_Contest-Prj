"use client";

import { Activity, Radar } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

export function TopNav() {
  const pathname = usePathname();
  const isHome = pathname === "/";
  const isRadar = pathname.startsWith("/radar");

  return (
    <nav aria-label="Điều hướng chính" className="flex items-center gap-2">
      <Link
        href="/"
        aria-current={isHome ? "page" : undefined}
        className={`inline-flex min-h-[40px] items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold transition-colors sm:px-3.5 sm:text-sm ${
          isHome
            ? "border-amber-400/70 bg-amber-500/15 text-amber-100 shadow-sm shadow-amber-500/10"
            : "border-border-strong bg-surface-subtle text-ink-secondary hover:border-amber-500/50 hover:text-ink"
        }`}
      >
        <Activity
          className={`h-4 w-4 shrink-0 ${isHome ? "text-amber-300" : "text-amber-400/80"}`}
          aria-hidden="true"
        />
        <span>Kiểm tra lừa đảo</span>
      </Link>
      <Link
        href="/radar"
        aria-current={isRadar ? "page" : undefined}
        className={`inline-flex min-h-[40px] items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold transition-colors sm:px-3.5 sm:text-sm ${
          isRadar
            ? "border-sky-400/80 bg-sky-500/20 text-sky-100 shadow-sm shadow-sky-500/10"
            : "border-sky-500/35 bg-sky-500/10 text-sky-200 hover:border-sky-400 hover:bg-sky-500/20"
        }`}
      >
        <Radar
          className={`h-4 w-4 shrink-0 ${isRadar ? "text-sky-300" : "text-sky-400"}`}
          aria-hidden="true"
        />
        <span>Giám sát gian lận</span>
      </Link>
    </nav>
  );
}
