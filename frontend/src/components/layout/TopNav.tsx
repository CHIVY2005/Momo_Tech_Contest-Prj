"use client";

import { Activity, Radar, Search } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { MouseEvent } from "react";

export function TopNav() {
  const pathname = usePathname();
  const isHome = pathname === "/";
  const isRadar = pathname.startsWith("/radar");

  function openCommandPalette(ev: MouseEvent<HTMLButtonElement>) {
    window.dispatchEvent(
      new CustomEvent("verishield:open-command-palette", {
        detail: { opener: ev.currentTarget },
      }),
    );
  }

  return (
    <nav aria-label="Điều hướng chính" className="flex items-center gap-1.5 sm:gap-2">
      <Link
        href="/"
        aria-current={isHome ? "page" : undefined}
        className={`vs-pressable inline-flex min-h-[40px] items-center gap-2 rounded-lg border px-2.5 py-2 text-xs font-semibold sm:px-3.5 sm:text-sm ${
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
        className={`vs-pressable inline-flex min-h-[40px] items-center gap-2 rounded-lg border px-2.5 py-2 text-xs font-semibold sm:px-3.5 sm:text-sm ${
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
      <button
        type="button"
        onClick={openCommandPalette}
        aria-label="Mở bảng lệnh nhanh (Ctrl+K)"
        title="Bảng lệnh nhanh (Ctrl+K / Cmd+K)"
        className="vs-pressable inline-flex min-h-[40px] cursor-pointer items-center gap-2 rounded-lg border border-border-strong bg-surface-subtle px-2.5 py-2 text-xs font-medium text-ink-secondary hover:border-amber-400/65 hover:text-ink"
      >
        <Search className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
        <span className="hidden md:inline">Tìm nhanh</span>
        <kbd className="hidden rounded border border-border-strong bg-surface-deep px-1.5 py-0.5 font-mono text-[10px] text-ink-muted md:inline">
          Ctrl K
        </kbd>
      </button>
    </nav>
  );
}
