"use client";

import { ChevronDown, List } from "lucide-react";
import { useEffect, useState } from "react";

export interface TocItem {
  id: string;
  number: string;
  label: string;
}

interface DocsTocProps {
  items: readonly TocItem[];
  title?: string;
}

export function DocsToc({ items, title = "Mục lục" }: DocsTocProps) {
  const [activeId, setActiveId] = useState<string>(items[0]?.id ?? "");

  useEffect(() => {
    if (items.length === 0 || typeof IntersectionObserver === "undefined") {
      return;
    }

    const elements = items
      .map((item) => document.getElementById(item.id))
      .filter((el): el is HTMLElement => el !== null);

    if (elements.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);

        if (visible[0]?.target.id) {
          setActiveId(visible[0].target.id);
        }
      },
      {
        rootMargin: "-96px 0px -65% 0px",
        threshold: 0,
      },
    );

    for (const el of elements) {
      observer.observe(el);
    }

    return () => observer.disconnect();
  }, [items]);

  return (
    <>
      {/* Mobile / tablet collapsible TOC */}
      <details className="rounded-xl border border-border-subtle bg-surface-subtle/80 lg:hidden">
        <summary className="flex min-h-[44px] cursor-pointer list-none items-center justify-between gap-2 px-4 py-2.5 text-xs font-semibold text-ink">
          <span className="inline-flex items-center gap-2">
            <List className="h-4 w-4 text-amber-400" aria-hidden="true" />
            <span>
              {title} ({items.length} phần)
            </span>
          </span>
          <ChevronDown className="h-4 w-4 text-ink-muted" aria-hidden="true" />
        </summary>
        <nav aria-label={title} className="border-t border-border-subtle/80 px-3 py-2.5">
          <ol className="space-y-1">
            {items.map((item) => {
              const isActive = activeId === item.id;
              return (
                <li key={item.id}>
                  <a
                    href={`#${item.id}`}
                    onClick={() => setActiveId(item.id)}
                    className={`flex items-baseline gap-2 rounded-md px-2 py-1.5 text-xs leading-snug transition-colors ${
                      isActive
                        ? "bg-amber-500/10 font-semibold text-amber-200"
                        : "text-ink-muted hover:text-ink"
                    }`}
                  >
                    <span className="tabular-num shrink-0 font-mono text-[11px] text-ink-muted">
                      {item.number}
                    </span>
                    <span>{item.label}</span>
                  </a>
                </li>
              );
            })}
          </ol>
        </nav>
      </details>

      {/* Desktop sticky sidebar TOC */}
      <aside className="hidden lg:block">
        <nav
          aria-label={title}
          className="sticky top-24 max-h-[calc(100vh-7.5rem)] overflow-y-auto pr-2"
        >
          <p className="mb-3 text-[11px] font-semibold tracking-wider text-ink-muted uppercase">
            {title}
          </p>
          <ol className="space-y-0.5 border-l border-border-subtle/80">
            {items.map((item) => {
              const isActive = activeId === item.id;
              return (
                <li key={item.id}>
                  <a
                    href={`#${item.id}`}
                    onClick={() => setActiveId(item.id)}
                    aria-current={isActive ? "location" : undefined}
                    className={`-ml-px flex items-baseline gap-2 border-l-2 py-1.5 pl-3 text-xs leading-snug transition-colors ${
                      isActive
                        ? "border-amber-400 font-semibold text-ink"
                        : "border-transparent text-ink-muted hover:border-border-strong hover:text-ink-secondary"
                    }`}
                  >
                    <span className="tabular-num shrink-0 font-mono text-[11px] opacity-75">
                      {item.number}
                    </span>
                    <span>{item.label}</span>
                  </a>
                </li>
              );
            })}
          </ol>
        </nav>
      </aside>
    </>
  );
}
