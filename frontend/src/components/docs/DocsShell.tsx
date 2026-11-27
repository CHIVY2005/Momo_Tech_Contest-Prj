import { AlertTriangle, ChevronRight, Info, ShieldAlert } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { DocsToc, type TocItem } from "./DocsToc";

interface DocsShellProps {
  breadcrumbLabel: string;
  title: string;
  description: string;
  metaItems: readonly { label: string; value: string }[];
  tocItems: readonly TocItem[];
  children: ReactNode;
}

export function DocsShell({
  breadcrumbLabel,
  title,
  description,
  metaItems,
  tocItems,
  children,
}: DocsShellProps) {
  return (
    <div className="space-y-6 pb-8">
      <header className="border-b border-border-subtle/90 pb-6">
        <nav aria-label="Đường dẫn trang" className="mb-3 flex items-center gap-1.5 text-xs text-ink-muted">
          <Link href="/" className="transition-colors hover:text-ink">
            Trang chủ
          </Link>
          <ChevronRight className="h-3.5 w-3.5 opacity-60" aria-hidden="true" />
          <span className="text-ink-secondary">{breadcrumbLabel}</span>
        </nav>

        <h1 className="text-2xl font-bold tracking-tight text-ink sm:text-3xl">{title}</h1>
        <p className="mt-2 max-w-3xl text-sm leading-relaxed text-ink-secondary sm:text-base">
          {description}
        </p>

        {metaItems.length > 0 && (
          <dl className="mt-4 flex flex-wrap gap-x-6 gap-y-2 border-t border-border-subtle/60 pt-3.5 text-xs">
            {metaItems.map((item) => (
              <div key={item.label} className="flex items-baseline gap-1.5">
                <dt className="text-ink-muted">{item.label}:</dt>
                <dd className="font-medium text-ink-secondary">{item.value}</dd>
              </div>
            ))}
          </dl>
        )}
      </header>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-[248px_minmax(0,1fr)] lg:gap-10">
        <DocsToc items={tocItems} />

        <article className="min-w-0 max-w-4xl space-y-10 text-sm leading-relaxed text-ink-secondary">
          {children}
        </article>
      </div>
    </div>
  );
}

interface DocSectionProps {
  id: string;
  number: string;
  title: string;
  children: ReactNode;
}

export function DocSection({ id, number, title, children }: DocSectionProps) {
  const headingId = `${id}-heading`;
  return (
    <section
      id={id}
      aria-labelledby={headingId}
      className="scroll-mt-24 border-t border-border-subtle/70 pt-7 first:border-t-0 first:pt-0"
    >
      <div className="mb-3.5 flex items-baseline gap-2.5">
        <span className="tabular-num font-mono text-xs font-semibold text-amber-400/90">
          {number}
        </span>
        <h2
          id={headingId}
          className="group text-lg font-bold tracking-tight text-ink sm:text-xl"
        >
          <a
            href={`#${id}`}
            className="inline-flex items-baseline gap-2 rounded focus-visible:outline-amber-400"
          >
            <span>{title}</span>
            <span
              aria-hidden="true"
              className="font-mono text-sm font-normal text-ink-muted opacity-0 transition-opacity group-hover:opacity-100"
            >
              #
            </span>
          </a>
        </h2>
      </div>
      <div className="space-y-3.5">{children}</div>
    </section>
  );
}

interface DocCalloutProps {
  tone?: "info" | "warning" | "caution";
  title: string;
  children: ReactNode;
}

export function DocCallout({ tone = "info", title, children }: DocCalloutProps) {
  const styles = {
    info: {
      wrapper: "border-sky-500/35 bg-sky-500/8",
      title: "text-sky-200",
      Icon: Info,
      iconClass: "text-sky-400",
    },
    warning: {
      wrapper: "border-amber-500/40 bg-amber-500/8",
      title: "text-amber-200",
      Icon: AlertTriangle,
      iconClass: "text-amber-400",
    },
    caution: {
      wrapper: "border-rose-500/40 bg-rose-500/8",
      title: "text-rose-200",
      Icon: ShieldAlert,
      iconClass: "text-rose-400",
    },
  }[tone];

  const Icon = styles.Icon;

  return (
    <aside
      className={`rounded-xl border px-4 py-3.5 text-xs leading-relaxed text-ink-secondary ${styles.wrapper}`}
    >
      <div className={`mb-1.5 flex items-center gap-2 font-semibold ${styles.title}`}>
        <Icon className={`h-4 w-4 shrink-0 ${styles.iconClass}`} aria-hidden="true" />
        <span>{title}</span>
      </div>
      <div className="space-y-1.5">{children}</div>
    </aside>
  );
}

interface DocTableProps {
  caption: string;
  headers: readonly string[];
  rows: readonly (readonly ReactNode[])[];
}

export function DocTable({ caption, headers, rows }: DocTableProps) {
  return (
    <div className="overflow-x-auto rounded-xl border border-border-subtle bg-surface-subtle/60">
      <table className="w-full min-w-[540px] border-collapse text-left text-xs">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="border-b border-border-subtle bg-surface text-ink-muted">
            {headers.map((header) => (
              <th key={header} scope="col" className="px-3.5 py-2.5 font-semibold">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border-subtle/70">
          {rows.map((cells, rowIdx) => (
            <tr key={rowIdx} className="align-top transition-colors hover:bg-surface/60">
              {cells.map((cell, cellIdx) => (
                <td
                  key={cellIdx}
                  className={`px-3.5 py-2.5 leading-relaxed ${
                    cellIdx === 0 ? "font-medium text-ink" : "text-ink-secondary"
                  }`}
                >
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ImplementationStatus({
  status,
}: {
  status: "implemented" | "experimental" | "planned";
}) {
  const cfg = {
    implemented: {
      label: "Đã triển khai",
      className: "border-emerald-500/35 bg-emerald-500/10 text-emerald-300",
    },
    experimental: {
      label: "Thử nghiệm / Tùy chọn",
      className: "border-amber-500/40 bg-amber-500/10 text-amber-200",
    },
    planned: {
      label: "Dự kiến phát triển",
      className: "border-border-strong bg-surface-subtle text-ink-muted",
    },
  }[status];

  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium ${cfg.className}`}
    >
      {cfg.label}
    </span>
  );
}
