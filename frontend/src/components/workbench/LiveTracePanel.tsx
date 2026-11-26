"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Loader2,
  MinusCircle,
} from "lucide-react";
import { useEffect, useState } from "react";

import { TRACE_STAGES } from "@/lib/copy";
import type { TraceStep } from "@/lib/types";

interface LiveTracePanelProps {
  steps: TraceStep[];
  isAnalyzing: boolean;
  hasReport?: boolean;
}

function isTerminalStatus(status: TraceStep["status"] | undefined): boolean {
  return status === "done" || status === "warning" || status === "skipped";
}

export function LiveTracePanel({
  steps,
  isAnalyzing,
  hasReport = false,
}: LiveTracePanelProps) {
  const [manualExpanded, setManualExpanded] = useState(false);

  useEffect(() => {
    if (isAnalyzing) {
      setManualExpanded(false);
    }
  }, [isAnalyzing]);

  if (!isAnalyzing && steps.length === 0) {
    return null;
  }

  const byId = new Map(steps.map((s) => [s.step_id, s]));
  const completedCount = TRACE_STAGES.filter((st) =>
    isTerminalStatus(byId.get(st.step_id)?.status),
  ).length;
  const hasWarning = steps.some((s) => s.status === "warning");
  const totalMs = steps.reduce(
    (sum, s) => (s.status !== "running" ? sum + Math.max(0, s.duration_ms) : sum),
    0,
  );
  const canCompact = !isAnalyzing && hasReport && steps.length > 0;
  const isExpanded = !canCompact || manualExpanded;

  if (!isExpanded) {
    return (
      <section
        aria-label="Tóm tắt tiến trình kiểm tra"
        className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border-subtle bg-surface/95 px-4 py-2.5 shadow-sm"
      >
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {hasWarning ? (
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
          ) : (
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
          )}
          <span className="font-semibold text-ink">
            Đã hoàn tất {completedCount}/{TRACE_STAGES.length} bước kiểm tra
          </span>
          <span className="tabular-num rounded bg-surface-subtle px-2 py-0.5 font-mono text-[11px] text-ink-secondary">
            {totalMs >= 1000 ? `${(totalMs / 1000).toFixed(2)} giây` : `${totalMs} ms`}
          </span>
          {hasWarning && (
            <span className="rounded border border-amber-500/35 bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-200">
              Có lưu ý kỹ thuật
            </span>
          )}
        </div>

        <button
          type="button"
          aria-expanded={false}
          onClick={() => setManualExpanded(true)}
          className="inline-flex min-h-[34px] cursor-pointer items-center gap-1 rounded-lg border border-border-strong bg-surface-subtle px-2.5 py-1 text-xs font-medium text-ink-secondary hover:border-sky-400 hover:text-ink"
        >
          <span>Xem tiến trình kiểm tra</span>
          <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </section>
    );
  }

  return (
    <section
      aria-label="Tiến trình kiểm tra"
      aria-live="polite"
      className="rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-lg"
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <h3 className="text-xs font-bold text-ink-secondary">Tiến trình kiểm tra</h3>
          <span className="tabular-num rounded bg-surface-subtle px-2 py-0.5 font-mono text-[11px] text-ink-muted">
            {completedCount}/{TRACE_STAGES.length} bước
          </span>
        </div>

        <div className="flex items-center gap-2">
          {isAnalyzing && (
            <span className="inline-flex items-center gap-1.5 text-xs text-amber-300">
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              <span>Đang kiểm tra...</span>
            </span>
          )}
          {canCompact && (
            <button
              type="button"
              aria-expanded={true}
              onClick={() => setManualExpanded(false)}
              className="inline-flex min-h-[32px] cursor-pointer items-center gap-1 rounded-lg border border-border-strong bg-surface-subtle px-2.5 py-1 text-xs font-medium text-ink-secondary hover:border-sky-400 hover:text-ink"
            >
              <span>Thu gọn</span>
              <ChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      <ol className="grid grid-cols-1 gap-2.5 md:grid-cols-2 lg:grid-cols-4">
        {TRACE_STAGES.map((stage, idx) => {
          const step = byId.get(stage.step_id);
          const prevStep =
            idx > 0 ? byId.get(TRACE_STAGES[idx - 1]?.step_id ?? "") : undefined;
          const isExplicitRunning = step?.status === "running";
          const isInferredRunning =
            !step && isAnalyzing && (idx === 0 || isTerminalStatus(prevStep?.status));
          const isRunning = isExplicitRunning || isInferredRunning;

          return (
            <li
              key={stage.step_id}
              className={`rounded-xl border p-3 transition-colors ${
                step?.status === "warning"
                  ? "border-amber-500/45 bg-amber-500/10"
                  : isRunning
                    ? "border-sky-500/55 bg-sky-500/10"
                    : step
                      ? "border-emerald-500/35 bg-emerald-500/5"
                      : "border-border-subtle bg-surface-subtle"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-ink">
                  {step?.status === "warning" ? (
                    <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
                  ) : step?.status === "skipped" ? (
                    <MinusCircle className="h-4 w-4 shrink-0 text-ink-muted" aria-hidden="true" />
                  ) : isRunning ? (
                    <Loader2 className="h-4 w-4 shrink-0 animate-spin text-sky-400" aria-hidden="true" />
                  ) : step ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
                  ) : (
                    <span
                      className="inline-block h-2.5 w-2.5 shrink-0 rounded-full bg-slate-600"
                      aria-hidden="true"
                    />
                  )}
                  <span className="leading-snug">{step?.title ?? stage.defaultTitle}</span>
                </div>
                {step && step.status !== "running" && (
                  <span className="tabular-num shrink-0 rounded bg-surface-elevated px-1.5 py-0.5 font-mono text-[10px] text-ink-secondary">
                    {step.duration_ms} ms
                  </span>
                )}
              </div>
              <p className="mt-1.5 text-[11px] leading-relaxed text-ink-muted">
                {step
                  ? step.detail
                  : isRunning
                    ? "Đang thực hiện kiểm tra..."
                    : "Chờ bước trước hoàn tất..."}
              </p>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
