"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Loader2,
  MinusCircle,
  Radio,
  XCircle,
} from "lucide-react";
import * as m from "motion/react-m";
import { useEffect, useState } from "react";

import { TRACE_STAGES } from "@/lib/copy";
import { staggerDelaysMs } from "@/lib/motion/motionMath";
import type { TraceStep } from "@/lib/types";

const stageDelays = staggerDelaysMs(TRACE_STAGES.length, 40, 200);

interface LiveTracePanelProps {
  steps: TraceStep[];
  isAnalyzing: boolean;
  hasReport?: boolean;
  hasError?: boolean;
}

type StageVisualState = "pending" | "processing" | "completed" | "warning" | "skipped" | "failed";

function isTerminalStatus(status: TraceStep["status"] | undefined): boolean {
  return status === "done" || status === "warning" || status === "skipped";
}

function resolveStageState(
  step: TraceStep | undefined,
  prevStep: TraceStep | undefined,
  idx: number,
  isAnalyzing: boolean,
  hasError: boolean,
): StageVisualState {
  if (step?.status === "warning") return "warning";
  if (step?.status === "skipped") return "skipped";
  if (step?.status === "done") return "completed";
  if (step?.status === "running") return "processing";

  const isNextActiveSlot = idx === 0 || isTerminalStatus(prevStep?.status);
  if (hasError && !isAnalyzing && isNextActiveSlot) return "failed";
  if (isAnalyzing && isNextActiveSlot) return "processing";
  return "pending";
}

const STATE_BADGE: Record<StageVisualState, { label: string; style: string }> = {
  pending: {
    label: "Đang chờ",
    style: "border-border-subtle bg-surface text-ink-muted",
  },
  processing: {
    label: "Đang xử lý",
    style: "border-sky-400/55 bg-sky-500/15 text-sky-200",
  },
  completed: {
    label: "Hoàn tất",
    style: "border-emerald-500/45 bg-emerald-500/15 text-emerald-200",
  },
  warning: {
    label: "Lưu ý kỹ thuật",
    style: "border-amber-500/50 bg-amber-500/15 text-amber-200",
  },
  skipped: {
    label: "Bỏ qua",
    style: "border-border-subtle bg-surface-elevated text-ink-muted",
  },
  failed: {
    label: "Thất bại",
    style: "border-rose-500/55 bg-rose-500/18 text-rose-200",
  },
};

function PipelineBeamConnector({
  state,
}: {
  state: "idle" | "active" | "completed" | "warning" | "failed";
}) {
  const stroke =
    state === "failed"
      ? "#ef4444"
      : state === "warning"
        ? "#f59e0b"
        : state === "completed"
          ? "#10b981"
          : state === "active"
            ? "#38bdf8"
            : "#334155";

  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 36 16"
      className="hidden h-4 w-7 shrink-0 lg:block"
    >
      <line x1="2" y1="8" x2="30" y2="8" stroke="#1e293b" strokeWidth="2.5" strokeLinecap="round" />
      <line
        x1="2"
        y1="8"
        x2="30"
        y2="8"
        stroke={stroke}
        strokeWidth={state === "idle" ? "1.5" : "2.5"}
        strokeLinecap="round"
        className={state === "active" ? "vs-beam-flow" : undefined}
      />
      <polygon points="28,4 35,8 28,12" fill={stroke} />
    </svg>
  );
}

export function LiveTracePanel({
  steps,
  isAnalyzing,
  hasReport = false,
  hasError = false,
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
  const stageStates = TRACE_STAGES.map((stage, idx) => {
    const step = byId.get(stage.step_id);
    const prevStep = idx > 0 ? byId.get(TRACE_STAGES[idx - 1]?.step_id ?? "") : undefined;
    return {
      stage,
      step,
      state: resolveStageState(step, prevStep, idx, isAnalyzing, hasError),
    };
  });

  const completedCount = stageStates.filter(
    (s) => s.state === "completed" || s.state === "warning" || s.state === "skipped",
  ).length;
  const hasWarning = stageStates.some((s) => s.state === "warning");
  const totalMs = steps.reduce(
    (sum, s) => (s.status !== "running" ? sum + Math.max(0, s.duration_ms) : sum),
    0,
  );
  const canCompact = !isAnalyzing && hasReport && !hasError && steps.length > 0;
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
            Đã hoàn tất {completedCount}/{TRACE_STAGES.length} công đoạn phân tích trực tiếp
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
          className="vs-pressable inline-flex min-h-[34px] cursor-pointer items-center gap-1 rounded-lg border border-border-strong bg-surface-subtle px-2.5 py-1 text-xs font-medium text-ink-secondary hover:border-sky-400 hover:text-ink"
        >
          <span>Xem pipeline phân tích</span>
          <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </section>
    );
  }

  return (
    <section
      aria-label="Quy trình phân tích trực tiếp"
      aria-live="polite"
      className="rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-lg"
    >
      <div className="mb-3.5 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Radio
            className={`h-4 w-4 ${isAnalyzing ? "text-sky-400" : hasError ? "text-rose-400" : "text-emerald-400"}`}
            aria-hidden="true"
          />
          <h3 className="text-xs font-bold text-ink">
            Quy trình phân tích trực tiếp (SSE)
          </h3>
          <span className="tabular-num rounded-md border border-border-subtle bg-surface-subtle px-2 py-0.5 font-mono text-[10.5px] text-ink-muted">
            {completedCount}/{TRACE_STAGES.length} công đoạn
          </span>
          {!isAnalyzing && totalMs > 0 && (
            <span className="tabular-num rounded-md border border-border-subtle bg-surface-deep px-2 py-0.5 font-mono text-[10.5px] text-ink-secondary">
              {totalMs >= 1000 ? `${(totalMs / 1000).toFixed(2)}s` : `${totalMs} ms`}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {isAnalyzing && (
            <span className="inline-flex items-center gap-1.5 text-xs text-amber-300">
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              <span className="vs-shimmer-text">Đang kiểm tra...</span>
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

      {/* Directional Pipeline Stages with Real SSE Beams */}
      <ol className="flex flex-col gap-2.5 lg:flex-row lg:items-stretch lg:gap-1.5">
        {stageStates.map(({ stage, step, state }, idx) => {
          const badge = STATE_BADGE[state];
          const cardClass =
            state === "failed"
              ? "border-rose-500/60 bg-rose-500/12"
              : state === "warning"
                ? "border-amber-500/50 bg-amber-500/10"
                : state === "processing"
                  ? "vs-stage-running border-sky-400/70 bg-sky-500/10"
                  : state === "completed"
                    ? "border-emerald-500/40 bg-emerald-500/6"
                    : "border-border-subtle bg-surface-subtle";

          const connectorState: "idle" | "active" | "completed" | "warning" | "failed" =
            state === "failed"
              ? "failed"
              : state === "warning"
                ? "warning"
                : state === "completed" || state === "skipped"
                  ? "completed"
                  : state === "processing"
                    ? "active"
                    : "idle";

          return (
            <m.li
              key={stage.step_id}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.22, delay: (stageDelays[idx] ?? 0) / 1000 }}
              className="flex min-w-0 flex-1 items-center gap-1.5"
            >
              <div
                className={`flex h-full min-w-0 flex-1 flex-col justify-between rounded-xl border p-3 transition-colors ${cardClass}`}
              >
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex min-w-0 items-start gap-1.5 text-xs font-semibold text-ink">
                      {state === "failed" ? (
                        <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" aria-hidden="true" />
                      ) : state === "warning" ? (
                        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
                      ) : state === "skipped" ? (
                        <MinusCircle className="mt-0.5 h-4 w-4 shrink-0 text-ink-muted" aria-hidden="true" />
                      ) : state === "processing" ? (
                        <Loader2
                          className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-sky-400"
                          aria-hidden="true"
                        />
                      ) : state === "completed" ? (
                        <CheckCircle2
                          className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400"
                          aria-hidden="true"
                        />
                      ) : (
                        <span
                          className="mt-1 inline-block h-2.5 w-2.5 shrink-0 rounded-full bg-slate-600"
                          aria-hidden="true"
                        />
                      )}
                      <span className="leading-snug">{step?.title ?? stage.defaultTitle}</span>
                    </div>
                  </div>

                  <p className="mt-1.5 text-[11px] leading-relaxed text-ink-muted">
                    {step
                      ? step.detail
                      : state === "failed"
                        ? "Công đoạn dừng do gián đoạn kết nối hoặc lỗi xử lý từ máy chủ."
                        : state === "processing"
                          ? "Đang thực thi kiểm tra thực tế trên máy chủ..."
                          : "Đang chờ công đoạn trước hoàn tất..."}
                  </p>
                </div>

                <div className="mt-2.5 flex items-center justify-between gap-1.5 border-t border-border-subtle/60 pt-2">
                  <span
                    className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold ${badge.style}`}
                  >
                    {badge.label}
                  </span>
                  {step && step.status !== "running" && (
                    <span className="tabular-num font-mono text-[10px] text-ink-secondary">
                      {step.duration_ms} ms
                    </span>
                  )}
                </div>
              </div>

              {idx < stageStates.length - 1 && <PipelineBeamConnector state={connectorState} />}
            </m.li>
          );
        })}
      </ol>
    </section>
  );
}
