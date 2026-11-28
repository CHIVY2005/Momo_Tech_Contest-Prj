"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Loader2,
  Radio,
  XCircle,
} from "lucide-react";
import * as m from "motion/react-m";
import { useEffect, useMemo, useState } from "react";

import { PipelineStageGlyph, type StageGlyphState } from "@/components/motion/PipelineStageGlyph";
import { useViewportMotion } from "@/components/motion/useViewportMotion";
import {
  classifyTraceStageVisual,
  selectVisibleBackendTraceSteps,
} from "@/lib/motion/cyberMotion";
import { staggerDelaysMs } from "@/lib/motion/motionMath";
import type { TraceStep } from "@/lib/types";

interface LiveTracePanelProps {
  steps: TraceStep[];
  isAnalyzing: boolean;
  hasReport?: boolean;
  hasError?: boolean;
}

const STATE_BADGE: Record<StageGlyphState, { label: string; style: string }> = {
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
  failed: {
    label: "Thất bại",
    style: "border-rose-500/55 bg-rose-500/18 text-rose-200",
  },
};

function resolveBackendStepState(
  step: TraceStep,
  isAnalyzing: boolean,
  hasError: boolean,
): StageGlyphState {
  if (step.status === "warning") return "warning";
  if (step.status === "done") return "completed";
  if (step.status === "running") {
    return hasError && !isAnalyzing ? "failed" : "processing";
  }
  return "completed";
}

function PipelineBeamConnector({
  state,
}: {
  state: "active" | "completed" | "warning" | "failed";
}) {
  const stroke =
    state === "failed"
      ? "#ef4444"
      : state === "warning"
        ? "#f59e0b"
        : state === "completed"
          ? "#10b981"
          : "#38bdf8";

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
        strokeWidth="2.5"
        strokeLinecap="round"
        className={state === "active" ? "vs-beam-flow" : undefined}
      />
      <polygon points="28,4 35,8 28,12" fill={stroke} />
    </svg>
  );
}

/**
 * Backend-driven SSE analysis progress panel.
 * Renders stage cards ONLY for stages actually reported by the backend (`steps`), separating
 * `skipped` stages so non-applicable sub-pipelines (e.g. OCR/QR on text-only checks) are never
 * fabricated. Each stage renders a dedicated cybersecurity SVG glyph matching its real domain.
 */
export function LiveTracePanel({
  steps,
  isAnalyzing,
  hasReport = false,
  hasError = false,
}: LiveTracePanelProps) {
  const [manualExpanded, setManualExpanded] = useState(false);
  const { ref: sectionRef, shouldAnimate } = useViewportMotion<HTMLElement>();

  useEffect(() => {
    if (isAnalyzing) {
      setManualExpanded(false);
    }
  }, [isAnalyzing]);

  const { activeSteps, skippedSteps } = useMemo(
    () => selectVisibleBackendTraceSteps(steps),
    [steps],
  );
  const stageDelays = useMemo(
    () => staggerDelaysMs(activeSteps.length, 40, 200),
    [activeSteps.length],
  );

  if (!isAnalyzing && steps.length === 0) {
    return null;
  }

  const stageItems = activeSteps.map((step) => ({
    step,
    kind: classifyTraceStageVisual(step),
    state: resolveBackendStepState(step, isAnalyzing, hasError),
  }));

  const completedCount = stageItems.filter(
    (item) => item.state === "completed" || item.state === "warning",
  ).length;
  const hasRunningStep = stageItems.some((item) => item.state === "processing");
  const hasWarning = stageItems.some((item) => item.state === "warning");
  const totalMs = steps.reduce(
    (sum, s) => (s.status !== "running" ? sum + Math.max(0, s.duration_ms) : sum),
    0,
  );
  const canCompact = !isAnalyzing && hasReport && !hasError && activeSteps.length > 0;
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
            Đã hoàn tất {completedCount} công đoạn phân tích trực tiếp
          </span>
          <span className="tabular-num rounded bg-surface-subtle px-2 py-0.5 font-mono text-[11px] text-ink-secondary">
            {totalMs >= 1000 ? `${(totalMs / 1000).toFixed(2)} giây` : `${totalMs} ms`}
          </span>
          {skippedSteps.length > 0 && (
            <span
              title={skippedSteps.map((s) => `${s.title}: ${s.detail}`).join("\n")}
              className="rounded border border-border-subtle bg-surface-subtle px-2 py-0.5 text-[11px] text-ink-muted"
            >
              Không áp dụng {skippedSteps.length} công đoạn
            </span>
          )}
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
      ref={sectionRef}
      data-testid="live-trace-panel"
      data-motion-state={shouldAnimate ? "running" : "paused"}
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
          {activeSteps.length > 0 && (
            <span className="tabular-num rounded-md border border-border-subtle bg-surface-subtle px-2 py-0.5 font-mono text-[10.5px] text-ink-muted">
              {completedCount}/{activeSteps.length} công đoạn đã ghi nhận
            </span>
          )}
          {skippedSteps.length > 0 && (
            <span
              title={skippedSteps.map((s) => `${s.title}: ${s.detail}`).join("\n")}
              className="rounded-md border border-border-subtle bg-surface-deep px-2 py-0.5 text-[10.5px] text-ink-muted"
            >
              Bỏ qua {skippedSteps.length} mục không áp dụng
            </span>
          )}
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

      {stageItems.length === 0 ? (
        <div className="vs-stage-running flex items-center gap-3 rounded-xl border border-sky-400/55 bg-sky-500/8 px-3.5 py-3 text-xs text-ink-secondary">
          <Loader2 className="h-4 w-4 shrink-0 animate-spin text-sky-400" aria-hidden="true" />
          <div className="min-w-0">
            <p className="font-semibold text-ink">
              Đang khởi chạy phiên phân tích trên máy chủ
            </p>
            <p className="mt-0.5 text-[11px] text-ink-muted">
              Các công đoạn thực tế sẽ hiển thị ngay khi máy chủ phản hồi tín hiệu xử lý.
            </p>
          </div>
        </div>
      ) : (
        <ol className="flex flex-col gap-2.5 lg:flex-row lg:items-stretch lg:gap-1.5">
          {stageItems.map(({ step, kind, state }, idx) => {
            const badge = STATE_BADGE[state];
            const cardClass =
              state === "failed"
                ? "border-rose-500/60 bg-rose-500/12"
                : state === "warning"
                  ? "border-amber-500/50 bg-amber-500/10"
                  : state === "processing"
                    ? "vs-stage-running border-sky-400/70 bg-sky-500/10"
                    : "border-emerald-500/40 bg-emerald-500/6";

            const showConnector =
              idx < stageItems.length - 1 || (isAnalyzing && !hasRunningStep);
            const connectorState: "active" | "completed" | "warning" | "failed" =
              state === "failed"
                ? "failed"
                : state === "warning"
                  ? "warning"
                  : idx === stageItems.length - 1 && isAnalyzing
                    ? "active"
                    : state === "processing"
                      ? "active"
                      : "completed";

            return (
              <m.li
                key={step.step_id}
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.22, delay: (stageDelays[idx] ?? 0) / 1000 }}
                className="flex min-w-0 flex-1 items-center gap-1.5"
              >
                <div
                  className={`flex h-full min-w-0 flex-1 flex-col justify-between rounded-xl border p-3 transition-colors ${cardClass}`}
                >
                  <div>
                    <div className="flex items-start gap-2 text-xs font-semibold text-ink">
                      <PipelineStageGlyph kind={kind} state={state} />
                      <span className="min-w-0 flex-1 leading-snug">{step.title}</span>
                    </div>

                    <p className="mt-1.5 text-[11px] leading-relaxed text-ink-muted">
                      {step.detail}
                    </p>
                  </div>

                  <div className="mt-2.5 flex items-center justify-between gap-1.5 border-t border-border-subtle/60 pt-2">
                    <span
                      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold ${badge.style}`}
                    >
                      {state === "failed" ? (
                        <XCircle className="h-3 w-3 shrink-0" aria-hidden="true" />
                      ) : state === "warning" ? (
                        <AlertTriangle className="h-3 w-3 shrink-0" aria-hidden="true" />
                      ) : state === "processing" ? (
                        <Loader2 className="h-3 w-3 shrink-0 animate-spin" aria-hidden="true" />
                      ) : (
                        <CheckCircle2 className="h-3 w-3 shrink-0" aria-hidden="true" />
                      )}
                      <span>{badge.label}</span>
                    </span>
                    {step.status !== "running" && (
                      <span className="tabular-num font-mono text-[10px] text-ink-secondary">
                        {step.duration_ms} ms
                      </span>
                    )}
                  </div>
                </div>

                {showConnector && <PipelineBeamConnector state={connectorState} />}
              </m.li>
            );
          })}

          {isAnalyzing && !hasRunningStep && (
            <li className="flex min-w-0 flex-1 items-center">
              <div className="vs-stage-running flex h-full min-w-0 flex-1 flex-col justify-between rounded-xl border border-sky-400/65 bg-sky-500/10 p-3">
                <div className="flex items-start gap-2 text-xs font-semibold text-ink">
                  <Loader2
                    className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-sky-400"
                    aria-hidden="true"
                  />
                  <span className="leading-snug">Đang xử lý công đoạn tiếp theo</span>
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-ink-muted">
                  Đang chờ máy chủ hoàn tất và gửi trạng thái công đoạn kế tiếp qua SSE...
                </p>
                <div className="mt-2.5 border-t border-border-subtle/60 pt-2">
                  <span className="inline-block rounded border border-sky-400/55 bg-sky-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-sky-200">
                    Đang chờ tín hiệu
                  </span>
                </div>
              </div>
            </li>
          )}
        </ol>
      )}
    </section>
  );
}
