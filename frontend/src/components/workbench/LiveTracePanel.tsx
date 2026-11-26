"use client";

import { AlertTriangle, CheckCircle2, Loader2, MinusCircle } from "lucide-react";

import type { TraceStep } from "@/lib/types";

interface LiveTracePanelProps {
  steps: TraceStep[];
  isAnalyzing: boolean;
}

const EXPECTED_PIPELINE_STAGES: Array<{ step_id: string; defaultTitle: string }> = [
  {
    step_id: "media_forensics",
    defaultTitle: "Pháp y ảnh (ELA/dHash/VietQR) & Chuyển ngữ cục bộ",
  },
  {
    step_id: "cyber_guardrails",
    defaultTitle: "Kiểm tra Block Rules, SSRF/Punycode URL & Guardrails",
  },
  {
    step_id: "onnx_and_kb",
    defaultTitle: "Phân loại Ngữ nghĩa E5 ONNX & Đối chiếu 20 Kịch bản VN",
  },
  {
    step_id: "multimodal_calibration",
    defaultTitle: "Thẩm định Đa phương thức & Hiệu chuẩn Điểm Rủi ro",
  },
];

function isTerminalStatus(status: TraceStep["status"] | undefined): boolean {
  return status === "done" || status === "warning" || status === "skipped";
}

export function LiveTracePanel({ steps, isAnalyzing }: LiveTracePanelProps) {
  if (!isAnalyzing && steps.length === 0) {
    return null;
  }

  const byId = new Map(steps.map((s) => [s.step_id, s]));

  return (
    <section
      aria-label="Tiến trình điều tra thời gian thực"
      aria-live="polite"
      className="rounded-2xl border border-slate-800 bg-[#111827]/95 p-4 shadow-lg"
    >
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-xs font-bold tracking-wide text-slate-200 uppercase">
          Luồng Điều tra Thời gian thực (SSE Pipeline Trace)
        </h3>
        {isAnalyzing && (
          <span className="inline-flex items-center gap-1.5 font-[family-name:var(--font-mono)] text-xs text-amber-300">
            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            <span>Đang xử lý...</span>
          </span>
        )}
      </div>

      <ol className="grid grid-cols-1 gap-2.5 md:grid-cols-2 lg:grid-cols-4">
        {EXPECTED_PIPELINE_STAGES.map((stage, idx) => {
          const step = byId.get(stage.step_id);
          const prevStep = idx > 0 ? byId.get(EXPECTED_PIPELINE_STAGES[idx - 1]?.step_id ?? "") : undefined;
          const isExplicitRunning = step?.status === "running";
          const isInferredRunning =
            !step && isAnalyzing && (idx === 0 || isTerminalStatus(prevStep?.status));
          const isRunning = isExplicitRunning || isInferredRunning;

          return (
            <li
              key={stage.step_id}
              className={`rounded-xl border p-3 transition-colors ${
                step?.status === "warning"
                  ? "border-amber-500/40 bg-amber-500/10"
                  : isRunning
                    ? "border-sky-500/50 bg-sky-500/10"
                    : step
                      ? "border-emerald-500/30 bg-emerald-500/5"
                      : "border-slate-800 bg-[#0b1120]"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-100">
                  {step?.status === "warning" ? (
                    <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
                  ) : step?.status === "skipped" ? (
                    <MinusCircle className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
                  ) : isRunning ? (
                    <Loader2 className="h-4 w-4 shrink-0 animate-spin text-sky-400" aria-hidden="true" />
                  ) : step ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
                  ) : (
                    <span className="inline-block h-2.5 w-2.5 rounded-full bg-slate-700" aria-hidden="true" />
                  )}
                  <span className="leading-snug">{step?.title ?? stage.defaultTitle}</span>
                </div>
                {step && step.status !== "running" && (
                  <span className="shrink-0 rounded bg-slate-900 px-1.5 py-0.5 font-[family-name:var(--font-mono)] text-[10px] text-slate-300">
                    {step.duration_ms}ms
                  </span>
                )}
              </div>
              <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">
                {step
                  ? step.detail
                  : isRunning
                    ? "Đang thực thi bước kiểm định..."
                    : "Đang chờ bước trước..."}
              </p>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
