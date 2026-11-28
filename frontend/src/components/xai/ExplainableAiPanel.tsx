"use client";

import {
  Activity,
  ArrowUpRight,
  BarChart3,
  CheckCircle2,
  Clock,
  Cpu,
  Info,
  Layers,
  ShieldAlert,
} from "lucide-react";
import dynamic from "next/dynamic";
import { useMemo } from "react";

import {
  formatClassifierLabel,
  formatEvidenceSource,
  SEVERITY_COPY,
  VERDICT_COPY,
} from "@/lib/copy";
import {
  buildClassifierDistribution,
  buildDetectedSignals,
  buildEvidenceDistribution,
  buildMeasuredSignalFactors,
  buildTraceTimeline,
  type EvidenceTabKey,
} from "@/lib/explainableAi";
import type { AnalysisReport, SeverityLevel } from "@/lib/types";

const RiskScoreGaugeChart = dynamic(
  () => import("./XaiCharts").then((mod) => mod.RiskScoreGaugeChart),
  {
    ssr: false,
    loading: () => (
      <div
        aria-hidden="true"
        className="flex h-[196px] w-full items-center justify-center rounded-xl border border-border-subtle/70 bg-surface-deep/60 text-xs text-ink-muted"
      >
        Đang tải biểu đồ chỉ số rủi ro...
      </div>
    ),
  },
);

const ClassifierDistributionChart = dynamic(
  () => import("./XaiCharts").then((mod) => mod.ClassifierDistributionChart),
  {
    ssr: false,
    loading: () => (
      <div
        aria-hidden="true"
        className="flex h-[220px] w-full items-center justify-center rounded-xl border border-border-subtle/70 bg-surface-deep/60 text-xs text-ink-muted"
      >
        Đang tải biểu đồ phân loại E5 ONNX...
      </div>
    ),
  },
);

interface ExplainableAiPanelProps {
  report: AnalysisReport;
  onNavigateToEvidence: (tab: EvidenceTabKey, source?: string) => void;
}

const SEVERITY_BADGE: Record<SeverityLevel, string> = {
  CRITICAL: "border-rose-500/50 bg-rose-500/18 text-rose-200",
  HIGH: "border-orange-500/50 bg-orange-500/15 text-orange-200",
  MEDIUM: "border-amber-500/45 bg-amber-500/15 text-amber-200",
  LOW: "border-sky-500/45 bg-sky-500/15 text-sky-200",
  INFO: "border-border-strong bg-surface-elevated text-ink-secondary",
};

const SEVERITY_BAR: Record<SeverityLevel, string> = {
  CRITICAL: "bg-rose-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-amber-400",
  LOW: "bg-sky-400",
  INFO: "bg-slate-400",
};

export function ExplainableAiPanel({
  report,
  onNavigateToEvidence,
}: ExplainableAiPanelProps) {
  const signals = useMemo(() => buildDetectedSignals(report), [report]);
  const measuredFactors = useMemo(() => buildMeasuredSignalFactors(report), [report]);
  const classifierItems = useMemo(
    () => buildClassifierDistribution(report.classifier),
    [report.classifier],
  );
  const evidenceDist = useMemo(
    () => buildEvidenceDistribution(report.evidence),
    [report.evidence],
  );
  const timeline = useMemo(() => buildTraceTimeline(report.trace), [report.trace]);

  return (
    <section
      aria-labelledby="xai-panel-heading"
      className="space-y-4 rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-lg sm:p-5"
    >
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border-subtle pb-3.5">
        <div>
          <div className="flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-amber-400" aria-hidden="true" />
            <h3 id="xai-panel-heading" className="text-sm font-bold text-ink">
              Giải thích kết quả phân tích (Explainable AI)
            </h3>
          </div>
          <p className="mt-1 text-xs leading-relaxed text-ink-muted">
            Trình bày các tín hiệu kỹ thuật và mô hình thực tế đã tạo nên đánh giá rủi ro; nhấp vào
            từng tín hiệu để mở bằng chứng tương ứng.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          <span className="tabular-num rounded-lg border border-border-subtle bg-surface-subtle px-2.5 py-1 font-mono text-ink-secondary">
            Độ tin cậy hệ thống: <strong className="text-ink">{Math.round(report.confidence * 100)}%</strong>
          </span>
          {report.degraded_mode && (
            <span className="rounded-lg border border-amber-500/40 bg-amber-500/12 px-2.5 py-1 font-medium text-amber-200">
              Chế độ dự phòng cục bộ (Tầng 1)
            </span>
          )}
        </div>
      </div>

      {/* Epistemic distinction: Risk Score != Statistical Fraud Probability */}
      <div className="flex items-start gap-2.5 rounded-xl border border-sky-500/30 bg-sky-500/8 px-3.5 py-2.5 text-[11px] leading-relaxed text-sky-100">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" aria-hidden="true" />
        <p>
          <strong className="font-semibold text-sky-200">Phân biệt chỉ số rủi ro và xác suất:</strong>{" "}
          <strong>Điểm rủi ro ({report.risk_score}/100)</strong> là chỉ số tổng hợp từ kiểm tra kỹ
          thuật Tầng 1, ngưỡng sàn an toàn, bộ phân loại E5 ONNX và suy luận ngữ cảnh (khi bật) —{" "}
          <strong>không đồng nhất với xác suất thống kê xảy ra lừa đảo</strong>. Chỉ các thành phần
          thực sự trả về số đo từ máy chủ mới được hiển thị bên dưới.
        </p>
      </div>

      {/* Row 1: Risk Score Gauge + Measured Signal Components */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        <div className="flex flex-col justify-between rounded-xl border border-border-subtle bg-surface-subtle p-4 lg:col-span-5">
          <div className="flex items-center justify-between gap-2">
            <h4 className="text-xs font-bold text-ink">Chỉ số rủi ro tổng hợp</h4>
            <span className="rounded-md border border-border-strong bg-surface px-2 py-0.5 text-[10px] font-semibold text-ink-secondary">
              {VERDICT_COPY[report.verdict].shortLabel}
            </span>
          </div>

          <RiskScoreGaugeChart
            score={report.risk_score}
            verdict={report.verdict}
            verdictLabel={VERDICT_COPY[report.verdict].label}
          />

          <div className="tabular-num grid grid-cols-4 gap-1 border-t border-border-subtle/70 pt-2.5 text-center text-[10px] text-ink-muted">
            <span className="text-emerald-300">0–24 Thấp</span>
            <span className="text-amber-300">25–49 Thận trọng</span>
            <span className="text-orange-300">50–74 Cao</span>
            <span className="text-rose-300">75–100 Rất cao</span>
          </div>
        </div>

        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-4 lg:col-span-7">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <Layers className="h-4 w-4 text-sky-400" aria-hidden="true" />
              <h4 className="text-xs font-bold text-ink">Số đo thành phần thực tế</h4>
            </div>
            <span className="text-[11px] text-ink-muted">
              Không cộng tuyến tính (áp dụng max + ngưỡng sàn an toàn)
            </span>
          </div>

          {measuredFactors.length === 0 ? (
            <p className="rounded-lg border border-border-subtle bg-surface p-3 text-xs text-ink-muted">
              Hồ sơ này không có chỉ số định lượng thành phần từ bộ kiểm tra hình ảnh, biên lai, URL
              hoặc E5 ONNX.
            </p>
          ) : (
            <div className="space-y-3">
              {measuredFactors.map((factor) => {
                const barTone =
                  factor.score >= 75
                    ? "bg-rose-500"
                    : factor.score >= 50
                      ? "bg-orange-500"
                      : factor.score >= 25
                        ? "bg-amber-400"
                        : "bg-emerald-500";
                return (
                  <div
                    key={factor.id}
                    className="rounded-lg border border-border-subtle/80 bg-surface p-2.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <button
                        type="button"
                        onClick={() => onNavigateToEvidence(factor.evidenceTab)}
                        className="inline-flex cursor-pointer items-center gap-1 font-semibold text-ink transition-colors hover:text-amber-200"
                      >
                        <span>{factor.label}</span>
                        <ArrowUpRight className="h-3 w-3 text-ink-muted" aria-hidden="true" />
                      </button>
                      <span className="tabular-num font-mono text-xs font-bold text-ink">
                        {factor.unit === "raw_score_pct"
                          ? `${factor.score}%`
                          : `${factor.score}/100`}
                      </span>
                    </div>
                    <div
                      aria-hidden="true"
                      className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-surface-elevated"
                    >
                      <div
                        className={`h-full rounded-full ${barTone}`}
                        style={{ width: `${Math.max(2, Math.min(100, factor.score))}%` }}
                      />
                    </div>
                    <p className="mt-1.5 text-[11px] leading-snug text-ink-muted">{factor.note}</p>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Row 2: Detected Signals (clickable links to Evidence) */}
      <div className="rounded-xl border border-border-subtle bg-surface-subtle p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            <ShieldAlert className="h-4 w-4 text-amber-400" aria-hidden="true" />
            <h4 className="text-xs font-bold text-ink">
              Tín hiệu phát hiện liên kết bằng chứng ({signals.length})
            </h4>
          </div>
          <span className="text-[11px] text-ink-muted">
            Chọn bất kỳ tín hiệu nào để nhảy tới bằng chứng gốc
          </span>
        </div>

        {signals.length === 0 ? (
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/8 px-3 py-2.5 text-xs text-emerald-200">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
            <span>Chưa ghi nhận tín hiệu rủi ro nổi bật nào từ dữ liệu đã gửi.</span>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {signals.map((sig) => (
              <button
                key={sig.id}
                type="button"
                onClick={() => onNavigateToEvidence(sig.evidenceTab, sig.evidenceSource)}
                className="vs-pressable group flex cursor-pointer flex-col justify-between gap-1.5 rounded-xl border border-border-subtle bg-surface p-3 text-left hover:border-amber-400/65 hover:bg-surface-elevated/70"
              >
                <div className="flex flex-wrap items-center justify-between gap-1.5">
                  <span className="text-xs font-semibold text-ink group-hover:text-amber-200">
                    {sig.label}
                  </span>
                  <div className="flex items-center gap-1">
                    <span
                      className={`rounded border px-1.5 py-0.5 text-[10px] font-bold ${
                        SEVERITY_BADGE[sig.severity]
                      }`}
                    >
                      {SEVERITY_COPY[sig.severity]}
                    </span>
                  </div>
                </div>
                <p className="text-[11px] leading-relaxed text-ink-muted">{sig.detail}</p>
                <div className="flex items-center justify-between pt-1 text-[10px]">
                  <span
                    className={
                      sig.verified
                        ? "font-medium text-emerald-300"
                        : "font-medium text-sky-300"
                    }
                  >
                    {sig.verified ? "Kiểm tra kỹ thuật xác định" : "Phân tích ngữ cảnh / hành vi"}
                  </span>
                  <span className="inline-flex items-center gap-0.5 font-semibold text-amber-300">
                    <span>Xem bằng chứng</span>
                    <ArrowUpRight className="h-3 w-3" aria-hidden="true" />
                  </span>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Row 3: E5 ONNX 7-Class Distribution (only when real class_probabilities exist) + Evidence Distribution */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        {classifierItems.length > 0 && report.classifier && (
          <div className="rounded-xl border border-border-subtle bg-surface-subtle p-4 lg:col-span-7">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1.5">
                <Cpu className="h-4 w-4 text-sky-400" aria-hidden="true" />
                <h4 className="text-xs font-bold text-ink">
                  Phân bố 7 lớp ngữ nghĩa (E5-Small INT8 ONNX)
                </h4>
              </div>
              <span className="tabular-num rounded bg-surface px-2 py-0.5 font-mono text-[10px] text-sky-300">
                {formatClassifierLabel(report.classifier.predicted_label)} ·{" "}
                {report.classifier.latency_ms} ms
              </span>
            </div>
            <p className="mb-2 text-[11px] text-ink-muted">
              Điểm phân loại thô theo từng nhóm kịch bản tiếng Việt (chỉ dùng cho tầng phân loại
              ngữ nghĩa cục bộ).
            </p>
            <ClassifierDistributionChart items={classifierItems} />
          </div>
        )}

        <div
          className={`space-y-4 rounded-xl border border-border-subtle bg-surface-subtle p-4 ${
            classifierItems.length > 0 ? "lg:col-span-5" : "lg:col-span-12"
          }`}
        >
          {/* Evidence Distribution */}
          <div>
            <div className="mb-2 flex items-center justify-between gap-2">
              <h4 className="text-xs font-bold text-ink">
                Phân bố bằng chứng ({evidenceDist.total})
              </h4>
              <button
                type="button"
                onClick={() => onNavigateToEvidence("all")}
                className="cursor-pointer text-[11px] font-semibold text-sky-300 hover:text-sky-200"
              >
                Mở toàn bộ
              </button>
            </div>

            {evidenceDist.total === 0 ? (
              <p className="text-[11px] text-ink-muted">
                Chưa ghi nhận mục bằng chứng bất thường nào.
              </p>
            ) : (
              <div className="space-y-2.5">
                <div
                  aria-label="Tỷ lệ mức độ nghiêm trọng của bằng chứng"
                  className="flex h-2.5 w-full overflow-hidden rounded-full bg-surface-elevated"
                >
                  {evidenceDist.bySeverity.map((item) => (
                    <div
                      key={item.severity}
                      title={`${SEVERITY_COPY[item.severity]}: ${item.count}`}
                      className={SEVERITY_BAR[item.severity]}
                      style={{ width: `${Math.max(4, item.sharePct)}%` }}
                    />
                  ))}
                </div>

                <div className="flex flex-wrap gap-1.5">
                  {evidenceDist.bySeverity.map((item) => (
                    <span
                      key={item.severity}
                      className={`tabular-num inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-semibold ${
                        SEVERITY_BADGE[item.severity]
                      }`}
                    >
                      <span>{SEVERITY_COPY[item.severity]}:</span>
                      <span className="font-mono">{item.count}</span>
                    </span>
                  ))}
                </div>

                <div className="space-y-1 border-t border-border-subtle/70 pt-2">
                  <p className="text-[10px] font-semibold text-ink-muted">Theo mô-đun phát hiện:</p>
                  {evidenceDist.bySource.map((src) => (
                    <button
                      key={src.source}
                      type="button"
                      onClick={() => onNavigateToEvidence(src.evidenceTab, src.source)}
                      className="flex w-full cursor-pointer items-center justify-between gap-2 rounded-lg px-2 py-1 text-left text-[11px] text-ink-secondary transition-colors hover:bg-surface hover:text-ink"
                    >
                      <span className="truncate">{formatEvidenceSource(src.source)}</span>
                      <span className="tabular-num shrink-0 font-mono text-[10px] font-semibold text-amber-300">
                        {src.count} mục
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Real Detection Timeline (from report.trace) */}
          {timeline.entries.length > 0 && (
            <div className="border-t border-border-subtle/70 pt-3">
              <div className="mb-2 flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
                  <h4 className="text-xs font-bold text-ink">Dòng thời gian thực thi phân tích</h4>
                </div>
                <span className="tabular-num font-mono text-[10px] text-ink-muted">
                  Tổng: {timeline.totalMs >= 1000 ? `${(timeline.totalMs / 1000).toFixed(2)}s` : `${timeline.totalMs} ms`}
                </span>
              </div>

              <ol className="space-y-2">
                {timeline.entries.map((entry) => (
                  <li key={entry.step_id} className="space-y-1 text-[11px]">
                    <div className="flex items-center justify-between gap-2">
                      <span className="inline-flex min-w-0 items-center gap-1.5 font-medium text-ink-secondary">
                        <Activity
                          className={`h-3 w-3 shrink-0 ${
                            entry.status === "warning"
                              ? "text-amber-400"
                              : entry.status === "skipped"
                                ? "text-ink-muted"
                                : "text-emerald-400"
                          }`}
                          aria-hidden="true"
                        />
                        <span className="truncate">{entry.title}</span>
                      </span>
                      <span className="tabular-num shrink-0 font-mono text-[10px] text-ink-muted">
                        {entry.status === "skipped" ? "Bỏ qua" : `${entry.duration_ms} ms`}
                      </span>
                    </div>
                    <div
                      aria-hidden="true"
                      className="h-1.5 w-full overflow-hidden rounded-full bg-surface-elevated"
                    >
                      <div
                        className={`h-full rounded-full ${
                          entry.status === "warning"
                            ? "bg-amber-400"
                            : entry.status === "skipped"
                              ? "bg-slate-600"
                              : "bg-sky-400"
                        }`}
                        style={{ width: `${entry.sharePct}%` }}
                      />
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
