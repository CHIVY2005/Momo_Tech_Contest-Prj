"use client";

import {
  AlertOctagon,
  AlertTriangle,
  Cpu,
  FileWarning,
  Layers,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Users,
  Volume2,
} from "lucide-react";

import { buildContextQuickActions } from "@/components/assistant/AssistantQuickActions";
import {
  formatClassifierLabel,
  SHARED_DISCLAIMERS,
  VERDICT_COPY,
} from "@/lib/copy";
import type { AnalysisReport, AssistantQuickIntent, VerdictLevel } from "@/lib/types";

export interface VerdictDashboardProps {
  report: AnalysisReport;
  onOpenAssistant?: (initialPrompt?: string, initialIntent?: AssistantQuickIntent) => void;
}

const VERDICT_META: Record<
  VerdictLevel,
  {
    label: string;
    border: string;
    badgeBg: string;
    barColor: string;
    scoreColor: string;
    Icon: typeof ShieldCheck;
  }
> = {
  SAFE: {
    label: VERDICT_COPY.SAFE.label,
    border: "border-emerald-500/45",
    badgeBg: "border-emerald-500/45 bg-emerald-500/15 text-emerald-200",
    barColor: "bg-emerald-500",
    scoreColor: "text-emerald-300",
    Icon: ShieldCheck,
  },
  SUSPICIOUS: {
    label: VERDICT_COPY.SUSPICIOUS.label,
    border: "border-amber-500/50",
    badgeBg: "border-amber-500/45 bg-amber-500/15 text-amber-200",
    barColor: "bg-amber-500",
    scoreColor: "text-amber-300",
    Icon: AlertTriangle,
  },
  HIGH_RISK: {
    label: VERDICT_COPY.HIGH_RISK.label,
    border: "border-orange-500/55",
    badgeBg: "border-orange-500/50 bg-orange-500/15 text-orange-200",
    barColor: "bg-orange-500",
    scoreColor: "text-orange-300",
    Icon: ShieldAlert,
  },
  CRITICAL_SCAM: {
    label: VERDICT_COPY.CRITICAL_SCAM.label,
    border: "border-rose-500/65",
    badgeBg: "border-rose-500/55 bg-rose-500/18 text-rose-100",
    barColor: "bg-rose-500",
    scoreColor: "text-rose-300",
    Icon: AlertOctagon,
  },
};

function summarizeLayerConsensus(report: AnalysisReport): { activeCount: number; flaggedCount: number } {
  let activeCount = 0;
  let flaggedCount = 0;

  // Layer 1: Local ONNX / KB semantic analysis
  if (report.classifier?.available || report.matched_playbooks.length > 0) {
    activeCount += 1;
    if (
      (report.classifier?.available && report.classifier.scam_probability >= 0.5) ||
      report.matched_playbooks.length > 0
    ) {
      flaggedCount += 1;
    }
  }

  // Layer 2: Media / Receipt / VietQR forensics
  if (
    report.image_forensics ||
    report.receipt_logic?.is_receipt_candidate ||
    report.vietqr_findings.length > 0
  ) {
    activeCount += 1;
    const mediaFlagged =
      (report.image_forensics?.tamper_score ?? 0) >= 35 ||
      Boolean(report.image_forensics?.editing_software_detected) ||
      (report.receipt_logic?.logic_risk_points ?? 0) >= 25 ||
      report.vietqr_findings.some(
        (q) => q.receive_scam_detected || q.beneficiary_mismatch || q.kind === "INVALID_CRC_VIETQR",
      );
    if (mediaFlagged) {
      flaggedCount += 1;
    }
  }

  // Layer 3: URL / Sandbox / Radar IOC
  if (report.url_findings.length > 0 || report.sandbox || report.active_block_rule_hit || report.community_hits > 0) {
    activeCount += 1;
    const cyberFlagged =
      report.active_block_rule_hit ||
      report.community_hits > 0 ||
      report.url_findings.some((u) => u.risk_points >= 30 || u.is_blocked_ssrf || u.is_idn_homoglyph) ||
      Boolean(report.sandbox && (report.sandbox.blocked_ssrf || report.sandbox.risk_points >= 30));
    if (cyberFlagged) {
      flaggedCount += 1;
    }
  }

  // Layer 4: Cloud LLM multimodal reasoning (when active)
  if (!report.degraded_mode && report.llm_model) {
    activeCount += 1;
    if (report.risk_score >= 45 || report.manipulation_tactics.length > 0) {
      flaggedCount += 1;
    }
  }

  return { activeCount: Math.max(1, activeCount), flaggedCount };
}

export function VerdictDashboard({ report, onOpenAssistant }: VerdictDashboardProps) {
  const meta = VERDICT_META[report.verdict];
  const VerdictIcon = meta.Icon;
  const showMerchantHonestyBanner =
    report.receipt_verification_status === "UNVERIFIED_SCREENSHOT" ||
    Boolean(report.actions.merchant_balance_warning);
  const consensus = summarizeLayerConsensus(report);
  const quickAssistantActions = onOpenAssistant
    ? buildContextQuickActions(report).slice(0, 3)
    : [];

  return (
    <section
      aria-labelledby="verdict-heading"
      className={`rounded-2xl border ${meta.border} bg-surface/95 p-5 shadow-xl`}
    >
      {showMerchantHonestyBanner && (
        <div
          role="alert"
          className="mb-4 rounded-xl border-2 border-amber-400/80 bg-amber-500/15 p-3.5 text-amber-100"
        >
          <div className="flex items-start gap-2.5">
            <FileWarning className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden="true" />
            <div>
              <p className="text-xs font-bold text-amber-200">
                {SHARED_DISCLAIMERS.merchantHonestyHeading}
              </p>
              <p className="mt-1 text-xs leading-relaxed text-amber-100">
                {report.actions.merchant_balance_warning ??
                  SHARED_DISCLAIMERS.merchantHonestyFallback}
              </p>
            </div>
          </div>
        </div>
      )}

      {report.active_block_rule_hit && (
        <div
          role="alert"
          className="mb-4 rounded-xl border border-rose-500/75 bg-rose-500/20 px-3.5 py-2.5 text-xs font-semibold text-rose-100"
        >
          Cảnh báo từ danh sách chặn hệ thống: Số tài khoản hoặc tên miền trong giao dịch này đang
          bị chặn do có dấu hiệu liên quan đến lừa đảo.
        </div>
      )}

      <div className="flex flex-col justify-between gap-4 md:flex-row md:items-start">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-bold ${meta.badgeBg}`}
            >
              <VerdictIcon className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{meta.label}</span>
            </span>

            <span className="tabular-num inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-surface-subtle px-2.5 py-1 text-[11px] font-medium text-ink-secondary">
              <Layers className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
              <span>
                Đánh giá tổng hợp: {consensus.flaggedCount}/{consensus.activeCount} lớp ghi nhận bất
                thường
              </span>
            </span>
          </div>

          <h2
            id="verdict-heading"
            className="mt-3 text-base font-semibold leading-relaxed text-ink"
          >
            {report.summary_vi}
          </h2>
        </div>

        <div className="flex shrink-0 items-center gap-4 rounded-xl border border-border-subtle bg-surface-subtle px-4 py-3">
          <div>
            <p className="text-[11px] font-medium text-ink-muted">Mức độ rủi ro</p>
            <div className="flex items-baseline gap-1">
              <span className={`tabular-num font-mono text-3xl font-bold ${meta.scoreColor}`}>
                {report.risk_score}
              </span>
              <span className="tabular-num font-mono text-xs text-ink-muted">/100</span>
            </div>
          </div>
          <div className="h-10 w-px bg-border-subtle" aria-hidden="true" />
          <div>
            <p className="text-[11px] font-medium text-ink-muted">Mức độ chắc chắn</p>
            <p className="tabular-num font-mono text-lg font-semibold text-ink">
              {Math.round(report.confidence * 100)}%
            </p>
          </div>
        </div>
      </div>

      <div className="mt-3.5">
        <div
          role="progressbar"
          aria-label="Thanh mức độ rủi ro"
          aria-valuenow={report.risk_score}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuetext={`${report.risk_score} trên 100 — ${meta.label}`}
          className="h-2.5 w-full overflow-hidden rounded-full bg-surface-elevated"
        >
          <div
            className={`h-full rounded-full transition-all duration-300 ${meta.barColor}`}
            style={{ width: `${Math.max(3, report.risk_score)}%` }}
          />
        </div>
        <div
          aria-hidden="true"
          className="tabular-num mt-1 flex justify-between text-[10px] text-ink-muted"
        >
          <span>0 · Thấp</span>
          <span>25 · Cần thận trọng</span>
          <span>50 · Cao</span>
          <span>75–100 · Rất cao</span>
        </div>
      </div>

      {onOpenAssistant && (
        <div className="mt-4 flex flex-col gap-2.5 rounded-xl border border-amber-500/30 bg-surface-subtle/90 p-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[11px] font-semibold text-ink-secondary">
              Hỏi nhanh Trợ lý VeriShield:
            </span>
            {quickAssistantActions.map((action) => (
              <button
                key={action.id}
                type="button"
                onClick={() => onOpenAssistant(action.prompt, action.intent)}
                className="min-h-[34px] cursor-pointer rounded-lg border border-border-strong bg-surface px-2.5 py-1 text-[11px] font-medium text-ink-secondary transition-colors hover:border-amber-400/65 hover:text-ink"
              >
                {action.label}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => onOpenAssistant()}
            className="inline-flex min-h-[38px] shrink-0 cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-amber-400/65 bg-amber-500/18 px-3.5 py-1.5 text-xs font-bold text-amber-100 transition-colors hover:border-amber-300 hover:bg-amber-500/28"
          >
            <Sparkles className="h-3.5 w-3.5 text-amber-300" aria-hidden="true" />
            <span>Hỏi Trợ lý VeriShield</span>
          </button>
        </div>
      )}

      {(report.matched_playbooks.length > 0 || report.manipulation_tactics.length > 0) && (
        <div className="mt-4 grid grid-cols-1 gap-3 border-t border-border-subtle/80 pt-4 sm:grid-cols-2">
          <div>
            <p className="mb-1.5 text-xs font-semibold text-ink-secondary">
              Kịch bản lừa đảo tương tự
            </p>
            {report.matched_playbooks.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {report.matched_playbooks.map((pb) => (
                  <span
                    key={pb}
                    className="rounded-lg border border-border-strong bg-surface-subtle px-2.5 py-1 text-xs font-medium text-ink"
                  >
                    {pb}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-xs text-ink-muted">Chưa trùng khớp với kịch bản cụ thể nào.</p>
            )}
          </div>

          <div>
            <p className="mb-1.5 text-xs font-semibold text-ink-secondary">
              Dấu hiệu gây áp lực tâm lý
            </p>
            {report.manipulation_tactics.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {report.manipulation_tactics.map((tac) => (
                  <span
                    key={tac}
                    className="rounded-lg border border-amber-500/35 bg-amber-500/10 px-2.5 py-1 text-xs text-amber-200"
                  >
                    {tac}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-xs text-ink-muted">Chưa ghi nhận dấu hiệu thao túng tâm lý rõ rệt.</p>
            )}
          </div>
        </div>
      )}

      {report.transcript && (
        <div className="mt-4 rounded-xl border border-border-subtle bg-surface-subtle p-3.5">
          <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-sky-300">
            <Volume2 className="h-4 w-4" aria-hidden="true" />
            <span>Nội dung chuyển từ tệp ghi âm</span>
          </div>
          <p className="text-xs leading-relaxed text-ink-secondary italic">
            &ldquo;{report.transcript}&rdquo;
          </p>
        </div>
      )}

      <div className="mt-4 space-y-2.5 border-t border-border-subtle/70 pt-3 text-[11px]">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-ink-muted">{SHARED_DISCLAIMERS.referenceOnly}</p>
          <div className="flex flex-wrap items-center gap-2">
            {report.community_hits > 0 && (
              <span className="tabular-num inline-flex items-center gap-1.5 rounded-md border border-rose-500/35 bg-rose-500/10 px-2 py-1 text-rose-200">
                <Users className="h-3.5 w-3.5 text-rose-400" aria-hidden="true" />
                <span>Đã có {report.community_hits} báo cáo trùng dấu hiệu</span>
              </span>
            )}
            {report.degraded_mode && (
              <span className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-amber-200">
                Đang hiển thị kết quả phân tích nhanh nội bộ
              </span>
            )}
          </div>
        </div>

        <details className="rounded-lg border border-border-subtle/80 bg-surface-subtle/70 px-3 py-2">
          <summary className="cursor-pointer font-medium text-ink-secondary hover:text-ink">
            Thông tin kỹ thuật
          </summary>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="tabular-num rounded-md border border-border-subtle bg-surface px-2 py-1 font-mono text-ink-secondary">
              Mã hồ sơ: {report.case_id}
            </span>

            {report.classifier?.available && (
              <span className="tabular-num inline-flex items-center gap-1.5 rounded-md border border-sky-500/30 bg-sky-500/10 px-2 py-1 text-sky-200">
                <Cpu className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
                <span>
                  Phân loại cục bộ (E5 INT8 ONNX): {formatClassifierLabel(report.classifier.predicted_label)}{" "}
                  ({report.classifier.latency_ms} ms)
                </span>
              </span>
            )}

            {!report.degraded_mode && report.llm_model && (
              <span className="tabular-num rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 font-mono text-emerald-200">
                Mô hình suy luận: {report.llm_model}
                {typeof report.llm_latency_ms === "number" ? ` (${report.llm_latency_ms} ms)` : ""}
              </span>
            )}
          </div>
        </details>
      </div>
    </section>
  );
}
