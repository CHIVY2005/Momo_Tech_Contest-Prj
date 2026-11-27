"use client";

import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Download,
  FileCheck2,
  Loader2,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";

import { downloadReportPdf, persistAssistantEvidence } from "@/lib/api";
import { RECEIPT_STATUS_COPY, VERDICT_COPY } from "@/lib/copy";
import type {
  AssistantEvidenceReportEvent,
  ReceiptVerificationStatus,
  VerdictLevel,
} from "@/lib/types";

export interface PersistedEvidenceState {
  childCaseId: string;
  childToken: string;
  contributedToRadar: boolean;
}

export interface AssistantEvidenceCardProps {
  evidence: AssistantEvidenceReportEvent;
  parentCaseId: string;
  caseAccessToken: string | null;
  persisted?: PersistedEvidenceState | null;
  onPersisted?: (state: PersistedEvidenceState) => void;
}

const VERDICT_STYLES: Record<VerdictLevel, string> = {
  SAFE: "border-emerald-500/45 bg-emerald-500/15 text-emerald-200",
  SUSPICIOUS: "border-amber-500/45 bg-amber-500/15 text-amber-200",
  HIGH_RISK: "border-orange-500/50 bg-orange-500/15 text-orange-200",
  CRITICAL_SCAM: "border-rose-500/55 bg-rose-500/18 text-rose-100",
};

function resolveVerdictMeta(verdict: string): { label: string; style: string } {
  if (verdict in VERDICT_COPY) {
    const typed = verdict as VerdictLevel;
    return {
      label: VERDICT_COPY[typed].shortLabel,
      style: VERDICT_STYLES[typed],
    };
  }
  return {
    label: verdict,
    style: "border-border-strong bg-surface-subtle text-ink-secondary",
  };
}

function resolveReceiptWarning(status: string): string | null {
  if (!status || status === "NOT_APPLICABLE") {
    return null;
  }
  if (status in RECEIPT_STATUS_COPY) {
    return RECEIPT_STATUS_COPY[status as ReceiptVerificationStatus];
  }
  return "Chưa thể xác nhận tiền đã vào tài khoản từ ảnh chụp biên lai.";
}

function truncateId(id: string): string {
  const clean = id.trim();
  if (clean.length <= 16) return clean;
  return `${clean.slice(0, 10)}…${clean.slice(-4)}`;
}

export function AssistantEvidenceCard({
  evidence,
  parentCaseId,
  caseAccessToken,
  persisted: controlledPersisted = null,
  onPersisted,
}: AssistantEvidenceCardProps) {
  const [contributeToRadar, setContributeToRadar] = useState(false);
  const [localPersisted, setLocalPersisted] = useState<PersistedEvidenceState | null>(null);
  const [isWorking, setIsWorking] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const persisted = controlledPersisted ?? localPersisted;
  const verdictMeta = resolveVerdictMeta(evidence.verdict);
  const receiptWarning = resolveReceiptWarning(evidence.receipt_verification_status);
  const radarDisabled = !evidence.can_contribute_radar || isWorking;
  const checkboxId = `radar-optin-${evidence.draft_id}`;

  async function handlePersistAndDownload() {
    if (isWorking) return;
    setErrorMessage(null);
    setIsWorking(true);
    try {
      let activeChild = persisted;
      if (!activeChild) {
        const res = await persistAssistantEvidence(
          evidence.draft_id,
          parentCaseId,
          evidence.can_contribute_radar && contributeToRadar,
          caseAccessToken,
        );
        activeChild = {
          childCaseId: res.child_case_id,
          childToken: res.child_case_access_token,
          contributedToRadar: res.contributed_to_radar,
        };
        setLocalPersisted(activeChild);
        onPersisted?.(activeChild);
      }
      await downloadReportPdf(activeChild.childCaseId, activeChild.childToken);
    } catch (err) {
      setErrorMessage(
        err instanceof Error && err.message.trim()
          ? err.message
          : "Không thể lưu hồ sơ bổ sung hoặc tải PDF lúc này. Vui lòng thử lại.",
      );
    } finally {
      setIsWorking(false);
    }
  }

  return (
    <section
      aria-label="Kết quả phân tích bằng chứng bổ sung"
      className="space-y-2.5 rounded-xl border border-border-strong bg-surface p-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <span
            className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-bold ${verdictMeta.style}`}
          >
            {verdictMeta.label}
          </span>
          <span className="tabular-num rounded-md border border-border-subtle bg-surface-subtle px-2 py-0.5 font-mono text-[11px] font-semibold text-ink">
            {evidence.risk_score}/100
          </span>
        </div>

        {persisted ? (
          <span className="inline-flex items-center gap-1 rounded-md border border-emerald-500/45 bg-emerald-500/15 px-2 py-0.5 text-[10px] font-semibold text-emerald-200">
            <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
            <span>Đã lưu hồ sơ bổ sung</span>
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded-md border border-sky-500/40 bg-sky-500/10 px-2 py-0.5 text-[10px] font-semibold text-sky-200">
            <Clock className="h-3 w-3" aria-hidden="true" />
            <span>Chưa lưu vào hệ thống — chỉ tạm giữ 15 phút</span>
          </span>
        )}
      </div>

      {receiptWarning && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-lg border border-amber-400/60 bg-amber-500/15 px-2.5 py-2 text-[11px] leading-relaxed text-amber-100"
        >
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300" aria-hidden="true" />
          <span>{receiptWarning}</span>
        </div>
      )}

      {evidence.summary_vi && (
        <p className="text-xs leading-relaxed text-ink-secondary">{evidence.summary_vi}</p>
      )}

      {!persisted ? (
        <div className="space-y-2 border-t border-border-subtle/80 pt-2">
          <label
            htmlFor={checkboxId}
            title={
              evidence.can_contribute_radar
                ? "Chỉ gửi dấu hiệu đã băm một chiều và che giấu lên Radar cộng đồng nếu rủi ro cao."
                : "Hồ sơ xuất phát từ tình huống mẫu (demo) không thể đóng góp vào Radar cộng đồng."
            }
            className={`flex items-start gap-2 text-[11px] leading-snug ${
              radarDisabled ? "cursor-not-allowed text-ink-muted opacity-70" : "cursor-pointer text-ink-secondary"
            }`}
          >
            <input
              id={checkboxId}
              type="checkbox"
              checked={evidence.can_contribute_radar ? contributeToRadar : false}
              disabled={radarDisabled}
              onChange={(ev) => setContributeToRadar(ev.target.checked)}
              className="mt-0.5 h-3.5 w-3.5 shrink-0 rounded border-border-strong bg-surface-deep accent-amber-500"
            />
            <span>
              Đóng góp dấu hiệu đã ẩn danh vào Radar cộng đồng
              {!evidence.can_contribute_radar && (
                <span className="block text-[10px] text-ink-muted">
                  (Tắt cố định vì hồ sơ hiện tại là tình huống mẫu demo)
                </span>
              )}
            </span>
          </label>

          <button
            type="button"
            disabled={isWorking || !caseAccessToken?.trim()}
            onClick={() => void handlePersistAndDownload()}
            className="inline-flex min-h-[36px] w-full cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-amber-400/70 bg-amber-500/15 px-3 py-1.5 text-[11px] font-semibold text-amber-100 transition-colors hover:bg-amber-500/25 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isWorking ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <FileCheck2 className="h-3.5 w-3.5" aria-hidden="true" />
            )}
            <span>{isWorking ? "Đang lưu & tạo báo cáo PDF..." : "Lưu hồ sơ bổ sung & tải PDF"}</span>
          </button>
        </div>
      ) : (
        <div className="space-y-2 border-t border-border-subtle/80 pt-2">
          <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] text-ink-muted">
            <span className="inline-flex items-center gap-1 font-mono text-emerald-200">
              <ShieldCheck className="h-3 w-3" aria-hidden="true" />
              <span>Mã hồ sơ con: {truncateId(persisted.childCaseId)}</span>
            </span>
            <span>
              {persisted.contributedToRadar
                ? "Đã đóng góp dấu hiệu ẩn danh vào Radar"
                : "Lưu riêng tư (không đóng góp Radar)"}
            </span>
          </div>

          <button
            type="button"
            disabled={isWorking}
            onClick={() => void handlePersistAndDownload()}
            className="inline-flex min-h-[34px] w-full cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-emerald-500/50 bg-emerald-500/15 px-3 py-1.5 text-[11px] font-semibold text-emerald-100 transition-colors hover:bg-emerald-500/25 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isWorking ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
            )}
            <span>{isWorking ? "Đang tải PDF..." : "Tải lại báo cáo PDF"}</span>
          </button>
        </div>
      )}

      {errorMessage && (
        <div
          role="alert"
          className="flex items-start gap-1.5 rounded-lg border border-rose-500/45 bg-rose-500/15 px-2.5 py-1.5 text-[11px] text-rose-100"
        >
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-300" aria-hidden="true" />
          <span>{errorMessage}</span>
        </div>
      )}
    </section>
  );
}
