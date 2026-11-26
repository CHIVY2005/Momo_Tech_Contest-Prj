"use client";

import {
  AlertOctagon,
  AlertTriangle,
  Cpu,
  FileWarning,
  Layers,
  ShieldAlert,
  ShieldCheck,
  Users,
  Volume2,
} from "lucide-react";

import type { AnalysisReport, VerdictLevel } from "@/lib/types";

interface VerdictDashboardProps {
  report: AnalysisReport;
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
    label: "ÍT RỦI RO — CHƯA PHÁT HIỆN MÃ ĐỘC / LỪA ĐẢO",
    border: "border-emerald-500/45",
    badgeBg: "border-emerald-500/45 bg-emerald-500/15 text-emerald-200",
    barColor: "bg-emerald-500",
    scoreColor: "text-emerald-300",
    Icon: ShieldCheck,
  },
  SUSPICIOUS: {
    label: "NGHI VẤN — CẦN KIỂM CHỨNG ĐỘC LẬP",
    border: "border-amber-500/50",
    badgeBg: "border-amber-500/45 bg-amber-500/15 text-amber-200",
    barColor: "bg-amber-500",
    scoreColor: "text-amber-300",
    Icon: AlertTriangle,
  },
  HIGH_RISK: {
    label: "RỦI RO CAO — TẠM DỪNG GIAO DỊCH NGAY",
    border: "border-orange-500/55",
    badgeBg: "border-orange-500/50 bg-orange-500/15 text-orange-200",
    barColor: "bg-orange-500",
    scoreColor: "text-orange-300",
    Icon: ShieldAlert,
  },
  CRITICAL_SCAM: {
    label: "CẢNH BÁO ĐỎ — DẤU HIỆU LỪA ĐẢO / GIẢ MẠO RÕ RỆT",
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

export function VerdictDashboard({ report }: VerdictDashboardProps) {
  const meta = VERDICT_META[report.verdict];
  const VerdictIcon = meta.Icon;
  const showMerchantHonestyBanner =
    report.receipt_verification_status === "UNVERIFIED_SCREENSHOT" ||
    Boolean(report.actions.merchant_balance_warning);
  const consensus = summarizeLayerConsensus(report);

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
              <p className="text-xs font-bold tracking-wide text-amber-200 uppercase">
                CHƯA ĐỐI SOÁT SỐ DƯ — BẮT BUỘC KIỂM TRA APP NGÂN HÀNG / LOA THÔNG BÁO
              </p>
              <p className="mt-1 text-xs leading-relaxed text-amber-100">
                {report.actions.merchant_balance_warning ??
                  "Ảnh chụp màn hình biên lai KHÔNG phải bằng chứng tiền đã vào tài khoản. Tuyệt đối không giao hàng trước khi kiểm tra biến động số dư thực tế hoặc Loa thông báo nhận tiền."}
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
          TRÙNG KHỚP DANH SÁCH CHẶN KHẨN CẤP (/radar): Tài khoản/tên miền trong giao dịch vừa bị
          Trung tâm Fraud Ops khóa trên toàn hệ sinh thái.
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
                Đồng thuận tầng: {consensus.flaggedCount}/{consensus.activeCount} lớp cảnh báo
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
            <p className="text-[11px] font-medium text-ink-muted">Điểm Rủi ro Hiệu chuẩn</p>
            <div className="flex items-baseline gap-1">
              <span className={`tabular-num font-mono text-3xl font-bold ${meta.scoreColor}`}>
                {report.risk_score}
              </span>
              <span className="tabular-num font-mono text-xs text-ink-muted">/100</span>
            </div>
          </div>
          <div className="h-10 w-px bg-border-subtle" aria-hidden="true" />
          <div>
            <p className="text-[11px] font-medium text-ink-muted">Độ tin cậy</p>
            <p className="tabular-num font-mono text-lg font-semibold text-ink">
              {Math.round(report.confidence * 100)}%
            </p>
          </div>
        </div>
      </div>

      <div className="mt-3.5">
        <div
          role="progressbar"
          aria-label="Thanh điểm rủi ro hiệu chuẩn"
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
          className="tabular-num mt-1 flex justify-between font-mono text-[10px] text-ink-muted"
        >
          <span>0 · Ít rủi ro</span>
          <span>25 · Nghi vấn</span>
          <span>50 · Rủi ro cao</span>
          <span>75–100 · Cảnh báo đỏ</span>
        </div>
      </div>

      {(report.matched_playbooks.length > 0 || report.manipulation_tactics.length > 0) && (
        <div className="mt-4 grid grid-cols-1 gap-3 border-t border-border-subtle/80 pt-4 sm:grid-cols-2">
          <div>
            <p className="mb-1.5 text-xs font-semibold text-ink-secondary">
              Kịch bản Lừa đảo Việt Nam Khớp Mẫu
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
              <p className="text-xs text-ink-muted">Không khớp mẫu lừa đảo cố định.</p>
            )}
          </div>

          <div>
            <p className="mb-1.5 text-xs font-semibold text-ink-secondary">
              Đòn bẩy Thao túng Tâm lý Phát hiện
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
              <p className="text-xs text-ink-muted">Chưa ghi nhận kỹ thuật thao túng tâm lý.</p>
            )}
          </div>
        </div>
      )}

      {report.transcript && (
        <div className="mt-4 rounded-xl border border-border-subtle bg-surface-subtle p-3.5">
          <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-sky-300">
            <Volume2 className="h-4 w-4" aria-hidden="true" />
            <span>Bản gỡ băng lời thoại cuộc gọi (Audio Transcript)</span>
          </div>
          <p className="text-xs leading-relaxed text-ink-secondary italic">
            &ldquo;{report.transcript}&rdquo;
          </p>
        </div>
      )}

      {/* Secondary technical provenance row (auditability without crowding the primary verdict) */}
      <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-border-subtle/70 pt-3 text-[11px]">
        <span className="tabular-num rounded-md border border-border-subtle bg-surface-subtle px-2 py-1 font-mono text-ink-secondary">
          Hồ sơ: {report.case_id}
        </span>

        {report.classifier?.available && (
          <span className="tabular-num inline-flex items-center gap-1.5 rounded-md border border-sky-500/30 bg-sky-500/10 px-2 py-1 font-mono text-sky-200">
            <Cpu className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
            <span>
              E5 ONNX: {report.classifier.predicted_label} ({report.classifier.latency_ms}ms)
            </span>
          </span>
        )}

        {!report.degraded_mode && report.llm_model && (
          <span className="tabular-num rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 font-mono text-emerald-200">
            LLM: {report.llm_model}
            {typeof report.llm_latency_ms === "number" ? ` (${report.llm_latency_ms}ms)` : ""}
          </span>
        )}

        {report.degraded_mode && (
          <span className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-amber-200">
            Chế độ dự phòng cục bộ Tầng 1 (Không phụ thuộc Cloud LLM)
          </span>
        )}

        {report.community_hits > 0 && (
          <span className="tabular-num inline-flex items-center gap-1.5 rounded-md border border-rose-500/35 bg-rose-500/10 px-2 py-1 text-rose-200">
            <Users className="h-3.5 w-3.5 text-rose-400" aria-hidden="true" />
            <span>Cộng đồng cảnh báo: {report.community_hits} ca trùng IOC</span>
          </span>
        )}
      </div>
    </section>
  );
}
