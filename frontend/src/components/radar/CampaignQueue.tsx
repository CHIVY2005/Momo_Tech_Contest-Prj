"use client";

import { Ban, CheckCircle2, Eye, Flame } from "lucide-react";

import { IOC_TYPE_COPY, VERDICT_COPY } from "@/lib/copy";
import { formatMaskedIoc } from "@/lib/radarLayout";
import type { EmergingCampaign } from "@/lib/types";

interface CampaignQueueProps {
  campaigns: EmergingCampaign[];
  selectedCampaignId?: string | null;
  isLocked?: boolean;
  onInspectCampaign: (campaign: EmergingCampaign) => void;
  onRequestBlockCampaign: (campaign: EmergingCampaign) => void;
}

export function CampaignQueue({
  campaigns,
  selectedCampaignId,
  isLocked = false,
  onInspectCampaign,
  onRequestBlockCampaign,
}: CampaignQueueProps) {
  return (
    <section
      aria-labelledby="campaign-queue-heading"
      className="rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-lg sm:p-5"
    >
      <div className="mb-3 flex items-start justify-between gap-2">
        <div className="flex items-start gap-2">
          <Flame className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" aria-hidden="true" />
          <div>
            <h2 id="campaign-queue-heading" className="text-sm font-bold text-ink">
              Chiến dịch cần xem xét
            </h2>
            <p className="text-xs text-ink-muted">
              Xem dấu hiệu liên quan và xác nhận đối tượng cụ thể trước khi tạo quy tắc chặn.
            </p>
          </div>
        </div>
        <span className="tabular-num shrink-0 rounded-md border border-border-subtle bg-surface-subtle px-2 py-0.5 font-mono text-[11px] font-semibold text-ink-secondary">
          {campaigns.length}
        </span>
      </div>

      <div className="space-y-2.5">
        {campaigns.length === 0 ? (
          <div className="rounded-xl border border-border-subtle bg-surface-subtle p-4 text-center text-xs text-ink-muted">
            Chưa có chiến dịch nghi vấn nào cần xem xét.
          </div>
        ) : (
          campaigns.map((camp) => {
            const isSelected = selectedCampaignId === camp.campaign_id;
            const totalIocs = camp.total_ioc_count ?? 1;
            const blockedIocs = camp.blocked_ioc_count ?? (camp.already_blocked ? 1 : 0);
            const riskLevel = camp.risk_level ?? (camp.case_count >= 5 ? "CRITICAL_SCAM" : "HIGH_RISK");
            const isCritical = riskLevel === "CRITICAL_SCAM";

            let statusText = "Chờ xử lý";
            let statusStyle = "border-border-strong bg-surface text-ink-secondary";
            if (blockedIocs > 0 && blockedIocs >= totalIocs) {
              statusText = `Đã chặn ${blockedIocs}/${totalIocs} dấu hiệu`;
              statusStyle = "border-emerald-500/45 bg-emerald-500/15 text-emerald-300";
            } else if (blockedIocs > 0) {
              statusText = `Đang chặn ${blockedIocs}/${totalIocs} dấu hiệu`;
              statusStyle = "border-amber-500/45 bg-amber-500/15 text-amber-200";
            }

            return (
              <article
                key={camp.campaign_id}
                className={`rounded-xl border p-3 transition-colors ${
                  isSelected
                    ? "border-sky-400/70 bg-sky-500/8"
                    : camp.already_blocked
                      ? "border-emerald-500/35 bg-emerald-500/5"
                      : "border-border-subtle bg-surface-subtle"
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-1.5">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                        isCritical
                          ? "bg-rose-500/20 text-rose-200"
                          : "bg-amber-500/20 text-amber-200"
                      }`}
                    >
                      {VERDICT_COPY[riskLevel].shortLabel}
                    </span>
                    <span className="tabular-num rounded bg-surface-elevated px-1.5 py-0.5 text-[10px] font-semibold text-ink-secondary">
                      {camp.case_count} hồ sơ
                    </span>
                    {camp.is_demo && (
                      <span className="rounded border border-sky-500/35 bg-sky-500/10 px-1.5 py-0.5 text-[10px] font-medium text-sky-300">
                        Mẫu minh họa
                      </span>
                    )}
                  </div>

                  <span
                    className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold ${statusStyle}`}
                  >
                    {blockedIocs > 0 && <CheckCircle2 className="h-3 w-3" aria-hidden="true" />}
                    <span>{statusText}</span>
                  </span>
                </div>

                <h3 className="mt-1.5 text-[13px] font-bold leading-snug text-ink">
                  {camp.title_vi}
                </h3>

                <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px]">
                  <span className="text-ink-muted">
                    {IOC_TYPE_COPY[camp.primary_ioc_type]} chính:
                  </span>
                  <code className="tabular-num rounded bg-surface-elevated px-1.5 py-0.5 font-mono font-semibold text-amber-300">
                    {formatMaskedIoc(camp.primary_ioc_masked, camp.primary_ioc_hash)}
                  </code>
                </div>

                <p className="mt-1.5 line-clamp-2 text-[11px] leading-relaxed text-ink-muted">
                  {camp.recommended_action}
                </p>

                <div className="mt-2.5 flex flex-wrap items-center justify-end gap-2 border-t border-border-subtle/70 pt-2.5">
                  <button
                    type="button"
                    onClick={() => onInspectCampaign(camp)}
                    className="inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-lg border border-border-strong bg-surface px-2.5 py-1 text-[11px] font-semibold text-ink-secondary transition-colors hover:border-sky-400 hover:text-ink"
                  >
                    <Eye className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
                    <span>Xem chi tiết</span>
                  </button>

                  {!camp.already_blocked ? (
                    <button
                      type="button"
                      disabled={isLocked}
                      onClick={() => onRequestBlockCampaign(camp)}
                      className="inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-lg bg-rose-600 px-3 py-1 text-[11px] font-bold text-white transition-colors hover:bg-rose-500 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      <Ban className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>Áp dụng quy tắc chặn</span>
                    </button>
                  ) : (
                    <span className="inline-flex min-h-[34px] items-center gap-1 rounded-lg border border-emerald-500/35 bg-emerald-500/10 px-2.5 py-1 text-[11px] font-semibold text-emerald-300">
                      <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>Đã chặn dấu hiệu chính</span>
                    </span>
                  )}
                </div>
              </article>
            );
          })
        )}
      </div>
    </section>
  );
}
