"use client";

import { Ban, CheckCircle2, Flame, Loader2 } from "lucide-react";

import type { EmergingCampaign } from "@/lib/types";

interface CampaignQueueProps {
  campaigns: EmergingCampaign[];
  busyCampaignId: string | null;
  isLocked?: boolean;
  onBlockCampaign: (campaign: EmergingCampaign) => void;
}

const IOC_TYPE_LABELS: Record<EmergingCampaign["primary_ioc_type"], string> = {
  bank_account: "Tài khoản Nhận (Mule STK)",
  domain: "Tên miền Phishing",
  phone: "Đầu số Giả mạo",
};

export function CampaignQueue({
  campaigns,
  busyCampaignId,
  isLocked = false,
  onBlockCampaign,
}: CampaignQueueProps) {
  return (
    <section
      aria-labelledby="campaign-queue-heading"
      className="rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-lg sm:p-5"
    >
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex items-start gap-2">
          <Flame className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" aria-hidden="true" />
          <div>
            <h2 id="campaign-queue-heading" className="text-sm font-bold text-ink">
              Hàng đợi Chiến dịch Bùng phát (1-Click Ecosystem Block)
            </h2>
            <p className="text-xs text-ink-muted">
              Khóa trực tiếp qua mã băm SHA-256 (
              <code className="font-mono text-ink-secondary">primary_ioc_hash</code>) mà không cần
              lộ dữ liệu cá nhân thô.
            </p>
          </div>
        </div>
      </div>

      <div className="space-y-3">
        {campaigns.length === 0 ? (
          <p className="rounded-xl border border-border-subtle bg-surface-subtle p-4 text-xs text-ink-muted">
            Chưa phát hiện chiến dịch bùng phát nào cần khóa khẩn cấp.
          </p>
        ) : (
          campaigns.map((camp) => {
            const isBusy = busyCampaignId === camp.campaign_id;
            return (
              <div
                key={camp.campaign_id}
                className={`rounded-xl border p-3.5 transition-colors ${
                  camp.already_blocked
                    ? "border-emerald-500/45 bg-emerald-500/5"
                    : "border-border-subtle bg-surface-subtle"
                }`}
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <span className="tabular-num rounded bg-rose-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-rose-200">
                      {camp.case_count} hồ sơ trùng khớp
                    </span>
                    <h3 className="mt-1.5 text-sm font-bold leading-snug text-ink">
                      {camp.title_vi}
                    </h3>
                  </div>

                  {camp.already_blocked ? (
                    <span className="inline-flex min-h-[38px] shrink-0 items-center gap-1.5 rounded-lg border border-emerald-500/45 bg-emerald-500/15 px-3 py-1.5 text-xs font-bold text-emerald-300">
                      <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                      <span>Đã Khóa Toàn Hệ thống</span>
                    </span>
                  ) : (
                    <button
                      type="button"
                      disabled={isBusy || isLocked}
                      onClick={() => onBlockCampaign(camp)}
                      className="inline-flex min-h-[40px] shrink-0 cursor-pointer items-center gap-1.5 rounded-xl bg-rose-600 px-3.5 py-2 text-xs font-bold text-white shadow-sm shadow-rose-900/40 transition-colors hover:bg-rose-500 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {isBusy ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                      ) : (
                        <Ban className="h-3.5 w-3.5" aria-hidden="true" />
                      )}
                      <span>1-Click Khóa Khẩn cấp</span>
                    </button>
                  )}
                </div>

                <div className="mt-2.5 flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-ink-muted">{IOC_TYPE_LABELS[camp.primary_ioc_type]}:</span>
                  <code className="tabular-num rounded bg-surface-elevated px-2 py-0.5 font-mono font-semibold text-amber-300">
                    {camp.primary_ioc_masked}
                  </code>
                  <span className="tabular-num font-mono text-[10px] text-ink-muted">
                    SHA256: {camp.primary_ioc_hash.slice(0, 12)}…
                  </span>
                </div>

                <p className="mt-2 text-xs leading-relaxed text-ink-secondary">
                  <span className="font-semibold text-ink">Khuyến nghị Ops: </span>
                  {camp.recommended_action}
                </p>
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}
