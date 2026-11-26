"use client";

import { Ban, CheckCircle2, Flame, ShieldAlert, X } from "lucide-react";
import { useEffect } from "react";

import { IOC_TYPE_COPY, VERDICT_COPY } from "@/lib/copy";
import { formatNodeDisplayLabel } from "@/lib/radarLayout";
import type { EmergingCampaign, IocType, RadarEdge, RadarNode } from "@/lib/types";

interface CampaignDetailDrawerProps {
  campaign: EmergingCampaign | null;
  nodes: RadarNode[];
  edges: RadarEdge[];
  onClose: () => void;
  onRequestBlockTarget: (target: {
    iocType: IocType;
    iocHash: string;
    maskedLabel: string;
    defaultReason: string;
  }) => void;
}

export function CampaignDetailDrawer({
  campaign,
  nodes,
  edges,
  onClose,
  onRequestBlockTarget,
}: CampaignDetailDrawerProps) {
  useEffect(() => {
    if (!campaign) return;
    function onKey(ev: KeyboardEvent) {
      if (ev.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [campaign, onClose]);

  if (!campaign) return null;

  const nodeMap = new Map(nodes.map((n) => [n.node_id, n]));
  const linkedIocIds = new Set<string>([campaign.primary_ioc_hash]);
  for (const edge of edges) {
    if (edge.source === campaign.campaign_id && edge.target !== campaign.campaign_id) {
      linkedIocIds.add(edge.target);
    } else if (edge.target === campaign.campaign_id && edge.source !== campaign.campaign_id) {
      linkedIocIds.add(edge.source);
    }
  }

  const linkedIocs = Array.from(linkedIocIds)
    .map((id) => nodeMap.get(id))
    .filter((n): n is RadarNode => Boolean(n && n.kind !== "campaign"));

  const riskLevel =
    campaign.risk_level ?? (campaign.case_count >= 5 ? "CRITICAL_SCAM" : "HIGH_RISK");

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        aria-hidden="true"
        onClick={onClose}
        className="fixed inset-0 bg-slate-950/75 backdrop-blur-xs"
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-labelledby="campaign-detail-title"
        className="relative z-10 flex h-full w-full max-w-lg flex-col border-l border-border-strong bg-surface shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3 border-b border-border-subtle px-5 py-4">
          <div className="flex items-start gap-2.5">
            <Flame className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" aria-hidden="true" />
            <div>
              <p className="text-[11px] font-semibold text-ink-muted">Chi tiết chiến dịch</p>
              <h2 id="campaign-detail-title" className="mt-0.5 text-base font-bold text-ink">
                {campaign.title_vi}
              </h2>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Đóng chi tiết chiến dịch"
            className="inline-flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-border-strong bg-surface-subtle text-ink-secondary hover:text-ink"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4 text-xs">
          <div className="grid grid-cols-3 gap-2.5">
            <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
              <p className="text-[11px] text-ink-muted">Hồ sơ liên quan</p>
              <p className="tabular-num mt-1 font-mono text-lg font-bold text-ink">
                {campaign.case_count}
              </p>
            </div>
            <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
              <p className="text-[11px] text-ink-muted">Mức rủi ro</p>
              <p className="mt-1 text-xs font-bold text-rose-300">
                {VERDICT_COPY[riskLevel].shortLabel}
              </p>
            </div>
            <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
              <p className="text-[11px] text-ink-muted">Nguồn dữ liệu</p>
              <p className="mt-1 text-xs font-semibold text-sky-300">
                {campaign.is_demo ? "Mẫu minh họa" : "Ghi nhận thực tế"}
              </p>
            </div>
          </div>

          <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3.5">
            <p className="text-[11px] font-semibold text-ink-muted">Khuyến nghị xử lý</p>
            <p className="mt-1 leading-relaxed text-ink-secondary">{campaign.recommended_action}</p>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-ink">
                Dấu hiệu thuộc chiến dịch ({linkedIocs.length})
              </h3>
              <span className="text-[11px] text-ink-muted">
                Xác nhận từng đối tượng trước khi chặn
              </span>
            </div>

            {linkedIocs.length === 0 ? (
              <p className="rounded-xl border border-border-subtle bg-surface-subtle p-3 text-ink-muted">
                Không có dấu hiệu chi tiết bổ sung.
              </p>
            ) : (
              <div className="space-y-2">
                {linkedIocs.map((ioc) => {
                  const isPrimary = ioc.node_id === campaign.primary_ioc_hash;
                  const iocKind = ioc.kind as IocType;
                  const label = formatNodeDisplayLabel(ioc);

                  return (
                    <div
                      key={ioc.node_id}
                      className={`flex flex-wrap items-center justify-between gap-2 rounded-xl border px-3.5 py-2.5 ${
                        ioc.blocked
                          ? "border-rose-500/40 bg-rose-500/8"
                          : "border-border-subtle bg-surface-subtle"
                      }`}
                    >
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="font-mono text-xs font-bold text-ink">{label}</span>
                          {isPrimary && (
                            <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-amber-200">
                              Chính
                            </span>
                          )}
                        </div>
                        <p className="tabular-num mt-0.5 text-[11px] text-ink-muted">
                          {IOC_TYPE_COPY[iocKind]} · {ioc.hit_count} lượt ghi nhận
                        </p>
                      </div>

                      {ioc.blocked ? (
                        <span className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-1 text-[11px] font-semibold text-emerald-300">
                          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>Đang áp dụng</span>
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={() =>
                            onRequestBlockTarget({
                              iocType: iocKind,
                              iocHash: ioc.node_id,
                              maskedLabel: label,
                              defaultReason: campaign.recommended_action,
                            })
                          }
                          className="inline-flex min-h-[32px] cursor-pointer items-center gap-1.5 rounded-lg border border-rose-500/45 bg-rose-500/15 px-2.5 py-1 text-[11px] font-semibold text-rose-200 hover:bg-rose-500/25"
                        >
                          <Ban className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>Áp dụng quy tắc chặn</span>
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="flex items-start gap-2 rounded-xl border border-border-subtle bg-surface-deep p-3 text-[11px] text-ink-muted">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
            <p className="leading-relaxed">
              Hệ thống không tự động chặn hàng loạt toàn bộ dấu hiệu trong chiến dịch. Mỗi quy tắc
              chặn phải được chọn rõ đối tượng, lý do, thời hạn và xác thực bởi quản trị viên.
            </p>
          </div>
        </div>
      </aside>
    </div>
  );
}
