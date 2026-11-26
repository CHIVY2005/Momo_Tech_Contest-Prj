"use client";

import { History, Lock, PlusCircle, ShieldAlert, Trash2 } from "lucide-react";

import { IOC_TYPE_COPY } from "@/lib/copy";
import {
  computeRuleStatus,
  formatMaskedIoc,
  formatRadarTimestamp,
  formatRemainingTtl,
} from "@/lib/radarLayout";
import type { BlockRule, RadarAuditEvent } from "@/lib/types";

interface BlockRuleManagerProps {
  rules: BlockRule[];
  auditLogs?: RadarAuditEvent[];
  nowMs: number;
  isBusy: boolean;
  onOpenCreateModal: () => void;
  onRequestRevokeRule: (rule: BlockRule) => void;
}

const AUDIT_ACTION_LABELS: Record<RadarAuditEvent["action"], string> = {
  create_rule: "Tạo quy tắc",
  revoke_rule: "Thu hồi quy tắc",
  reset_rules: "Đặt lại quy tắc mẫu",
  auth_failed: "Xác thực thất bại",
  protected_ioc_blocked: "Chống chặn nhầm",
};

export function BlockRuleManager({
  rules,
  auditLogs = [],
  nowMs,
  isBusy,
  onOpenCreateModal,
  onRequestRevokeRule,
}: BlockRuleManagerProps) {
  return (
    <section
      aria-labelledby="block-manager-heading"
      className="space-y-4 rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-lg sm:p-5"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-start gap-2">
          <Lock className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" aria-hidden="true" />
          <div>
            <h2 id="block-manager-heading" className="text-sm font-bold text-ink">
              Quy tắc chặn
            </h2>
            <p className="text-xs text-ink-muted">
              Danh sách các đối tượng đang áp dụng quy tắc chặn tạm thời có thời hạn tự động (TTL).
            </p>
          </div>
        </div>

        <button
          type="button"
          disabled={isBusy}
          onClick={onOpenCreateModal}
          className="inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-xl bg-amber-500 px-3.5 py-2 text-xs font-bold text-slate-950 transition-colors hover:bg-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          <PlusCircle className="h-4 w-4" aria-hidden="true" />
          <span>Thêm quy tắc</span>
        </button>
      </div>

      <div className="overflow-x-auto rounded-xl border border-border-subtle bg-surface-deep">
        <table className="w-full min-w-[760px] border-collapse text-left text-xs">
          <caption className="sr-only">Bảng quản lý các quy tắc chặn đang áp dụng</caption>
          <thead>
            <tr className="border-b border-border-subtle bg-surface-subtle text-[11px] font-semibold text-ink-secondary">
              <th scope="col" className="px-3.5 py-2.5">
                Loại đối tượng
              </th>
              <th scope="col" className="px-3.5 py-2.5">
                Định danh đã che giấu
              </th>
              <th scope="col" className="px-3.5 py-2.5">
                Lý do áp dụng
              </th>
              <th scope="col" className="px-3.5 py-2.5">
                Trạng thái
              </th>
              <th scope="col" className="px-3.5 py-2.5">
                Thời điểm tạo
              </th>
              <th scope="col" className="px-3.5 py-2.5">
                Thời gian hết hạn
              </th>
              <th scope="col" className="px-3.5 py-2.5 text-right">
                Thao tác
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-subtle/60">
            {rules.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-xs text-ink-muted">
                  Hiện chưa có quy tắc chặn nào đang áp dụng. Chọn một chiến dịch cần xem xét hoặc
                  nhấn &ldquo;Thêm quy tắc&rdquo; để khởi tạo.
                </td>
              </tr>
            ) : (
              rules.map((rule) => {
                const status = computeRuleStatus(rule.expires_at, nowMs);
                const statusBadgeStyle =
                  status.code === "expired"
                    ? "bg-surface-elevated text-ink-muted"
                    : status.code === "expiring"
                      ? "bg-amber-500/20 text-amber-200"
                      : "bg-rose-500/20 text-rose-200";

                return (
                  <tr key={rule.rule_id} className="transition-colors hover:bg-surface-subtle/60">
                    <td className="px-3.5 py-3 text-ink-secondary">
                      {IOC_TYPE_COPY[rule.ioc_type]}
                    </td>
                    <td className="tabular-num px-3.5 py-3 font-mono font-bold text-rose-200">
                      <span className="inline-flex items-center gap-1.5">
                        <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-rose-400" aria-hidden="true" />
                        <span>{formatMaskedIoc(rule.masked_value, rule.rule_id)}</span>
                      </span>
                    </td>
                    <td className="max-w-[260px] px-3.5 py-3 text-ink-secondary">
                      <p className="line-clamp-2" title={rule.reason}>
                        {rule.reason}
                      </p>
                    </td>
                    <td className="px-3.5 py-3">
                      <span
                        className={`inline-block rounded-md px-2 py-0.5 text-[10px] font-bold ${statusBadgeStyle}`}
                      >
                        {status.label}
                      </span>
                    </td>
                    <td className="tabular-num px-3.5 py-3 font-mono text-[11px] text-ink-muted">
                      {formatRadarTimestamp(rule.created_at)}
                    </td>
                    <td className="tabular-num px-3.5 py-3">
                      <div className="font-mono text-[11px] text-ink">
                        {formatRadarTimestamp(rule.expires_at)}
                      </div>
                      <div className="text-[10px] text-amber-300">
                        {formatRemainingTtl(rule.expires_at, nowMs)}
                      </div>
                    </td>
                    <td className="px-3.5 py-3 text-right">
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => onRequestRevokeRule(rule)}
                        aria-label={`Thu hồi quy tắc chặn ${rule.masked_value}`}
                        className="inline-flex min-h-[32px] cursor-pointer items-center gap-1 rounded-lg border border-border-strong bg-surface-subtle px-2.5 py-1 text-[11px] font-semibold text-ink-secondary transition-colors hover:border-rose-400 hover:text-rose-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>Thu hồi</span>
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {auditLogs.length > 0 && (
        <details className="rounded-xl border border-border-subtle bg-surface-subtle/70 px-3.5 py-2.5 text-xs">
          <summary className="flex cursor-pointer items-center justify-between gap-2 font-semibold text-ink-secondary hover:text-ink">
            <span className="inline-flex items-center gap-1.5">
              <History className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
              <span>Nhật ký thao tác quản trị ({auditLogs.length})</span>
            </span>
            <span className="text-[11px] font-normal text-ink-muted">Mở rộng</span>
          </summary>

          <div className="mt-2.5 divide-y divide-border-subtle/60 border-t border-border-subtle pt-2">
            {auditLogs.slice(0, 8).map((ev) => (
              <div
                key={ev.audit_id}
                className="flex flex-wrap items-center justify-between gap-2 py-2 text-[11px]"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                      ev.outcome === "allowed"
                        ? "bg-emerald-500/15 text-emerald-300"
                        : "bg-rose-500/15 text-rose-300"
                    }`}
                  >
                    {AUDIT_ACTION_LABELS[ev.action]}
                  </span>
                  {ev.masked_target && (
                    <code className="rounded bg-surface-elevated px-1.5 py-0.5 font-mono text-ink">
                      {formatMaskedIoc(ev.masked_target)}
                    </code>
                  )}
                  <span className="text-ink-secondary">{ev.detail}</span>
                </div>
                <span className="tabular-num shrink-0 font-mono text-[10px] text-ink-muted">
                  {formatRadarTimestamp(ev.created_at)}
                </span>
              </div>
            ))}
          </div>
        </details>
      )}
    </section>
  );
}
