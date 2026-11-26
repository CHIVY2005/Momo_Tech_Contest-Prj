"use client";

import { KeyRound, Lock, PlusCircle, RotateCcw, ShieldAlert, Trash2 } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { formatRemainingTtl } from "@/lib/radarLayout";
import type { BlockRule, IocType } from "@/lib/types";

interface BlockRuleManagerProps {
  rules: BlockRule[];
  analystPin: string;
  nowMs: number;
  isBusy: boolean;
  onPinChange: (pin: string) => void;
  onCreateManualRule: (iocType: IocType, rawValue: string, reason: string) => Promise<boolean>;
  onRevokeRule: (ruleId: string) => void;
  onResetRules: () => void;
}

const DEFAULT_TTL_MS = 30 * 60 * 1000;

function computeTtlProgressPct(expiresAt: string | null | undefined, nowMs: number): number | null {
  if (!expiresAt) return null;
  const expMs = Date.parse(expiresAt);
  if (!Number.isFinite(expMs)) return null;
  const rem = Math.max(0, expMs - nowMs);
  return Math.min(100, Math.max(2, Math.round((rem / DEFAULT_TTL_MS) * 100)));
}

export function BlockRuleManager({
  rules,
  analystPin,
  nowMs,
  isBusy,
  onPinChange,
  onCreateManualRule,
  onRevokeRule,
  onResetRules,
}: BlockRuleManagerProps) {
  const [iocType, setIocType] = useState<IocType>("bank_account");
  const [rawValue, setRawValue] = useState("");
  const [reason, setReason] = useState("Tài khoản trung gian nhận tiền lừa đảo (Fraud Ops xác minh)");
  const [confirmRevokeId, setConfirmRevokeId] = useState<string | null>(null);

  useEffect(() => {
    if (!confirmRevokeId) return;
    const timer = window.setTimeout(() => setConfirmRevokeId(null), 4000);
    return () => window.clearTimeout(timer);
  }, [confirmRevokeId]);

  async function handleSubmit(ev: FormEvent) {
    ev.preventDefault();
    if (!rawValue.trim() || !reason.trim()) return;
    const created = await onCreateManualRule(iocType, rawValue.trim(), reason.trim());
    if (created) {
      setRawValue("");
    }
  }

  return (
    <section
      aria-labelledby="block-manager-heading"
      className="space-y-4 rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-lg sm:p-5"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Lock className="h-5 w-5 text-rose-400" aria-hidden="true" />
          <h2 id="block-manager-heading" className="text-sm font-bold text-ink">
            Quản lý Danh sách Chặn Tức thì &amp; Cách ly Đa Giám khảo (TTL 30m)
          </h2>
        </div>

        <button
          type="button"
          disabled={isBusy}
          onClick={onResetRules}
          className="inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-lg border border-border-strong bg-surface-subtle px-3 py-1.5 text-xs font-semibold text-ink transition-colors hover:border-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          <RotateCcw className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
          <span>Khôi phục Demo (Reset)</span>
        </button>
      </div>

      <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 p-3">
        <label
          htmlFor="radar-analyst-pin"
          className="flex items-center gap-1.5 text-xs font-semibold text-amber-200"
        >
          <KeyRound className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
          <span>Mã PIN Xác thực Chuyên viên Fraud Ops (Chế độ Trải nghiệm Giám khảo)</span>
        </label>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <input
            id="radar-analyst-pin"
            type="password"
            autoComplete="off"
            value={analystPin}
            onChange={(e) => onPinChange(e.target.value)}
            placeholder="Nhập PIN..."
            className="tabular-num w-36 rounded-lg border border-amber-500/45 bg-surface-subtle px-3 py-2 font-mono text-xs font-bold text-amber-200 placeholder:text-ink-muted"
          />
          <span className="text-[11px] text-ink-secondary">
            Thử đổi sai PIN (&rarr; HTTP 403) hoặc khóa{" "}
            <button
              type="button"
              onClick={() => {
                setIocType("domain");
                setRawValue("vietcombank.com.vn");
              }}
              className="cursor-pointer font-mono text-sky-300 underline hover:text-sky-200"
            >
              vietcombank.com.vn
            </button>{" "}
            (&rarr; HTTP 409 chống phá hoại IOC sạch).
          </span>
        </div>
      </div>

      <form
        onSubmit={(ev) => void handleSubmit(ev)}
        className="space-y-2.5 rounded-xl border border-border-subtle bg-surface-subtle p-3.5"
      >
        <p className="text-xs font-semibold text-ink">Ban hành Quy tắc Chặn Thủ công:</p>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
          <div>
            <label htmlFor="manual-ioc-type" className="sr-only">
              Loại IOC
            </label>
            <select
              id="manual-ioc-type"
              value={iocType}
              onChange={(e) => setIocType(e.target.value as IocType)}
              className="w-full rounded-lg border border-border-strong bg-surface-elevated px-2.5 py-2 text-xs text-ink"
            >
              <option value="bank_account">Số tài khoản (STK)</option>
              <option value="domain">Tên miền (Domain)</option>
              <option value="phone">Số điện thoại</option>
            </select>
          </div>
          <div className="sm:col-span-2">
            <label htmlFor="manual-ioc-value" className="sr-only">
              Giá trị thực thể cần chặn
            </label>
            <input
              id="manual-ioc-value"
              type="text"
              value={rawValue}
              onChange={(e) => setRawValue(e.target.value)}
              placeholder="Nhập STK, tên miền hoặc SĐT (sẽ băm SHA-256 & che PII tự động)"
              className="w-full rounded-lg border border-border-strong bg-surface-elevated px-3 py-2 font-mono text-xs text-ink placeholder:text-ink-muted"
            />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="manual-ioc-reason" className="sr-only">
            Lý do chặn
          </label>
          <input
            id="manual-ioc-reason"
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="min-w-0 flex-1 rounded-lg border border-border-strong bg-surface-elevated px-3 py-2 text-xs text-ink"
          />
          <button
            type="submit"
            disabled={isBusy || !rawValue.trim()}
            className="inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-lg bg-amber-500 px-3.5 py-2 text-xs font-bold text-slate-950 hover:bg-amber-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <PlusCircle className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Thêm Lệnh Chặn</span>
          </button>
        </div>
      </form>

      <div className="space-y-2">
        <p className="tabular-num text-xs font-semibold text-ink-secondary">
          Quy tắc đang kích hoạt ({rules.length}):
        </p>
        {rules.length === 0 ? (
          <p className="rounded-xl border border-border-subtle bg-surface-subtle p-3 text-xs text-ink-muted">
            Chưa có lệnh chặn khẩn cấp nào đang bật. Hãy bấm &ldquo;1-Click Khóa Khẩn cấp&rdquo; ở Hàng đợi Chiến dịch phía trên để kiểm chứng vòng lặp khép kín!
          </p>
        ) : (
          rules.map((rule) => {
            const ttlPct = computeTtlProgressPct(rule.expires_at, nowMs);
            const isConfirming = confirmRevokeId === rule.rule_id;

            return (
              <div
                key={rule.rule_id}
                className="space-y-2 rounded-xl border border-rose-500/45 bg-rose-500/10 px-3.5 py-2.5 text-xs"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 shrink-0 text-rose-400" aria-hidden="true" />
                    <div>
                      <span className="tabular-num font-mono font-bold text-rose-200">
                        {rule.masked_value}
                      </span>
                      <span className="ml-2 rounded bg-surface-elevated px-1.5 py-0.5 font-mono text-[10px] text-ink-secondary">
                        {rule.ioc_type}
                      </span>
                      <p className="text-[11px] text-ink-secondary">{rule.reason}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="tabular-num rounded bg-surface-deep px-2 py-1 font-mono text-[10px] text-amber-300">
                      {formatRemainingTtl(rule.expires_at, nowMs)}
                    </span>
                    {isConfirming ? (
                      <div className="inline-flex items-center gap-1">
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => {
                            setConfirmRevokeId(null);
                            onRevokeRule(rule.rule_id);
                          }}
                          className="min-h-[32px] cursor-pointer rounded bg-rose-600 px-2.5 py-1 text-[10px] font-bold text-white hover:bg-rose-500 disabled:opacity-50"
                        >
                          Xác nhận gỡ
                        </button>
                        <button
                          type="button"
                          onClick={() => setConfirmRevokeId(null)}
                          className="min-h-[32px] cursor-pointer rounded border border-border-strong bg-surface-subtle px-2 py-1 text-[10px] text-ink-secondary hover:text-ink"
                        >
                          Hủy
                        </button>
                      </div>
                    ) : (
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => setConfirmRevokeId(rule.rule_id)}
                        aria-label={`Thu hồi lệnh chặn ${rule.masked_value}`}
                        className="inline-flex min-h-[32px] cursor-pointer items-center gap-1 rounded border border-border-strong bg-surface-subtle px-2.5 py-1 text-[10px] font-semibold text-ink-secondary hover:border-rose-400 hover:text-rose-200 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <Trash2 className="h-3 w-3" aria-hidden="true" />
                        <span>Gỡ</span>
                      </button>
                    )}
                  </div>
                </div>

                {ttlPct !== null && (
                  <div className="h-1 w-full overflow-hidden rounded-full bg-surface-deep/80">
                    <div
                      className="h-full rounded-full bg-amber-400/80 transition-all duration-300"
                      style={{ width: `${ttlPct}%` }}
                    />
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}
