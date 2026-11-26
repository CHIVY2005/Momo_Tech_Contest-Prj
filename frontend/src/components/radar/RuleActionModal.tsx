"use client";

import { AlertCircle, Ban, KeyRound, Loader2, RotateCcw, ShieldCheck, Trash2, X } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { validateAnalystPinInput } from "@/lib/api";
import { IOC_TYPE_COPY } from "@/lib/copy";
import type { BlockRule, IocType } from "@/lib/types";

export interface TargetIocOption {
  iocType: IocType;
  iocHash: string;
  maskedLabel: string;
}

export type RuleModalState =
  | {
      kind: "create_manual";
      defaultIocType?: IocType;
    }
  | {
      kind: "create_targeted";
      title: string;
      targets: TargetIocOption[];
      initialHash: string;
      defaultReason: string;
    }
  | {
      kind: "revoke";
      rule: BlockRule;
    }
  | {
      kind: "reset_demo";
      activeCount: number;
    };

interface RuleActionModalProps {
  modal: RuleModalState | null;
  isBusy: boolean;
  onClose: () => void;
  onCreateRule: (payload: {
    iocType: IocType;
    rawValue?: string;
    iocHash?: string;
    reason: string;
    ttlMinutes: number;
    analystPin: string;
  }) => Promise<string | null>;
  onRevokeRule: (ruleId: string, analystPin: string) => Promise<string | null>;
  onResetDemoRules: (analystPin: string) => Promise<string | null>;
}

const TTL_OPTIONS = [
  { minutes: 15, label: "15 phút" },
  { minutes: 30, label: "30 phút (mặc định)" },
  { minutes: 120, label: "2 giờ" },
  { minutes: 1440, label: "24 giờ" },
];

export function RuleActionModal({
  modal,
  isBusy,
  onClose,
  onCreateRule,
  onRevokeRule,
  onResetDemoRules,
}: RuleActionModalProps) {
  const [iocType, setIocType] = useState<IocType>("bank_account");
  const [rawValue, setRawValue] = useState("");
  const [selectedHash, setSelectedHash] = useState("");
  const [reason, setReason] = useState("");
  const [ttlMinutes, setTtlMinutes] = useState<number>(30);
  const [pin, setPin] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);

  useEffect(() => {
    if (!modal) return;
    setLocalError(null);
    setPin("");
    setTtlMinutes(30);
    if (modal.kind === "create_manual") {
      setIocType(modal.defaultIocType ?? "bank_account");
      setRawValue("");
      setReason("Tài khoản hoặc tên miền liên quan đến dấu hiệu lừa đảo");
      setSelectedHash("");
    } else if (modal.kind === "create_targeted") {
      const initial =
        modal.targets.find((t) => t.iocHash === modal.initialHash) ?? modal.targets[0];
      setSelectedHash(initial?.iocHash ?? "");
      setIocType(initial?.iocType ?? "bank_account");
      setReason(modal.defaultReason);
      setRawValue("");
    }
  }, [modal]);

  useEffect(() => {
    if (!modal) return;
    function onKey(ev: KeyboardEvent) {
      if (ev.key === "Escape" && !isBusy) onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [modal, isBusy, onClose]);

  if (!modal) return null;

  async function handleSubmit(ev: FormEvent) {
    ev.preventDefault();
    if (!modal || isBusy) return;

    const pinErr = validateAnalystPinInput(pin);
    if (pinErr) {
      setLocalError(pinErr);
      return;
    }

    setLocalError(null);
    let errMsg: string | null = null;

    if (modal.kind === "create_manual") {
      if (rawValue.trim().length < 3) {
        setLocalError("Vui lòng nhập đối tượng cần chặn (tối thiểu 3 ký tự).");
        return;
      }
      if (reason.trim().length < 3) {
        setLocalError("Vui lòng nhập lý do áp dụng quy tắc.");
        return;
      }
      errMsg = await onCreateRule({
        iocType,
        rawValue: rawValue.trim(),
        reason: reason.trim(),
        ttlMinutes,
        analystPin: pin.trim(),
      });
    } else if (modal.kind === "create_targeted") {
      const target = modal.targets.find((t) => t.iocHash === selectedHash);
      if (!target) {
        setLocalError("Vui lòng chọn một đối tượng cụ thể để áp dụng quy tắc.");
        return;
      }
      if (reason.trim().length < 3) {
        setLocalError("Vui lòng nhập lý do áp dụng quy tắc.");
        return;
      }
      errMsg = await onCreateRule({
        iocType: target.iocType,
        iocHash: target.iocHash,
        reason: reason.trim(),
        ttlMinutes,
        analystPin: pin.trim(),
      });
    } else if (modal.kind === "revoke") {
      errMsg = await onRevokeRule(modal.rule.rule_id, pin.trim());
    } else if (modal.kind === "reset_demo") {
      errMsg = await onResetDemoRules(pin.trim());
    }

    if (errMsg) {
      setLocalError(errMsg);
    } else {
      onClose();
    }
  }

  const heading =
    modal.kind === "create_manual"
      ? "Thêm quy tắc chặn mới"
      : modal.kind === "create_targeted"
        ? "Xác nhận áp dụng quy tắc chặn"
        : modal.kind === "revoke"
          ? "Xác nhận thu hồi quy tắc"
          : "Khôi phục trạng thái dữ liệu mẫu";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        aria-hidden="true"
        onClick={() => !isBusy && onClose()}
        className="fixed inset-0 bg-slate-950/75 backdrop-blur-xs"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="rule-modal-title"
        className="relative z-10 w-full max-w-md rounded-2xl border border-border-strong bg-surface p-5 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            {modal.kind === "revoke" ? (
              <Trash2 className="h-5 w-5 text-rose-400" aria-hidden="true" />
            ) : modal.kind === "reset_demo" ? (
              <RotateCcw className="h-5 w-5 text-amber-400" aria-hidden="true" />
            ) : (
              <Ban className="h-5 w-5 text-rose-400" aria-hidden="true" />
            )}
            <h2 id="rule-modal-title" className="text-sm font-bold text-ink">
              {heading}
            </h2>
          </div>
          <button
            type="button"
            disabled={isBusy}
            onClick={onClose}
            aria-label="Đóng hộp thoại"
            className="inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-lg border border-border-strong bg-surface-subtle text-ink-secondary hover:text-ink disabled:opacity-50"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <form onSubmit={(ev) => void handleSubmit(ev)} className="mt-4 space-y-3.5 text-xs">
          {modal.kind === "create_manual" && (
            <>
              <div>
                <label
                  htmlFor="modal-ioc-type"
                  className="mb-1 block font-semibold text-ink-secondary"
                >
                  Loại đối tượng
                </label>
                <select
                  id="modal-ioc-type"
                  value={iocType}
                  onChange={(e) => setIocType(e.target.value as IocType)}
                  className="w-full rounded-xl border border-border-strong bg-surface-subtle px-3 py-2 text-xs text-ink"
                >
                  <option value="bank_account">{IOC_TYPE_COPY.bank_account}</option>
                  <option value="domain">{IOC_TYPE_COPY.domain}</option>
                  <option value="phone">{IOC_TYPE_COPY.phone}</option>
                </select>
              </div>

              <div>
                <label
                  htmlFor="modal-ioc-value"
                  className="mb-1 block font-semibold text-ink-secondary"
                >
                  Đối tượng cần chặn
                </label>
                <input
                  id="modal-ioc-value"
                  type="text"
                  autoComplete="off"
                  value={rawValue}
                  onChange={(e) => setRawValue(e.target.value)}
                  placeholder="Nhập số tài khoản, tên miền hoặc số điện thoại"
                  className="w-full rounded-xl border border-border-strong bg-surface-subtle px-3 py-2 font-mono text-xs text-ink placeholder:text-ink-muted"
                />
                <p className="mt-1 text-[11px] text-ink-muted">
                  Giá trị được băm bảo mật và che giấu tự động trước khi lưu.
                </p>
              </div>
            </>
          )}

          {modal.kind === "create_targeted" && (
            <div className="space-y-2">
              <p className="text-[11px] text-ink-muted">
                Chiến dịch: <strong className="text-ink">{modal.title}</strong>
              </p>
              <fieldset className="space-y-1.5">
                <legend className="mb-1 font-semibold text-ink-secondary">
                  Chọn duy nhất đối tượng áp dụng quy tắc
                </legend>
                {modal.targets.map((target) => {
                  const checked = selectedHash === target.iocHash;
                  return (
                    <label
                      key={target.iocHash}
                      className={`flex cursor-pointer items-center justify-between gap-2 rounded-xl border px-3 py-2 transition-colors ${
                        checked
                          ? "border-amber-400 bg-amber-500/10 text-ink"
                          : "border-border-subtle bg-surface-subtle text-ink-secondary hover:border-border-strong"
                      }`}
                    >
                      <span className="flex items-center gap-2">
                        <input
                          type="radio"
                          name="target-ioc"
                          value={target.iocHash}
                          checked={checked}
                          onChange={() => {
                            setSelectedHash(target.iocHash);
                            setIocType(target.iocType);
                          }}
                          className="h-3.5 w-3.5 accent-amber-400"
                        />
                        <span className="font-mono font-semibold text-ink">
                          {target.maskedLabel}
                        </span>
                      </span>
                      <span className="text-[11px] text-ink-muted">
                        {IOC_TYPE_COPY[target.iocType]}
                      </span>
                    </label>
                  );
                })}
              </fieldset>
            </div>
          )}

          {(modal.kind === "create_manual" || modal.kind === "create_targeted") && (
            <>
              <div>
                <label
                  htmlFor="modal-rule-reason"
                  className="mb-1 block font-semibold text-ink-secondary"
                >
                  Lý do áp dụng
                </label>
                <textarea
                  id="modal-rule-reason"
                  rows={2}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  className="w-full rounded-xl border border-border-strong bg-surface-subtle px-3 py-2 text-xs text-ink"
                />
              </div>

              <div>
                <label
                  htmlFor="modal-rule-ttl"
                  className="mb-1 block font-semibold text-ink-secondary"
                >
                  Thời hạn hiệu lực (TTL)
                </label>
                <select
                  id="modal-rule-ttl"
                  value={ttlMinutes}
                  onChange={(e) => setTtlMinutes(Number(e.target.value))}
                  className="w-full rounded-xl border border-border-strong bg-surface-subtle px-3 py-2 text-xs text-ink"
                >
                  {TTL_OPTIONS.map((opt) => (
                    <option key={opt.minutes} value={opt.minutes}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
            </>
          )}

          {modal.kind === "revoke" && (
            <div className="rounded-xl border border-rose-500/35 bg-rose-500/10 p-3 text-xs">
              <p className="text-ink-secondary">
                Thu hồi quy tắc đang áp dụng cho{" "}
                <strong className="font-mono text-rose-200">{modal.rule.masked_value}</strong> (
                {IOC_TYPE_COPY[modal.rule.ioc_type]}).
              </p>
              <p className="mt-1 text-[11px] text-ink-muted">Lý do hiện tại: {modal.rule.reason}</p>
            </div>
          )}

          {modal.kind === "reset_demo" && (
            <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 p-3 text-xs text-ink-secondary">
              Thao tác này sẽ thu hồi toàn bộ{" "}
              <strong className="tabular-num text-amber-200">{modal.activeCount}</strong> quy tắc
              tạm thời đang hoạt động để đưa môi trường thử nghiệm về trạng thái ban đầu.
            </div>
          )}

          {/* Admin verification requested ONLY when executing privileged mutations */}
          <div className="rounded-xl border border-amber-500/35 bg-amber-500/8 p-3">
            <label
              htmlFor="modal-analyst-pin"
              className="flex items-center gap-1.5 font-semibold text-amber-200"
            >
              <KeyRound className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
              <span>Xác thực quản trị viên (Mã PIN)</span>
            </label>
            <input
              id="modal-analyst-pin"
              type="password"
              autoComplete="off"
              value={pin}
              onChange={(e) => setPin(e.target.value)}
              placeholder="Nhập mã PIN quản trị để xác nhận"
              className="mt-2 w-full rounded-lg border border-amber-500/45 bg-surface px-3 py-2 font-mono text-xs text-ink placeholder:text-ink-muted"
            />
          </div>

          {localError && (
            <p
              role="alert"
              className="flex items-start gap-1.5 rounded-xl border border-rose-500/45 bg-rose-500/15 p-2.5 text-[11px] text-rose-100"
            >
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-300" aria-hidden="true" />
              <span>{localError}</span>
            </p>
          )}

          <div className="flex items-center justify-end gap-2 pt-1">
            <button
              type="button"
              disabled={isBusy}
              onClick={onClose}
              className="min-h-[38px] cursor-pointer rounded-xl border border-border-strong bg-surface-subtle px-3.5 py-2 text-xs font-semibold text-ink-secondary hover:text-ink disabled:opacity-50"
            >
              Hủy
            </button>
            <button
              type="submit"
              disabled={isBusy}
              className={`inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-xl px-4 py-2 text-xs font-bold transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${
                modal.kind === "revoke" || modal.kind === "create_targeted"
                  ? "bg-rose-600 text-white hover:bg-rose-500"
                  : "bg-amber-500 text-slate-950 hover:bg-amber-400"
              }`}
            >
              {isBusy ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              ) : (
                <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
              )}
              <span>
                {modal.kind === "revoke"
                  ? "Xác nhận thu hồi"
                  : modal.kind === "reset_demo"
                    ? "Xác nhận khôi phục"
                    : "Xác nhận áp dụng"}
              </span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
