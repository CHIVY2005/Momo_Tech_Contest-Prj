"use client";

import { KeyRound, Lock, PlusCircle, RotateCcw, ShieldAlert } from "lucide-react";
import { type FormEvent, useState } from "react";

import { formatRemainingTtl } from "@/lib/radarLayout";
import type { BlockRule, IocType } from "@/lib/types";

interface BlockRuleManagerProps {
  rules: BlockRule[];
  analystPin: string;
  nowMs: number;
  isBusy: boolean;
  onPinChange: (pin: string) => void;
  onCreateManualRule: (iocType: IocType, rawValue: string, reason: string) => Promise<boolean>;
  onResetRules: () => void;
}

export function BlockRuleManager({
  rules,
  analystPin,
  nowMs,
  isBusy,
  onPinChange,
  onCreateManualRule,
  onResetRules,
}: BlockRuleManagerProps) {
  const [iocType, setIocType] = useState<IocType>("bank_account");
  const [rawValue, setRawValue] = useState("");
  const [reason, setReason] = useState("Tài khoản trung gian nhận tiền lừa đảo (Fraud Ops xác minh)");

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
      className="space-y-4 rounded-2xl border border-slate-800 bg-[#111827]/95 p-5 shadow-lg"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Lock className="h-5 w-5 text-rose-400" aria-hidden="true" />
          <h2 id="block-manager-heading" className="text-sm font-bold text-slate-50">
            Quản lý Danh sách Chặn Tức thì &amp; Cách ly Đa Giám khảo (TTL 30m)
          </h2>
        </div>

        <button
          type="button"
          disabled={isBusy}
          onClick={onResetRules}
          className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-200 transition-colors hover:border-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          <RotateCcw className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
          <span>Khôi phục Demo (Reset)</span>
        </button>
      </div>

      <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3">
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
            className="w-36 rounded-lg border border-amber-500/40 bg-[#0b1120] px-3 py-1.5 font-[family-name:var(--font-mono)] text-xs font-bold text-amber-200"
          />
          <span className="text-[11px] text-slate-300">
            Thử đổi sai PIN (&rarr; HTTP 403) hoặc khóa{" "}
            <button
              type="button"
              onClick={() => {
                setIocType("domain");
                setRawValue("vietcombank.com.vn");
              }}
              className="cursor-pointer font-[family-name:var(--font-mono)] text-sky-300 underline hover:text-sky-200"
            >
              vietcombank.com.vn
            </button>{" "}
            (&rarr; HTTP 409 chống phá hoại IOC sạch).
          </span>
        </div>
      </div>

      <form
        onSubmit={(ev) => void handleSubmit(ev)}
        className="space-y-2.5 rounded-xl border border-slate-800 bg-[#0b1120] p-3.5"
      >
        <p className="text-xs font-semibold text-slate-200">Ban hành Quy tắc Chặn Thủ công:</p>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
          <div>
            <label htmlFor="manual-ioc-type" className="sr-only">
              Loại IOC
            </label>
            <select
              id="manual-ioc-type"
              value={iocType}
              onChange={(e) => setIocType(e.target.value as IocType)}
              className="w-full rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-2 text-xs text-slate-100"
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
              className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-[family-name:var(--font-mono)] text-xs text-slate-100 placeholder:text-slate-500"
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
            className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200"
          />
          <button
            type="submit"
            disabled={isBusy || !rawValue.trim()}
            className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg bg-amber-500 px-3.5 py-2 text-xs font-bold text-slate-950 hover:bg-amber-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <PlusCircle className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Thêm Lệnh Chặn</span>
          </button>
        </div>
      </form>

      <div className="space-y-2">
        <p className="text-xs font-semibold text-slate-300">
          Quy tắc đang kích hoạt ({rules.length}):
        </p>
        {rules.length === 0 ? (
          <p className="rounded-xl border border-slate-800 bg-[#0b1120] p-3 text-xs text-slate-400">
            Chưa có lệnh chặn khẩn cấp nào đang bật. Hãy bấm &ldquo;1-Click Khóa Khẩn cấp&rdquo; ở cột bên trái để kiểm chứng vòng lặp khép kín!
          </p>
        ) : (
          rules.map((rule) => (
            <div
              key={rule.rule_id}
              className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-rose-500/40 bg-rose-500/10 px-3.5 py-2.5 text-xs"
            >
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 shrink-0 text-rose-400" aria-hidden="true" />
                <div>
                  <span className="font-[family-name:var(--font-mono)] font-bold text-rose-200">
                    {rule.masked_value}
                  </span>
                  <span className="ml-2 rounded bg-slate-900 px-1.5 py-0.5 font-[family-name:var(--font-mono)] text-[10px] text-slate-300">
                    {rule.ioc_type}
                  </span>
                  <p className="text-[11px] text-slate-300">{rule.reason}</p>
                </div>
              </div>
              <span className="rounded bg-slate-950 px-2 py-0.5 font-[family-name:var(--font-mono)] text-[10px] text-amber-300">
                {formatRemainingTtl(rule.expires_at, nowMs)}
              </span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
