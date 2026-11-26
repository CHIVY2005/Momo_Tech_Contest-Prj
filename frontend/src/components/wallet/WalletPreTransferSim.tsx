"use client";

import { AlertTriangle, Ban, CheckCircle2, Lock, PhoneOff, ShieldAlert, Timer } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { maskDisplayIoc } from "@/lib/api";
import type { AnalysisReport } from "@/lib/types";

interface WalletPreTransferSimProps {
  report: AnalysisReport;
  transferAmountInput: string;
}

type WalletSimulationOutcome = "pending" | "aborted_safely" | "overridden_at_risk";

export function WalletPreTransferSim({
  report,
  transferAmountInput,
}: WalletPreTransferSimProps) {
  const pre = report.actions.pre_transfer;
  const [deadlineMs, setDeadlineMs] = useState<number>(() =>
    pre.should_hold_transfer ? Date.now() + pre.cooling_off_seconds * 1000 : 0,
  );
  const [secondsLeft, setSecondsLeft] = useState<number>(
    pre.should_hold_transfer ? pre.cooling_off_seconds : 0,
  );
  const [checkedQuestions, setCheckedQuestions] = useState<Record<number, boolean>>({});
  const [outcome, setOutcome] = useState<WalletSimulationOutcome>("pending");

  const startFreshHold = useCallback(() => {
    const secs = pre.should_hold_transfer ? pre.cooling_off_seconds : 0;
    setDeadlineMs(secs > 0 ? Date.now() + secs * 1000 : 0);
    setSecondsLeft(secs);
    setCheckedQuestions({});
    setOutcome("pending");
  }, [pre.cooling_off_seconds, pre.should_hold_transfer]);

  useEffect(() => {
    startFreshHold();
  }, [report.case_id, startFreshHold]);

  useEffect(() => {
    if (deadlineMs <= 0 || pre.blocked_by_ops_rule || outcome !== "pending") {
      return;
    }
    const syncElapsed = () => {
      const rem = Math.max(0, Math.ceil((deadlineMs - Date.now()) / 1000));
      setSecondsLeft(rem);
    };
    syncElapsed();
    const timer = window.setInterval(syncElapsed, 250);
    document.addEventListener("visibilitychange", syncElapsed);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", syncElapsed);
    };
  }, [deadlineMs, pre.blocked_by_ops_rule, outcome]);

  if (!pre.should_hold_transfer && report.mode !== "wallet_transfer") {
    return null;
  }

  const allVerified = pre.verification_questions.every((_, idx) => Boolean(checkedQuestions[idx]));
  const canProceedOverride =
    !pre.blocked_by_ops_rule &&
    secondsLeft === 0 &&
    (pre.verification_questions.length === 0 || allVerified);

  const trimmedAmt = transferAmountInput.trim();
  const parsedAmount = trimmedAmt !== "" ? Number(trimmedAmt) : Number.NaN;
  const formattedAmount =
    trimmedAmt !== "" && Number.isFinite(parsedAmount) && parsedAmount >= 0
      ? `${parsedAmount.toLocaleString("vi-VN")} VND`
      : "Chưa nhập số tiền (Mô phỏng trước chuyển khoản)";

  const vqrAcct = report.vietqr_findings.find((v) => v.account_number)?.account_number;
  const rawMention = vqrAcct ?? report.iocs.bank_accounts[0] ?? report.iocs.phones[0] ?? null;
  const targetDisplay = rawMention ? maskDisplayIoc(rawMention) : "Chưa khai báo STK đích";
  const targetLabel = vqrAcct ? "Tài khoản thụ hưởng (VietQR): " : "Thực thể trích xuất liên quan: ";

  return (
    <section
      aria-labelledby="wallet-guard-heading"
      className="rounded-2xl border-2 border-rose-500/60 bg-gradient-to-b from-[#1a1120] to-[#111827] p-5 shadow-xl"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Lock className="h-5 w-5 text-rose-400" aria-hidden="true" />
          <h3 id="wallet-guard-heading" className="text-sm font-bold text-slate-50">
            Chốt Chặn Phút 89 — Can thiệp Trước Xác Nhận Chuyển Tiền
          </h3>
        </div>
        {pre.triggered_by_active_call && (
          <span className="rounded-full border border-rose-500/50 bg-rose-500/20 px-2.5 py-0.5 text-[11px] font-semibold text-rose-200">
            Cảnh báo: Đang nghe điện thoại khi chuyển tiền
          </span>
        )}
      </div>

      <div className="mt-3 grid grid-cols-1 gap-2.5 rounded-xl border border-slate-800 bg-[#0b1120] p-3 text-xs sm:grid-cols-2">
        <div>
          <span className="text-slate-400">{targetLabel}</span>
          <strong className="font-[family-name:var(--font-mono)] text-amber-300">
            {targetDisplay}
          </strong>
        </div>
        <div>
          <span className="text-slate-400">Số tiền lệnh chuyển: </span>
          <strong className="font-[family-name:var(--font-mono)] text-slate-100">
            {formattedAmount}
          </strong>
        </div>
      </div>

      {outcome === "aborted_safely" ? (
        <div
          role="status"
          className="mt-4 flex items-center gap-2.5 rounded-xl border border-emerald-500/40 bg-emerald-500/15 p-4 text-xs font-semibold text-emerald-200"
        >
          <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" aria-hidden="true" />
          <span>
            Đã hủy lệnh chuyển tiền an toàn! Số dư ví của bạn được bảo toàn nguyên vẹn.
          </span>
        </div>
      ) : outcome === "overridden_at_risk" ? (
        <div
          role="status"
          className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-500/50 bg-amber-500/15 p-4 text-xs text-amber-100"
        >
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden="true" />
            <span>
              <strong>Mô phỏng Ghi nhận Miễn trừ Trách nhiệm:</strong> Người dùng đã chờ hết 30 giây làm
              nguội và tích xác nhận tự chịu rủi ro cho hồ sơ{" "}
              <code className="font-[family-name:var(--font-mono)]">{report.case_id}</code>. Hệ thống ví
              đã ghi nhật ký cảnh báo bắt buộc trước khi giải ngân.
            </span>
          </div>
          <button
            type="button"
            onClick={startFreshHold}
            className="cursor-pointer rounded-lg border border-amber-400/50 bg-slate-950 px-2.5 py-1 text-[11px] font-semibold text-amber-200 hover:bg-slate-900"
          >
            Khởi động lại Khóa 30s
          </button>
        </div>
      ) : pre.blocked_by_ops_rule ? (
        <div
          role="alert"
          className="mt-4 rounded-xl border border-rose-500 bg-rose-950/80 p-4 text-xs text-rose-100"
        >
          <div className="flex items-center gap-2 font-bold text-rose-200 uppercase">
            <Ban className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>GIAO DỊCH BỊ CHẶN CỨNG BỞI QUY TẮC FRAUD OPS (/radar)</span>
          </div>
          <p className="mt-1.5 leading-relaxed">
            {pre.warning_headline ||
              "Tài khoản thụ hưởng này đã bị Trung tâm Chống Gian lận khóa khẩn cấp trên toàn hệ thống. Không thể thực hiện chuyển tiền."}
          </p>
        </div>
      ) : pre.should_hold_transfer ? (
        <div className="mt-4 space-y-3.5">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-500/50 bg-amber-500/15 p-3.5">
            <div className="flex items-start gap-2.5">
              <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden="true" />
              <p className="text-xs font-semibold leading-relaxed text-amber-100">
                {pre.warning_headline}
              </p>
            </div>
            <div
              aria-live="polite"
              className="flex items-center gap-1.5 rounded-lg bg-slate-950 px-3 py-1.5 font-[family-name:var(--font-mono)] text-sm font-bold text-amber-300"
            >
              <Timer className="h-4 w-4 text-amber-400" aria-hidden="true" />
              <span>
                {secondsLeft > 0 ? `Khóa làm nguội: ${secondsLeft}s` : "Đã hết 30s làm nguội"}
              </span>
            </div>
          </div>

          {pre.verification_questions.length > 0 && (
            <fieldset className="space-y-2 rounded-xl border border-slate-800 bg-[#0b1120] p-3.5">
              <legend className="px-1 text-xs font-semibold text-slate-200">
                Câu hỏi Phá vỡ Thao túng Tâm lý (Bắt buộc xác nhận từng mục):
              </legend>
              {pre.verification_questions.map((q, idx) => (
                <label
                  key={q}
                  className="flex cursor-pointer items-start gap-2.5 rounded-lg p-1.5 text-xs text-slate-200 hover:bg-slate-900"
                >
                  <input
                    type="checkbox"
                    checked={Boolean(checkedQuestions[idx])}
                    onChange={(e) =>
                      setCheckedQuestions((prev) => ({ ...prev, [idx]: e.target.checked }))
                    }
                    className="mt-0.5 h-4 w-4 shrink-0 cursor-pointer accent-amber-500"
                  />
                  <span>{q}</span>
                </label>
              ))}
            </fieldset>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <button
              type="button"
              onClick={() => setOutcome("aborted_safely")}
              className="inline-flex cursor-pointer items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2.5 text-xs font-bold text-slate-950 transition-colors hover:bg-emerald-400"
            >
              <PhoneOff className="h-4 w-4" aria-hidden="true" />
              <span>Dừng Giao dịch &amp; Ngắt Cuộc gọi Ngay (An toàn)</span>
            </button>

            <button
              type="button"
              disabled={!canProceedOverride}
              onClick={() => setOutcome("overridden_at_risk")}
              className="cursor-pointer rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs font-medium text-slate-300 transition-colors enabled:hover:border-rose-500/60 enabled:hover:text-rose-200 disabled:cursor-not-allowed disabled:opacity-45"
            >
              {secondsLeft > 0
                ? `Đang khóa xác nhận (${secondsLeft}s)`
                : "Tôi tự chịu trách nhiệm tiếp tục"}
            </button>
          </div>
        </div>
      ) : (
        <p className="mt-3 text-xs text-emerald-300">
          Giao dịch không kích hoạt khóa làm nguội. Vẫn luôn kiểm tra kỹ tên người thụ hưởng trước khi xác nhận.
        </p>
      )}
    </section>
  );
}
