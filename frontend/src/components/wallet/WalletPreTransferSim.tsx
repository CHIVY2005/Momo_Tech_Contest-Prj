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
  const totalHoldSeconds = pre.should_hold_transfer ? Math.max(1, pre.cooling_off_seconds) : 0;
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
      : "Chưa nhập số tiền (mô phỏng trước khi chuyển tiền)";

  const vqrAcct = report.vietqr_findings.find((v) => v.account_number)?.account_number;
  const rawMention = vqrAcct ?? report.iocs.bank_accounts[0] ?? report.iocs.phones[0] ?? null;
  const targetDisplay = rawMention ? maskDisplayIoc(rawMention) : "Chưa có số tài khoản nhận";
  const targetLabel = vqrAcct
    ? "Tài khoản nhận (từ mã VietQR): "
    : "Thông tin liên quan trong giao dịch: ";

  const elapsedPct =
    totalHoldSeconds > 0
      ? Math.min(100, Math.max(0, Math.round(((totalHoldSeconds - secondsLeft) / totalHoldSeconds) * 100)))
      : 100;

  // Announce only major milestones to screen readers (prevents per-second aria-live spam)
  const srMilestone =
    secondsLeft === 0
      ? "Đã hết thời gian tạm dừng để kiểm tra 30 giây."
      : secondsLeft === 10
        ? "Còn 10 giây tạm dừng để kiểm tra."
        : secondsLeft === pre.cooling_off_seconds
          ? `Đang tạm dừng để kiểm tra trong ${pre.cooling_off_seconds} giây.`
          : "";

  return (
    <section
      aria-labelledby="wallet-guard-heading"
      className="rounded-2xl border-2 border-rose-500/60 bg-gradient-to-b from-[#1a1120] to-surface p-5 shadow-xl"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Lock className="h-5 w-5 text-rose-400" aria-hidden="true" />
          <h3 id="wallet-guard-heading" className="text-sm font-bold text-ink">
            Ngăn chặn lừa đảo trước khi chuyển tiền
          </h3>
        </div>
        {pre.triggered_by_active_call && (
          <span className="rounded-full border border-rose-500/50 bg-rose-500/20 px-2.5 py-0.5 text-[11px] font-semibold text-rose-200">
            Đang nghe điện thoại khi chuẩn bị chuyển tiền
          </span>
        )}
      </div>

      <div className="mt-3 grid grid-cols-1 gap-2.5 rounded-xl border border-border-subtle bg-surface-subtle p-3 text-xs sm:grid-cols-2">
        <div>
          <span className="text-ink-muted">{targetLabel}</span>
          <strong className="tabular-num font-mono text-amber-300">{targetDisplay}</strong>
        </div>
        <div>
          <span className="text-ink-muted">Số tiền dự kiến chuyển: </span>
          <strong className="tabular-num font-mono text-ink">{formattedAmount}</strong>
        </div>
      </div>

      {outcome === "aborted_safely" ? (
        <div
          role="status"
          className="mt-4 flex items-center gap-2.5 rounded-xl border border-emerald-500/45 bg-emerald-500/15 p-4 text-xs font-semibold text-emerald-200"
        >
          <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" aria-hidden="true" />
          <span>Bạn đã hủy giao dịch an toàn. Tài sản của bạn vẫn được bảo toàn.</span>
        </div>
      ) : outcome === "overridden_at_risk" ? (
        <div
          role="status"
          className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-500/50 bg-amber-500/15 p-4 text-xs text-amber-100"
        >
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden="true" />
            <span>
              <strong>Mô phỏng xác nhận tiếp tục:</strong> Bạn đã chờ hết thời gian tạm dừng để
              kiểm tra 30 giây và xác nhận đã cân nhắc rủi ro trước khi chuyển tiền. Hệ thống đã ghi
              nhận cảnh báo trước giao dịch.
            </span>
          </div>
          <button
            type="button"
            onClick={startFreshHold}
            className="min-h-[38px] cursor-pointer rounded-lg border border-amber-400/50 bg-surface-deep px-3 py-1.5 text-xs font-semibold text-amber-200 hover:bg-surface-elevated"
          >
            Bật lại tạm dừng 30 giây
          </button>
        </div>
      ) : pre.blocked_by_ops_rule ? (
        <div
          role="alert"
          className="mt-4 rounded-xl border border-rose-500 bg-rose-950/80 p-4 text-xs text-rose-100"
        >
          <div className="flex items-center gap-2 font-bold text-rose-200">
            <Ban className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>Giao dịch bị chặn do dấu hiệu nghi vấn</span>
          </div>
          <p className="mt-1.5 leading-relaxed">
            {pre.warning_headline ||
              "Tài khoản nhận hoặc tên miền trong giao dịch này đang nằm trong danh sách chặn rủi ro trên toàn hệ thống. Không nên tiếp tục chuyển tiền."}
          </p>
        </div>
      ) : pre.should_hold_transfer ? (
        <div className="mt-4 space-y-3.5">
          <div className="rounded-xl border border-amber-500/50 bg-amber-500/15 p-3.5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-start gap-2.5">
                <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden="true" />
                <p className="text-xs font-semibold leading-relaxed text-amber-100">
                  {pre.warning_headline}
                </p>
              </div>
              <div className="tabular-num flex items-center gap-1.5 rounded-lg border border-amber-500/35 bg-surface-deep px-3 py-1.5 font-mono text-sm font-bold text-amber-300">
                <Timer className="h-4 w-4 text-amber-400" aria-hidden="true" />
                <span>
                  {secondsLeft > 0
                    ? `Tạm dừng để kiểm tra: ${secondsLeft} giây`
                    : "Đã hết 30 giây tạm dừng"}
                </span>
              </div>
            </div>

            <div className="mt-2.5 h-1.5 w-full overflow-hidden rounded-full bg-surface-deep/90">
              <div
                className={`h-full rounded-full transition-all duration-200 ${
                  secondsLeft === 0 ? "bg-emerald-400" : "bg-amber-400"
                }`}
                style={{ width: `${elapsedPct}%` }}
              />
            </div>

            <span className="sr-only" aria-live="polite" aria-atomic="true">
              {srMilestone}
            </span>
          </div>

          {pre.verification_questions.length > 0 && (
            <fieldset className="space-y-1.5 rounded-xl border border-border-subtle bg-surface-subtle p-3.5">
              <legend className="px-1 text-xs font-semibold text-ink">
                Tự kiểm tra nhanh trước khi quyết định (chọn từng mục):
              </legend>
              {pre.verification_questions.map((q, idx) => (
                <label
                  key={q}
                  className="flex min-h-[44px] cursor-pointer items-center gap-3 rounded-lg px-2 py-2 text-xs text-ink-secondary transition-colors hover:bg-surface-elevated"
                >
                  <input
                    type="checkbox"
                    checked={Boolean(checkedQuestions[idx])}
                    onChange={(e) =>
                      setCheckedQuestions((prev) => ({ ...prev, [idx]: e.target.checked }))
                    }
                    className="h-4 w-4 shrink-0 cursor-pointer accent-amber-500"
                  />
                  <span className="leading-snug">{q}</span>
                </label>
              ))}
            </fieldset>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <button
              type="button"
              onClick={() => setOutcome("aborted_safely")}
              className="inline-flex min-h-[44px] cursor-pointer items-center gap-2 rounded-xl bg-emerald-500 px-5 py-2.5 text-xs font-bold text-slate-950 shadow-md shadow-emerald-500/20 transition-colors hover:bg-emerald-400 sm:text-sm"
            >
              <PhoneOff className="h-4 w-4" aria-hidden="true" />
              <span>Dừng chuyển tiền và ngắt cuộc gọi ngay</span>
            </button>

            <button
              type="button"
              disabled={!canProceedOverride}
              onClick={() => setOutcome("overridden_at_risk")}
              className="tabular-num min-h-[44px] cursor-pointer rounded-xl border border-border-strong bg-surface-subtle px-4 py-2 text-xs font-medium text-ink-secondary transition-colors enabled:hover:border-rose-500/60 enabled:hover:text-rose-200 disabled:cursor-not-allowed disabled:opacity-45"
            >
              {secondsLeft > 0
                ? `Đang tạm dừng để kiểm tra (${secondsLeft} giây)`
                : "Tôi đã kiểm tra kỹ và tự chịu trách nhiệm"}
            </button>
          </div>
        </div>
      ) : (
        <p className="mt-3 text-xs text-emerald-300">
          Chưa kích hoạt tạm dừng để kiểm tra. Bạn vẫn nên đối chiếu kỹ tên người nhận trước khi xác
          nhận chuyển tiền.
        </p>
      )}
    </section>
  );
}
