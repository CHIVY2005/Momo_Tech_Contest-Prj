"use client";

import { Ban, CheckCircle2, Code2, Loader2, Play } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { analyzeSync } from "@/lib/api";
import { VERDICT_COPY } from "@/lib/copy";
import type { AnalysisReport } from "@/lib/types";

const PRESET_PAYLOADS = [
  {
    label: "Chuyển 15 triệu vào STK 999888777666 (giả mạo công an)",
    text: "Cán bộ điều tra yêu cầu chuyển gấp 15.000.000 VND vào STK 999888777666 để xác minh tài sản trong sạch",
    inActiveCall: true,
  },
  {
    label: "Mở đường dẫn đổi điểm napas-diemthuong-247.top",
    text: "Thông báo đổi điểm thưởng hết hạn tại https://napas-diemthuong-247.top",
    inActiveCall: false,
  },
  {
    label: "Quét mã QR hoàn tiền tới STK 777666555444",
    text: "Cửa hàng gửi mã quét nhận tiền hoàn đơn lỗi vào STK 777666555444",
    inActiveCall: false,
  },
];

export function ApiPlaygroundCard() {
  const [sampleText, setSampleText] = useState(PRESET_PAYLOADS[0]?.text ?? "");
  const [inActiveCall, setInActiveCall] = useState(true);
  const [isCalling, setIsCalling] = useState(false);
  const [evaluated, setEvaluated] = useState<{
    payload: string;
    inActiveCall: boolean;
    report: AnalysisReport;
  } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    return () => abortRef.current?.abort();
  }, []);

  function invalidatePending() {
    abortRef.current?.abort();
    abortRef.current = null;
    setIsCalling(false);
    setEvaluated(null);
    setErr(null);
  }

  async function runApiCheck() {
    const submittedText = sampleText.trim();
    const submittedCall = inActiveCall;
    if (!submittedText) return;

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setIsCalling(true);
    setErr(null);
    setEvaluated(null);

    const fd = new FormData();
    fd.append("mode", "wallet_transfer");
    fd.append("in_active_call", String(submittedCall));
    fd.append("text", submittedText);
    try {
      const report = await analyzeSync(fd, controller.signal);
      if (abortRef.current === controller) {
        setEvaluated({ payload: submittedText, inActiveCall: submittedCall, report });
      }
    } catch (e) {
      if ((e as Error).name !== "AbortError" && abortRef.current === controller) {
        setErr(e instanceof Error ? e.message : "Không thể kiểm tra giao dịch mẫu lúc này.");
      }
    } finally {
      if (abortRef.current === controller) {
        setIsCalling(false);
      }
    }
  }

  const result = evaluated?.report ?? null;

  return (
    <section
      aria-labelledby="api-playground-heading"
      className="rounded-2xl border border-sky-500/35 bg-surface/95 p-4 shadow-lg sm:p-5"
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-start gap-2">
          <Code2 className="mt-0.5 h-5 w-5 shrink-0 text-sky-400" aria-hidden="true" />
          <div>
            <h2 id="api-playground-heading" className="text-sm font-bold text-ink">
              Kiểm thử hiệu lực quy tắc chặn
            </h2>
            <p className="text-xs text-ink-muted">
              Gửi thử một giao dịch mẫu sau khi bật chặn một chạm ở trên để thấy hệ thống tự động
              ngăn chặn ngay lập tức.
            </p>
          </div>
        </div>
      </div>

      <div className="mb-3 flex flex-wrap gap-2">
        {PRESET_PAYLOADS.map((p) => (
          <button
            key={p.label}
            type="button"
            onClick={() => {
              invalidatePending();
              setSampleText(p.text);
              setInActiveCall(p.inActiveCall);
            }}
            className="min-h-[34px] cursor-pointer rounded-lg border border-border-strong bg-surface-subtle px-2.5 py-1.5 text-left text-[11px] font-medium text-ink-secondary hover:border-sky-400 hover:text-ink"
          >
            {p.label}
          </button>
        ))}
      </div>

      <div className="space-y-3">
        <div>
          <label
            htmlFor="playground-payload"
            className="mb-1 block text-xs font-semibold text-ink-secondary"
          >
            Nội dung giao dịch mẫu cần kiểm tra:
          </label>
          <textarea
            id="playground-payload"
            rows={2}
            value={sampleText}
            onChange={(e) => {
              invalidatePending();
              setSampleText(e.target.value);
            }}
            className="w-full rounded-xl border border-border-strong bg-surface-subtle px-3 py-2 text-xs text-ink"
          />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="inline-flex min-h-[38px] cursor-pointer items-center gap-2 text-xs text-ink-secondary">
            <input
              type="checkbox"
              checked={inActiveCall}
              onChange={(e) => {
                invalidatePending();
                setInActiveCall(e.target.checked);
              }}
              className="h-4 w-4 cursor-pointer accent-amber-500"
            />
            <span>Giả lập người dùng đang nghe điện thoại khi chuyển tiền</span>
          </label>

          <button
            type="button"
            disabled={isCalling || !sampleText.trim()}
            onClick={() => void runApiCheck()}
            className="inline-flex min-h-[40px] cursor-pointer items-center gap-2 rounded-xl bg-sky-500 px-4 py-2 text-xs font-bold text-slate-950 hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isCalling ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <Play className="h-4 w-4" aria-hidden="true" />
            )}
            <span>Kiểm tra giao dịch mẫu</span>
          </button>
        </div>

        {err && (
          <p
            role="alert"
            className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-2.5 text-xs text-rose-200"
          >
            {err}
          </p>
        )}

        {result && evaluated && (
          <div className="space-y-2.5 rounded-xl border border-border-subtle bg-surface-deep p-3.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-bold">
                {result.active_block_rule_hit ? (
                  <span className="tabular-num inline-flex items-center gap-1.5 rounded bg-rose-500/20 px-2.5 py-1 text-rose-200">
                    <Ban className="h-4 w-4" aria-hidden="true" />
                    <span>Đã bị chặn bởi quy tắc hệ thống ({result.risk_score}/100)</span>
                  </span>
                ) : (
                  <span className="tabular-num inline-flex items-center gap-1.5 rounded bg-amber-500/20 px-2.5 py-1 text-amber-200">
                    <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                    <span>
                      {VERDICT_COPY[result.verdict].shortLabel} ({result.risk_score}/100) · Tạm
                      dừng để kiểm tra: {result.actions.pre_transfer.cooling_off_seconds} giây
                    </span>
                  </span>
                )}
              </div>
            </div>

            <p className="text-xs leading-relaxed text-ink-secondary">{result.summary_vi}</p>

            <details className="rounded-lg border border-border-subtle/80 bg-surface-subtle/60 px-3 py-2 text-[11px]">
              <summary className="cursor-pointer font-medium text-ink-secondary hover:text-ink">
                Thông tin kỹ thuật API (POST /api/v1/analyze)
              </summary>
              <pre className="mt-2 max-h-48 overflow-auto rounded-lg bg-slate-950 p-3 font-mono text-[11px] leading-relaxed text-sky-200">
                {JSON.stringify(
                  {
                    evaluated_payload: evaluated.payload,
                    in_active_call: evaluated.inActiveCall,
                    case_id: result.case_id,
                    risk_score: result.risk_score,
                    verdict: result.verdict,
                    active_block_rule_hit: result.active_block_rule_hit,
                    pre_transfer: result.actions.pre_transfer,
                  },
                  null,
                  2,
                )}
              </pre>
            </details>
          </div>
        )}
      </div>
    </section>
  );
}
