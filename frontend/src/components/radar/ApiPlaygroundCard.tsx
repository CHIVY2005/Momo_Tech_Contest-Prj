"use client";

import { Ban, CheckCircle2, Code2, Loader2, Play } from "lucide-react";
import { useState } from "react";

import { analyzeSync } from "@/lib/api";
import type { AnalysisReport } from "@/lib/types";

const PRESET_PAYLOADS = [
  {
    label: "Ví chuyển 15tr vào STK 999888777666 (Mạo danh Công an)",
    text: "Cán bộ điều tra yêu cầu chuyển gấp 15.000.000 VND vào STK 999888777666 để xác minh tài sản trong sạch",
    inActiveCall: true,
  },
  {
    label: "Ví mở link SMS đổi điểm napas-diemthuong-247.top",
    text: "Thông báo đổi điểm thưởng hết hạn tại https://napas-diemthuong-247.top",
    inActiveCall: false,
  },
  {
    label: "Quét QR hoàn tiền tới STK 777666555444",
    text: "Shop gửi mã quét nhận tiền hoàn đơn lỗi vào STK 777666555444",
    inActiveCall: false,
  },
];

export function ApiPlaygroundCard() {
  const [sampleText, setSampleText] = useState(PRESET_PAYLOADS[0]?.text ?? "");
  const [inActiveCall, setInActiveCall] = useState(true);
  const [isCalling, setIsCalling] = useState(false);
  const [result, setResult] = useState<AnalysisReport | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function runApiCheck() {
    setIsCalling(true);
    setErr(null);
    const fd = new FormData();
    fd.append("mode", "wallet_transfer");
    fd.append("in_active_call", String(inActiveCall));
    fd.append("text", sampleText);
    try {
      const report = await analyzeSync(fd);
      setResult(report);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Lỗi gọi API kiểm định.");
    } finally {
      setIsCalling(false);
    }
  }

  return (
    <section
      aria-labelledby="api-playground-heading"
      className="rounded-2xl border border-sky-500/30 bg-[#111827]/95 p-5 shadow-lg"
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Code2 className="h-5 w-5 text-sky-400" aria-hidden="true" />
          <div>
            <h2 id="api-playground-heading" className="text-sm font-bold text-slate-50">
              Fintech Pre-Transfer REST API Playground (`POST /api/v1/analyze`)
            </h2>
            <p className="text-xs text-slate-400">
              Kiểm chứng ngay lập tức: Khi Fraud Ops bấm Khóa 1-Click ở trên, lệnh chuyển tiền của Ví bị chặn cứng (&ge;96 điểm) trong tích tắc!
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
              setSampleText(p.text);
              setInActiveCall(p.inActiveCall);
            }}
            className="cursor-pointer rounded-lg border border-slate-700 bg-[#0b1120] px-2.5 py-1.5 text-[11px] font-medium text-slate-200 hover:border-sky-400"
          >
            {p.label}
          </button>
        ))}
      </div>

      <div className="space-y-3">
        <div>
          <label htmlFor="playground-payload" className="mb-1 block text-xs font-semibold text-slate-300">
            Payload giao dịch gửi từ Ứng dụng Ví Điện Tử:
          </label>
          <textarea
            id="playground-payload"
            rows={2}
            value={sampleText}
            onChange={(e) => setSampleText(e.target.value)}
            className="w-full rounded-xl border border-slate-700 bg-[#0b1120] px-3 py-2 font-[family-name:var(--font-mono)] text-xs text-slate-100"
          />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-slate-200">
            <input
              type="checkbox"
              checked={inActiveCall}
              onChange={(e) => setInActiveCall(e.target.checked)}
              className="h-4 w-4 cursor-pointer accent-amber-500"
            />
            <span>`in_active_call = true` (Đang trong cuộc gọi thoại)</span>
          </label>

          <button
            type="button"
            disabled={isCalling || !sampleText.trim()}
            onClick={() => void runApiCheck()}
            className="inline-flex cursor-pointer items-center gap-2 rounded-xl bg-sky-500 px-4 py-2 text-xs font-bold text-slate-950 hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isCalling ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <Play className="h-4 w-4" aria-hidden="true" />
            )}
            <span>Gửi Yêu cầu API Kiểm định Ví</span>
          </button>
        </div>

        {err && (
          <p role="alert" className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-2.5 text-xs text-rose-200">
            {err}
          </p>
        )}

        {result && (
          <div className="space-y-2.5 rounded-xl border border-slate-800 bg-[#070b14] p-3.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-bold">
                {result.active_block_rule_hit ? (
                  <span className="inline-flex items-center gap-1.5 rounded bg-rose-500/20 px-2.5 py-1 text-rose-200">
                    <Ban className="h-4 w-4" aria-hidden="true" />
                    <span>BỊ CHẶN BỞI FRAUD OPS RULE ({result.risk_score}/100)</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 rounded bg-amber-500/20 px-2.5 py-1 text-amber-200">
                    <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                    <span>
                      {result.verdict} ({result.risk_score}/100) · Khóa làm nguội:{" "}
                      {result.actions.pre_transfer.cooling_off_seconds}s
                    </span>
                  </span>
                )}
              </div>
              <span className="font-[family-name:var(--font-mono)] text-[11px] text-slate-400">
                case_id: {result.case_id}
              </span>
            </div>

            <pre className="max-h-48 overflow-auto rounded-lg bg-slate-950 p-3 font-[family-name:var(--font-mono)] text-[11px] leading-relaxed text-sky-200">
              {JSON.stringify(
                {
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
          </div>
        )}
      </div>
    </section>
  );
}
