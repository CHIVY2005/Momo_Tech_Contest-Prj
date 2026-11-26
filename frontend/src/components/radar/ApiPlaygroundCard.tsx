"use client";

import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  FlaskConical,
  Info,
  Loader2,
  Play,
  RotateCcw,
  X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { analyzeSync } from "@/lib/api";
import { IOC_TYPE_COPY, VERDICT_COPY } from "@/lib/copy";
import { formatMaskedIoc, formatRemainingTtl } from "@/lib/radarLayout";
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

interface ApiPlaygroundCardProps {
  open: boolean;
  activeRuleCount: number;
  showDemoControls: boolean;
  onClose: () => void;
  onRequestResetDemo: () => void;
}

export function ApiPlaygroundCard({
  open,
  activeRuleCount,
  showDemoControls,
  onClose,
  onRequestResetDemo,
}: ApiPlaygroundCardProps) {
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

  useEffect(() => {
    if (!open) return;
    function onKey(ev: KeyboardEvent) {
      if (ev.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  function invalidatePending() {
    abortRef.current?.abort();
    abortRef.current = null;
    setIsCalling(false);
    setEvaluated(null);
    setErr(null);
  }

  async function runSimulation() {
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
    fd.append("is_simulation", "true");
    fd.append("text", submittedText);
    try {
      const report = await analyzeSync(fd, controller.signal);
      if (abortRef.current === controller) {
        setEvaluated({ payload: submittedText, inActiveCall: submittedCall, report });
      }
    } catch (e) {
      if ((e as Error).name !== "AbortError" && abortRef.current === controller) {
        setErr(e instanceof Error ? e.message : "Không thể chạy mô phỏng lúc này.");
      }
    } finally {
      if (abortRef.current === controller) {
        setIsCalling(false);
      }
    }
  }

  const result = evaluated?.report ?? null;
  const matchedRules = result?.matched_block_rules ?? [];

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
        aria-labelledby="simulation-drawer-title"
        className="relative z-10 flex h-full w-full max-w-xl flex-col border-l border-border-strong bg-surface shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3 border-b border-border-subtle px-5 py-4">
          <div className="flex items-start gap-2.5">
            <FlaskConical className="mt-0.5 h-5 w-5 shrink-0 text-sky-400" aria-hidden="true" />
            <div>
              <h2 id="simulation-drawer-title" className="text-base font-bold text-ink">
                Mô phỏng giao dịch
              </h2>
              <p className="mt-0.5 text-xs text-ink-muted">
                Kiểm tra phản hồi đánh giá rủi ro và mức độ khớp quy tắc chặn mà không ghi vào thống
                kê thực tế.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Đóng khung mô phỏng giao dịch"
            className="inline-flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-border-strong bg-surface-subtle text-ink-secondary hover:text-ink"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4 text-xs">
          {/* Preset scenarios */}
          <div>
            <p className="mb-2 text-[11px] font-semibold text-ink-secondary">
              Tình huống mô phỏng mẫu
            </p>
            <div className="flex flex-wrap gap-2">
              {PRESET_PAYLOADS.map((p) => (
                <button
                  key={p.label}
                  type="button"
                  onClick={() => {
                    invalidatePending();
                    setSampleText(p.text);
                    setInActiveCall(p.inActiveCall);
                  }}
                  className="min-h-[34px] cursor-pointer rounded-lg border border-border-strong bg-surface-subtle px-2.5 py-1.5 text-left text-[11px] font-medium text-ink-secondary transition-colors hover:border-sky-400 hover:text-ink"
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            <div>
              <label
                htmlFor="simulation-payload"
                className="mb-1 block text-xs font-semibold text-ink-secondary"
              >
                Nội dung giao dịch mô phỏng
              </label>
              <textarea
                id="simulation-payload"
                rows={3}
                value={sampleText}
                onChange={(e) => {
                  invalidatePending();
                  setSampleText(e.target.value);
                }}
                className="w-full rounded-xl border border-border-strong bg-surface-subtle px-3 py-2 text-xs text-ink focus:border-sky-400"
              />
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <label className="inline-flex min-h-[36px] cursor-pointer items-center gap-2 text-xs text-ink-secondary">
                <input
                  type="checkbox"
                  checked={inActiveCall}
                  onChange={(e) => {
                    invalidatePending();
                    setInActiveCall(e.target.checked);
                  }}
                  className="h-4 w-4 cursor-pointer accent-amber-500"
                />
                <span>Giả lập đang nghe điện thoại khi chuyển tiền</span>
              </label>

              <button
                type="button"
                disabled={isCalling || !sampleText.trim()}
                onClick={() => void runSimulation()}
                className="inline-flex min-h-[38px] cursor-pointer items-center gap-2 rounded-xl bg-sky-500 px-4 py-2 text-xs font-bold text-slate-950 transition-colors hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isCalling ? (
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                ) : (
                  <Play className="h-4 w-4" aria-hidden="true" />
                )}
                <span>Chạy mô phỏng</span>
              </button>
            </div>
          </div>

          {err && (
            <p
              role="alert"
              className="rounded-xl border border-rose-500/40 bg-rose-500/15 p-3 text-xs text-rose-100"
            >
              {err}
            </p>
          )}

          {result && evaluated && (
            <div className="space-y-3 rounded-xl border border-border-subtle bg-surface-deep p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] font-semibold text-ink-muted">
                  Kết quả đánh giá mô phỏng
                </span>
                <span className="rounded border border-sky-500/35 bg-sky-500/10 px-2 py-0.5 text-[10px] font-semibold text-sky-300">
                  Không lưu vào thống kê thực tế
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2.5">
                <div className="rounded-lg border border-border-subtle bg-surface-subtle p-2.5">
                  <p className="text-[11px] text-ink-muted">Mức rủi ro</p>
                  <p className="tabular-num mt-0.5 font-mono text-lg font-bold text-rose-300">
                    {result.risk_score}/100
                  </p>
                </div>
                <div className="rounded-lg border border-border-subtle bg-surface-subtle p-2.5">
                  <p className="text-[11px] text-ink-muted">Kết quả đánh giá</p>
                  <p className="mt-0.5 text-xs font-bold text-ink">
                    {VERDICT_COPY[result.verdict].shortLabel}
                  </p>
                </div>
              </div>

              {/* Matched rules */}
              <div className="rounded-lg border border-border-subtle bg-surface-subtle p-3">
                <p className="mb-1.5 text-[11px] font-semibold text-ink-secondary">
                  Đối chiếu quy tắc chặn
                </p>
                {result.active_block_rule_hit ? (
                  <div className="space-y-1.5">
                    <div className="inline-flex items-center gap-1.5 rounded bg-rose-500/20 px-2 py-1 text-[11px] font-bold text-rose-200">
                      <Ban className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>Khớp quy tắc chặn đang áp dụng</span>
                    </div>
                    {matchedRules.length > 0 && (
                      <ul className="space-y-1 pt-1">
                        {matchedRules.map((mr) => (
                          <li
                            key={mr.rule_id}
                            className="flex flex-wrap items-center justify-between gap-1 rounded border border-rose-500/30 bg-rose-500/8 px-2.5 py-1.5 text-[11px]"
                          >
                            <span>
                              <strong className="font-mono text-rose-200">
                                {formatMaskedIoc(mr.masked_value, mr.rule_id)}
                              </strong>{" "}
                              <span className="text-ink-muted">
                                ({IOC_TYPE_COPY[mr.ioc_type]})
                              </span>
                              {" — "}
                              <span className="text-ink-secondary">{mr.reason}</span>
                            </span>
                            <span className="tabular-num font-mono text-[10px] text-amber-300">
                              {formatRemainingTtl(mr.expires_at)}
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ) : (
                  <div className="inline-flex items-center gap-1.5 rounded bg-amber-500/15 px-2 py-1 text-[11px] font-semibold text-amber-200">
                    <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>
                      Chưa khớp quy tắc chặn nào (đánh giá theo AI &amp; quy tắc rủi ro · nhắc tạm
                      dừng {result.actions.pre_transfer.cooling_off_seconds} giây)
                    </span>
                  </div>
                )}
              </div>

              <p className="text-xs leading-relaxed text-ink-secondary">{result.summary_vi}</p>
            </div>
          )}

          {/* Honest capability disclaimer */}
          <div className="flex items-start gap-2 rounded-xl border border-border-subtle bg-surface-subtle p-3 text-[11px] text-ink-muted">
            <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" aria-hidden="true" />
            <p className="leading-relaxed">
              Kết quả mô phỏng thể hiện đánh giá và khuyến nghị cảnh báo của VeriShield AI. Hệ thống
              không tự ý khóa tài khoản hay can thiệp trực tiếp vào lệnh chuyển tiền ngân hàng nếu
              chưa có tích hợp thực tế từ tổ chức thanh toán.
            </p>
          </div>

          {/* Demo data management isolated strictly inside Demo/Simulation drawer */}
          {showDemoControls && (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/6 p-3.5">
              <div className="flex items-start gap-2">
                <AlertTriangle
                  className="mt-0.5 h-4 w-4 shrink-0 text-amber-400"
                  aria-hidden="true"
                />
                <div className="flex-1">
                  <h3 className="text-xs font-bold text-amber-200">Khu vực dữ liệu mẫu</h3>
                  <p className="mt-0.5 text-[11px] leading-relaxed text-ink-secondary">
                    Thu hồi toàn bộ quy tắc chặn tạm thời đang bật để khôi phục trạng thái mẫu ban
                    đầu (yêu cầu xác thực quản trị viên).
                  </p>
                  <button
                    type="button"
                    onClick={onRequestResetDemo}
                    className="mt-2.5 inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-lg border border-amber-500/45 bg-surface px-3 py-1.5 text-[11px] font-semibold text-amber-200 transition-colors hover:bg-amber-500/15"
                  >
                    <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Khôi phục dữ liệu mẫu ({activeRuleCount} quy tắc đang bật)</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </aside>
    </div>
  );
}
