"use client";

import {
  AlertOctagon,
  AlertTriangle,
  Cpu,
  FileWarning,
  ShieldAlert,
  ShieldCheck,
  Users,
  Volume2,
} from "lucide-react";

import type { AnalysisReport, VerdictLevel } from "@/lib/types";

interface VerdictDashboardProps {
  report: AnalysisReport;
}

const VERDICT_META: Record<
  VerdictLevel,
  {
    label: string;
    border: string;
    badgeBg: string;
    barColor: string;
    Icon: typeof ShieldCheck;
  }
> = {
  SAFE: {
    label: "ÍT RỦI RO — CHƯA PHÁT HIỆN MÃ ĐỘC / LỪA ĐẢO",
    border: "border-emerald-500/40",
    badgeBg: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
    barColor: "bg-emerald-500",
    Icon: ShieldCheck,
  },
  SUSPICIOUS: {
    label: "NGHI VẤN — CẦN KIỂM CHỨNG ĐỘC LẬP",
    border: "border-amber-500/50",
    badgeBg: "bg-amber-500/15 text-amber-300 border-amber-500/40",
    barColor: "bg-amber-500",
    Icon: AlertTriangle,
  },
  HIGH_RISK: {
    label: "RỦI RO CAO — TẠM DỪNG GIAO DỊCH NGAY",
    border: "border-orange-500/50",
    badgeBg: "bg-orange-500/15 text-orange-300 border-orange-500/40",
    barColor: "bg-orange-500",
    Icon: ShieldAlert,
  },
  CRITICAL_SCAM: {
    label: "CẢNH BÁO ĐỎ — DẤU HIỆU LỪA ĐẢO / GIẢ MẠO RÕ RỆT",
    border: "border-rose-500/60",
    badgeBg: "bg-rose-500/15 text-rose-200 border-rose-500/50",
    barColor: "bg-rose-500",
    Icon: AlertOctagon,
  },
};

export function VerdictDashboard({ report }: VerdictDashboardProps) {
  const meta = VERDICT_META[report.verdict];
  const VerdictIcon = meta.Icon;
  const showMerchantHonestyBanner =
    report.receipt_verification_status === "UNVERIFIED_SCREENSHOT" ||
    Boolean(report.actions.merchant_balance_warning);

  return (
    <section
      aria-labelledby="verdict-heading"
      className={`rounded-2xl border ${meta.border} bg-[#111827]/95 p-5 shadow-xl`}
    >
      {showMerchantHonestyBanner && (
        <div
          role="alert"
          className="mb-4 rounded-xl border-2 border-amber-400/80 bg-amber-500/15 p-3.5 text-amber-100"
        >
          <div className="flex items-start gap-2.5">
            <FileWarning className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden="true" />
            <div>
              <p className="text-xs font-bold tracking-wide text-amber-200 uppercase">
                CHƯA ĐỐI SOÁT SỐ DƯ — BẮT BUỘC KIỂM TRA APP NGÂN HÀNG / LOA THÔNG BÁO
              </p>
              <p className="mt-1 text-xs leading-relaxed text-amber-100">
                {report.actions.merchant_balance_warning ??
                  "Ảnh chụp màn hình biên lai KHÔNG phải bằng chứng tiền đã vào tài khoản. Tuyệt đối không giao hàng trước khi kiểm tra biến động số dư thực tế hoặc Loa thông báo nhận tiền."}
              </p>
            </div>
          </div>
        </div>
      )}

      {report.active_block_rule_hit && (
        <div
          role="alert"
          className="mb-4 rounded-xl border border-rose-500/70 bg-rose-500/20 px-3.5 py-2.5 text-xs font-semibold text-rose-100"
        >
          TRÙNG KHỚP DANH SÁCH CHẶN KHẨN CẤP (/radar): Tài khoản/tên miền trong giao dịch vừa bị
          Trung tâm Fraud Ops khóa trên toàn hệ sinh thái.
        </div>
      )}

      <div className="flex flex-col justify-between gap-4 md:flex-row md:items-center">
        <div>
          <div className="inline-flex items-center gap-2 rounded-lg border px-3 py-1 text-xs font-bold">
            <span className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 border ${meta.badgeBg}`}>
              <VerdictIcon className="h-4 w-4" aria-hidden="true" />
              <span>{meta.label}</span>
            </span>
          </div>
          <h2 id="verdict-heading" className="mt-3 text-base font-semibold leading-relaxed text-slate-50">
            {report.summary_vi}
          </h2>
        </div>

        <div className="flex shrink-0 items-center gap-4 rounded-xl border border-slate-800 bg-[#0b1120] px-4 py-3">
          <div>
            <p className="text-[11px] font-medium text-slate-400">Điểm Rủi ro Hiệu chuẩn</p>
            <div className="flex items-baseline gap-1">
              <span className="font-[family-name:var(--font-mono)] text-3xl font-bold text-slate-50">
                {report.risk_score}
              </span>
              <span className="font-[family-name:var(--font-mono)] text-xs text-slate-400">/100</span>
            </div>
          </div>
          <div className="h-10 w-px bg-slate-800" aria-hidden="true" />
          <div>
            <p className="text-[11px] font-medium text-slate-400">Độ tin cậy</p>
            <p className="font-[family-name:var(--font-mono)] text-lg font-semibold text-slate-200">
              {Math.round(report.confidence * 100)}%
            </p>
          </div>
        </div>
      </div>

      <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full transition-all duration-300 ${meta.barColor}`}
          style={{ width: `${Math.max(3, report.risk_score)}%` }}
        />
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
        <span className="rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1 font-[family-name:var(--font-mono)] text-slate-300">
          Hồ sơ: {report.case_id}
        </span>

        {report.classifier?.available && (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-sky-200">
            <Cpu className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
            <span>
              E5 ONNX: {report.classifier.predicted_label} ({report.classifier.latency_ms}ms)
            </span>
          </span>
        )}

        {!report.degraded_mode && report.llm_model && (
          <span className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 font-[family-name:var(--font-mono)] text-emerald-200">
            LLM: {report.llm_model}
            {typeof report.llm_latency_ms === "number" ? ` (${report.llm_latency_ms}ms)` : ""}
          </span>
        )}

        {report.degraded_mode && (
          <span className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-amber-200">
            Chế độ dự phòng cục bộ Tầng 1 (Không phụ thuộc Cloud LLM)
          </span>
        )}

        {report.community_hits > 0 && (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 text-rose-200">
            <Users className="h-3.5 w-3.5 text-rose-400" aria-hidden="true" />
            <span>Cộng đồng cảnh báo: {report.community_hits} ca trùng IOC</span>
          </span>
        )}
      </div>

      {(report.matched_playbooks.length > 0 || report.manipulation_tactics.length > 0) && (
        <div className="mt-4 grid grid-cols-1 gap-3 border-t border-slate-800/80 pt-4 sm:grid-cols-2">
          <div>
            <p className="mb-1.5 text-xs font-semibold text-slate-300">
              Kịch bản Lừa đảo Việt Nam Khớp Mẫu
            </p>
            {report.matched_playbooks.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {report.matched_playbooks.map((pb) => (
                  <span
                    key={pb}
                    className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 text-xs font-medium text-rose-200"
                  >
                    {pb}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-400">Không khớp mẫu lừa đảo cố định.</p>
            )}
          </div>

          <div>
            <p className="mb-1.5 text-xs font-semibold text-slate-300">
              Đòn bẩy Thao túng Tâm lý Phát hiện
            </p>
            {report.manipulation_tactics.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {report.manipulation_tactics.map((tac) => (
                  <span
                    key={tac}
                    className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-xs text-amber-200"
                  >
                    {tac}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-400">Chưa ghi nhận kỹ thuật thao túng tâm lý.</p>
            )}
          </div>
        </div>
      )}

      {report.transcript && (
        <div className="mt-4 rounded-xl border border-slate-800 bg-[#0b1120] p-3.5">
          <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-sky-300">
            <Volume2 className="h-4 w-4" aria-hidden="true" />
            <span>Bản gỡ băng lời thoại cuộc gọi (Audio Transcript)</span>
          </div>
          <p className="text-xs leading-relaxed text-slate-200 italic">&ldquo;{report.transcript}&rdquo;</p>
        </div>
      )}
    </section>
  );
}
