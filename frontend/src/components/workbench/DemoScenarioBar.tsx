"use client";

import { FileAudio, Image as ImageIcon, QrCode, ShieldAlert, Sparkles } from "lucide-react";

import type { DemoScenario } from "@/lib/types";

interface DemoScenarioBarProps {
  demos: DemoScenario[];
  activeDemoId: string | null;
  isAnalyzing: boolean;
  onSelectDemo: (demo: DemoScenario) => void;
}

const MODE_LABELS: Record<DemoScenario["mode"], string> = {
  personal: "Cá nhân",
  merchant: "Chủ shop",
  wallet_transfer: "Ví 30s",
};

function pickScenarioIcon(demo: DemoScenario) {
  if (demo.audio_filename) {
    return FileAudio;
  }
  if (demo.demo_id.includes("vietqr")) {
    return QrCode;
  }
  if (demo.image_filename) {
    return ImageIcon;
  }
  if (demo.expected_verdict === "SAFE") {
    return Sparkles;
  }
  return ShieldAlert;
}

export function DemoScenarioBar({
  demos,
  activeDemoId,
  isAnalyzing,
  onSelectDemo,
}: DemoScenarioBarProps) {
  if (demos.length === 0) {
    return null;
  }

  return (
    <section
      aria-labelledby="demo-scenarios-heading"
      className="rounded-2xl border border-slate-800 bg-[#111827]/95 p-4 shadow-lg"
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 id="demo-scenarios-heading" className="text-sm font-semibold text-slate-100">
            5 Kịch bản Thực chiến 1-Click (Dành cho Hội đồng Giám khảo)
          </h2>
          <p className="text-xs text-slate-400">
            Nhấn chọn một tình huống để nạp dữ liệu mẫu tổng hợp và chạy luồng điều tra thời gian thực.
          </p>
        </div>
        <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 font-[family-name:var(--font-mono)] text-[11px] font-medium text-amber-300">
          Zero-Login · SSE Live
        </span>
      </div>

      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-5">
        {demos.map((demo) => {
          const Icon = pickScenarioIcon(demo);
          const isSelected = activeDemoId === demo.demo_id;
          const isSafeControl = demo.expected_verdict === "SAFE";

          return (
            <button
              key={demo.demo_id}
              type="button"
              disabled={isAnalyzing}
              onClick={() => onSelectDemo(demo)}
              aria-pressed={isSelected}
              className={`group flex cursor-pointer flex-col justify-between rounded-xl border p-3 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${
                isSelected
                  ? "border-amber-400 bg-amber-500/15"
                  : "border-slate-800 bg-[#0b1120] hover:border-slate-600 hover:bg-slate-900"
              }`}
            >
              <div>
                <div className="mb-2 flex items-center justify-between gap-1.5">
                  <span
                    className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold ${
                      isSafeControl
                        ? "border border-emerald-500/30 bg-emerald-500/15 text-emerald-300"
                        : "border border-rose-500/30 bg-rose-500/15 text-rose-300"
                    }`}
                  >
                    <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{demo.category_badge}</span>
                  </span>
                  <span className="rounded bg-slate-800 px-1.5 py-0.5 font-[family-name:var(--font-mono)] text-[10px] text-slate-300">
                    {MODE_LABELS[demo.mode]}
                  </span>
                </div>
                <p className="text-xs font-semibold leading-snug text-slate-100 group-hover:text-amber-200">
                  {demo.title_vi}
                </p>
              </div>
              <p className="mt-2 line-clamp-2 text-[11px] leading-relaxed text-slate-400">
                {demo.subtitle_vi}
              </p>
            </button>
          );
        })}
      </div>
    </section>
  );
}
