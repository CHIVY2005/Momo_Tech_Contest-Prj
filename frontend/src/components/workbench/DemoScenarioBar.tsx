"use client";

import { FileAudio, Image as ImageIcon, QrCode, ShieldAlert, Sparkles } from "lucide-react";

import { MODE_COPY } from "@/lib/copy";
import type { DemoScenario } from "@/lib/types";

interface DemoScenarioBarProps {
  demos: DemoScenario[];
  activeDemoId: string | null;
  isAnalyzing: boolean;
  onSelectDemo: (demo: DemoScenario) => void;
}

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
      className="rounded-2xl border border-border-subtle bg-surface/95 p-3.5 shadow-lg sm:p-4"
    >
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5">
          <h2 id="demo-scenarios-heading" className="text-xs font-bold text-ink sm:text-sm">
            5 tình huống mẫu để kiểm tra một chạm
          </h2>
          <p className="hidden text-[11px] text-ink-muted xl:block">
            Chọn một tình huống mẫu để xem cách hệ thống phân tích và cảnh báo.
          </p>
        </div>
        <span className="tabular-num rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 text-[11px] font-medium text-amber-300">
          Không cần đăng nhập · Dữ liệu mẫu
        </span>
      </div>

      <div className="flex snap-x snap-mandatory gap-2 overflow-x-auto pb-1 sm:grid sm:grid-cols-2 sm:overflow-visible sm:pb-0 lg:grid-cols-5">
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
              className={`group flex w-[236px] shrink-0 snap-start cursor-pointer flex-col justify-between rounded-xl border p-2.5 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto sm:min-w-0 ${
                isSelected
                  ? "border-amber-400 bg-amber-500/15 shadow-sm shadow-amber-500/10"
                  : "border-border-subtle bg-surface-subtle hover:border-border-strong hover:bg-surface-elevated"
              }`}
            >
              <div>
                <div className="mb-1 flex items-center justify-between gap-1.5">
                  <span
                    className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                      isSafeControl
                        ? "border border-emerald-500/35 bg-emerald-500/15 text-emerald-300"
                        : "border border-rose-500/35 bg-rose-500/15 text-rose-200"
                    }`}
                  >
                    <Icon className="h-3 w-3 shrink-0" aria-hidden="true" />
                    <span>{demo.category_badge}</span>
                  </span>
                  <span className="shrink-0 whitespace-nowrap rounded bg-surface-elevated px-1.5 py-0.5 text-[10px] text-ink-secondary">
                    {MODE_COPY[demo.mode].shortLabel}
                  </span>
                </div>
                <p className="line-clamp-2 text-xs font-semibold leading-snug text-ink group-hover:text-amber-200">
                  {demo.title_vi}
                </p>
              </div>
              <p className="mt-1 line-clamp-1 text-[11px] leading-snug text-ink-muted">
                {demo.subtitle_vi}
              </p>
            </button>
          );
        })}
      </div>
    </section>
  );
}
