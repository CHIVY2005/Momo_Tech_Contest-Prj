"use client";

import {
  ArrowRight,
  Check,
  FileAudio,
  Image as ImageIcon,
  QrCode,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

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
    return ShieldCheck;
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
      className="rounded-2xl border border-border-subtle bg-surface/95 p-4 sm:p-5"
    >
      <div className="mb-3 flex flex-col gap-0.5 sm:flex-row sm:items-baseline sm:justify-between">
        <h2 id="demo-scenarios-heading" className="text-sm font-bold text-ink">
          Thử nghiệm với tình huống mẫu
        </h2>
        <p className="text-xs text-ink-muted">
          Chọn một tình huống để xem cách hệ thống phân tích và cảnh báo.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
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
              className={`group flex h-full cursor-pointer flex-col justify-between rounded-xl border p-3.5 text-left transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-400 disabled:cursor-not-allowed disabled:opacity-60 ${
                isSelected
                  ? "border-amber-400 bg-amber-500/12"
                  : "border-border-subtle bg-surface-subtle hover:border-amber-400/60 hover:bg-surface-elevated"
              }`}
            >
              <div>
                <div className="mb-2 flex items-center gap-1.5">
                  <span
                    className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium ${
                      isSafeControl
                        ? "border border-emerald-500/35 bg-emerald-500/12 text-emerald-300"
                        : "border border-border-strong bg-surface text-ink-secondary"
                    }`}
                  >
                    <Icon
                      className={`h-3 w-3 shrink-0 ${
                        isSafeControl ? "text-emerald-400" : "text-amber-400"
                      }`}
                      aria-hidden="true"
                    />
                    <span>{demo.category_badge}</span>
                  </span>
                </div>

                <p className="text-xs font-semibold leading-snug text-ink group-hover:text-amber-200">
                  {demo.title_vi}
                </p>
                <p className="mt-1.5 text-[11px] leading-relaxed text-ink-muted">
                  {demo.subtitle_vi}
                </p>
              </div>

              <div className="mt-3 flex items-center justify-between border-t border-border-subtle/70 pt-2 text-[11px] font-medium">
                <span
                  className={
                    isSelected
                      ? "text-amber-300"
                      : "text-sky-300 transition-colors group-hover:text-amber-200"
                  }
                >
                  {isSelected ? "Đang chọn" : "Thử tình huống"}
                </span>
                {isSelected ? (
                  <Check className="h-3.5 w-3.5 text-amber-300" aria-hidden="true" />
                ) : (
                  <ArrowRight
                    className="h-3.5 w-3.5 text-sky-300 transition-transform group-hover:translate-x-0.5 group-hover:text-amber-200"
                    aria-hidden="true"
                  />
                )}
              </div>
            </button>
          );
        })}
      </div>
    </section>
  );
}
