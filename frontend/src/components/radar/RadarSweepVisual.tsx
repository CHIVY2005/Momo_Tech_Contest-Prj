"use client";

import { useId } from "react";

import { useViewportMotion } from "@/components/motion/useViewportMotion";
import type { RadarMotionScope } from "@/lib/motion/cyberMotion";

interface RadarSweepVisualProps {
  scope: RadarMotionScope;
  isRefreshing?: boolean;
}

/**
 * Lazy-loaded Radar Sweep visual for `/radar`.
 * Differentiates live telemetry (`live_cyan`) from demo/simulated scope (`demo_slate`) so
 * simulated sample data is never misread as an active real-world emergency alert.
 */
export function RadarSweepVisual({ scope, isRefreshing = false }: RadarSweepVisualProps) {
  const uid = useId().replace(/:/g, "");
  const { ref, shouldAnimate } = useViewportMotion<HTMLDivElement>();
  const gradId = `vs-radar-sweep-${uid}`;
  const isLive = scope.sweepTone === "live_cyan";
  const accent = isLive ? "#10b981" : "#38bdf8";
  const ringStroke = isLive ? "#1e3a4c" : "#273449";

  return (
    <div
      ref={ref}
      aria-hidden="true"
      data-testid="radar-sweep-visual"
      data-radar-scope={scope.mode}
      data-motion-state={shouldAnimate ? "running" : "paused"}
      title={scope.scopeAriaNote}
      className="vs-radar-sweep relative flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-border-strong/85 bg-surface-deep"
    >
      <svg viewBox="0 0 56 56" fill="none" className="h-full w-full" focusable="false">
        <defs>
          <linearGradient id={gradId} x1="28" y1="6" x2="48" y2="28" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor={accent} stopOpacity={isLive ? "0.45" : "0.28"} />
            <stop offset="100%" stopColor={accent} stopOpacity="0" />
          </linearGradient>
        </defs>

        <circle cx="28" cy="28" r="22" stroke={ringStroke} strokeWidth="1.1" />
        <circle
          cx="28"
          cy="28"
          r="14.5"
          stroke={ringStroke}
          strokeWidth="1"
          strokeDasharray={isLive ? undefined : "3 3"}
        />
        <circle cx="28" cy="28" r="7" stroke={ringStroke} strokeWidth="0.9" />
        <line x1="28" y1="6" x2="28" y2="50" stroke="#1e293b" strokeWidth="0.9" />
        <line x1="6" y1="28" x2="50" y2="28" stroke="#1e293b" strokeWidth="0.9" />

        <g className={isRefreshing ? "vs-radar-rotor vs-radar-rotor-fast" : "vs-radar-rotor"}>
          <path d="M28 28 L28 6 A22 22 0 0 1 47 17 Z" fill={`url(#${gradId})`} />
          <line
            x1="28"
            y1="28"
            x2="28"
            y2="6.5"
            stroke={accent}
            strokeWidth="1.35"
            strokeLinecap="round"
            strokeOpacity={isLive ? "0.85" : "0.6"}
          />
        </g>

        {/* Subtle telemetry reference blips (cyan/slate only — never red alarm strobes on demo data) */}
        <circle cx="38" cy="18" r="1.8" fill={isLive ? "#f59e0b" : "#38bdf8"} fillOpacity="0.85" />
        <circle cx="19" cy="35" r="1.5" fill={accent} fillOpacity="0.7" />
        <circle cx="28" cy="28" r="2.4" fill={accent} />
      </svg>
    </div>
  );
}
