"use client";

import { useId } from "react";

import { useViewportMotion } from "./useViewportMotion";

interface HeroShieldScannerProps {
  /** Pause ambient hero scan while live analysis pipeline is actively running below. */
  paused?: boolean;
}

/**
 * Self-hosted VeriShield Shield Scanning emblem for the homepage hero.
 * Combines the VeriShield shield silhouette (amber), concentric radar reticle,
 * subtle rotating cyan sweep arc, and clip-pathed horizontal scan line.
 * Zero external assets, zero layout shift, auto-pauses off-screen and under reduced motion.
 */
export function HeroShieldScanner({ paused = false }: HeroShieldScannerProps) {
  const uid = useId().replace(/:/g, "");
  const { ref, shouldAnimate } = useViewportMotion<HTMLDivElement>({ paused });
  const clipId = `vs-hero-shield-clip-${uid}`;
  const sweepGradId = `vs-hero-sweep-grad-${uid}`;
  const scanGradId = `vs-hero-scan-grad-${uid}`;

  return (
    <div
      ref={ref}
      aria-hidden="true"
      data-testid="hero-shield-scanner"
      data-motion-state={shouldAnimate ? "running" : "paused"}
      className="vs-hero-scanner relative flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-border-strong/90 bg-surface-deep shadow-inner sm:h-[54px] sm:w-[54px]"
    >
      <svg
        viewBox="0 0 64 64"
        fill="none"
        className="h-full w-full"
        focusable="false"
      >
        <defs>
          <clipPath id={clipId}>
            <path d="M32 13L47 19.2V31.2C47 41.2 40.5 48.6 32 51.4C23.5 48.6 17 41.2 17 31.2V19.2L32 13Z" />
          </clipPath>
          <linearGradient id={sweepGradId} x1="32" y1="6" x2="54" y2="32" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.45" />
            <stop offset="100%" stopColor="#0ea5e9" stopOpacity="0" />
          </linearGradient>
          <linearGradient id={scanGradId} x1="17" y1="0" x2="47" y2="0" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#0ea5e9" stopOpacity="0" />
            <stop offset="50%" stopColor="#38bdf8" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#0ea5e9" stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* Concentric radar rings + precision axis ticks */}
        <circle cx="32" cy="32" r="27" stroke="#1e293b" strokeWidth="1" />
        <circle cx="32" cy="32" r="21.5" stroke="#273449" strokeWidth="0.9" strokeDasharray="3 4" />
        <line x1="32" y1="4.5" x2="32" y2="9" stroke="#334155" strokeWidth="1" />
        <line x1="32" y1="55" x2="32" y2="59.5" stroke="#334155" strokeWidth="1" />
        <line x1="4.5" y1="32" x2="9" y2="32" stroke="#334155" strokeWidth="1" />
        <line x1="55" y1="32" x2="59.5" y2="32" stroke="#334155" strokeWidth="1" />

        {/* Subtle rotating cyan radar sweep wedge */}
        <g className="vs-hero-radar-rotor">
          <path
            d="M32 32 L32 6 A26 26 0 0 1 54.5 19 Z"
            fill={`url(#${sweepGradId})`}
          />
          <line
            x1="32"
            y1="32"
            x2="32"
            y2="6.5"
            stroke="#38bdf8"
            strokeOpacity="0.65"
            strokeWidth="1.2"
            strokeLinecap="round"
          />
        </g>

        {/* VeriShield dark core + amber shield silhouette */}
        <path
          d="M32 13L47 19.2V31.2C47 41.2 40.5 48.6 32 51.4C23.5 48.6 17 41.2 17 31.2V19.2L32 13Z"
          fill="#121a29"
          fillOpacity="0.94"
          stroke="#f59e0b"
          strokeWidth="2.1"
          strokeLinejoin="round"
        />

        {/* Subtle horizontal cyan scan beam clipped strictly inside the shield */}
        <g clipPath={`url(#${clipId})`}>
          <g className="vs-hero-scanline">
            <rect x="16" y="13" width="32" height="5" fill={`url(#${scanGradId})`} opacity="0.24" />
            <line
              x1="17"
              y1="15.5"
              x2="47"
              y2="15.5"
              stroke={`url(#${scanGradId})`}
              strokeWidth="1.4"
              strokeLinecap="round"
            />
          </g>
        </g>

        {/* Crisp inner verification chevron + brand amber telemetry node */}
        <path
          d="M25.5 32.2L29.8 36.5L38.8 27.3"
          stroke="#38bdf8"
          strokeWidth="2.6"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <circle cx="43.5" cy="21" r="2" fill="#f59e0b" className="vs-hero-telemetry-dot" />
      </svg>
    </div>
  );
}
