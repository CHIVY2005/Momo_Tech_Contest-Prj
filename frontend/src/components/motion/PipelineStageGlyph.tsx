"use client";

import type { PipelineStageKind } from "@/lib/motion/cyberMotion";

export type StageGlyphState = "processing" | "completed" | "warning" | "failed";

interface PipelineStageGlyphProps {
  kind: PipelineStageKind;
  state: StageGlyphState;
}

/**
 * Dedicated self-hosted cybersecurity SVG micro-animations for real backend analysis stages:
 * Text Analysis, URL Scanning, OCR Processing, QR Analysis, AI Inference, and Risk Assessment.
 * Animates ONLY when `state === "processing"`, settles statically on completion/warning/failure.
 */
export function PipelineStageGlyph({ kind, state }: PipelineStageGlyphProps) {
  const isActive = state === "processing";
  const toneColor =
    state === "failed"
      ? "#ef4444"
      : state === "warning"
        ? "#f59e0b"
        : state === "completed"
          ? "#10b981"
          : "#38bdf8";

  return (
    <span
      aria-hidden="true"
      data-stage-kind={kind}
      data-stage-state={state}
      className="vs-stage-glyph relative inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-border-strong/75 bg-surface-deep"
    >
      <svg viewBox="0 0 24 24" fill="none" className="h-4 w-4" focusable="false">
        {kind === "text_analysis" && (
          <>
            <rect x="4" y="4" width="16" height="16" rx="3" stroke={toneColor} strokeWidth="1.6" strokeOpacity="0.85" />
            <line
              x1="7.5"
              y1="9"
              x2="16.5"
              y2="9"
              stroke={toneColor}
              strokeWidth="1.6"
              strokeLinecap="round"
              className={isActive ? "vs-glyph-pulse-a" : undefined}
            />
            <line
              x1="7.5"
              y1="12.5"
              x2="14.5"
              y2="12.5"
              stroke={isActive ? "#f59e0b" : toneColor}
              strokeWidth="1.6"
              strokeLinecap="round"
              className={isActive ? "vs-glyph-pulse-b" : undefined}
            />
            <line
              x1="7.5"
              y1="16"
              x2="12.5"
              y2="16"
              stroke={toneColor}
              strokeWidth="1.6"
              strokeLinecap="round"
              className={isActive ? "vs-glyph-pulse-c" : undefined}
            />
          </>
        )}

        {kind === "url_scanning" && (
          <>
            <circle cx="12" cy="12" r="7.5" stroke={toneColor} strokeWidth="1.5" strokeOpacity="0.7" />
            <ellipse cx="12" cy="12" rx="3.6" ry="7.5" stroke={toneColor} strokeWidth="1.2" strokeOpacity="0.55" />
            <line x1="4.8" y1="12" x2="19.2" y2="12" stroke={toneColor} strokeWidth="1.2" strokeOpacity="0.55" />
            <path
              d="M12 4.5 A7.5 7.5 0 0 1 19.5 12"
              stroke={isActive ? "#38bdf8" : toneColor}
              strokeWidth="2"
              strokeLinecap="round"
              className={isActive ? "vs-glyph-orbit" : undefined}
            />
          </>
        )}

        {kind === "ocr_processing" && (
          <>
            <path
              d="M7 4H5a1 1 0 0 0-1 1v2M17 4h2a1 1 0 0 1 1 1v2M7 20H5a1 1 0 0 1-1-1v-2M17 20h2a1 1 0 0 0 1-1v-2"
              stroke={toneColor}
              strokeWidth="1.7"
              strokeLinecap="round"
            />
            <line x1="8" y1="10" x2="16" y2="10" stroke="#94a3b8" strokeWidth="1.3" strokeLinecap="round" />
            <line x1="8" y1="14" x2="14" y2="14" stroke="#94a3b8" strokeWidth="1.3" strokeLinecap="round" />
            <line
              x1="5.5"
              y1="7"
              x2="18.5"
              y2="7"
              stroke={isActive ? "#38bdf8" : toneColor}
              strokeWidth="1.7"
              strokeLinecap="round"
              className={isActive ? "vs-glyph-scan-y" : undefined}
            />
          </>
        )}

        {kind === "qr_analysis" && (
          <>
            <rect x="4" y="4" width="6" height="6" rx="1" stroke={toneColor} strokeWidth="1.6" />
            <rect x="14" y="4" width="6" height="6" rx="1" stroke={toneColor} strokeWidth="1.6" />
            <rect x="4" y="14" width="6" height="6" rx="1" stroke={toneColor} strokeWidth="1.6" />
            <rect x="14.5" y="14.5" width="2.2" height="2.2" fill={toneColor} />
            <rect x="18" y="18" width="2" height="2" fill={toneColor} />
            <line
              x1="3.5"
              y1="7"
              x2="20.5"
              y2="7"
              stroke={isActive ? "#f59e0b" : toneColor}
              strokeWidth="1.6"
              strokeLinecap="round"
              className={isActive ? "vs-glyph-scan-y" : undefined}
            />
          </>
        )}

        {kind === "ai_inference" && (
          <>
            <line x1="7" y1="8" x2="12" y2="12" stroke={toneColor} strokeWidth="1.3" strokeOpacity="0.65" />
            <line x1="7" y1="16" x2="12" y2="12" stroke={toneColor} strokeWidth="1.3" strokeOpacity="0.65" />
            <line x1="12" y1="12" x2="17.5" y2="9" stroke={toneColor} strokeWidth="1.3" strokeOpacity="0.65" />
            <line x1="12" y1="12" x2="17.5" y2="15" stroke={toneColor} strokeWidth="1.3" strokeOpacity="0.65" />
            <circle cx="7" cy="8" r="2" fill={toneColor} className={isActive ? "vs-glyph-pulse-a" : undefined} />
            <circle cx="7" cy="16" r="2" fill={toneColor} className={isActive ? "vs-glyph-pulse-a" : undefined} />
            <circle cx="12" cy="12" r="2.3" fill={isActive ? "#f59e0b" : toneColor} className={isActive ? "vs-glyph-pulse-b" : undefined} />
            <circle cx="17.5" cy="9" r="1.9" fill={toneColor} className={isActive ? "vs-glyph-pulse-c" : undefined} />
            <circle cx="17.5" cy="15" r="1.9" fill={toneColor} className={isActive ? "vs-glyph-pulse-c" : undefined} />
          </>
        )}

        {kind === "risk_assessment" && (
          <>
            <path
              d="M5.5 16.5 A7.5 7.5 0 1 1 18.5 16.5"
              stroke="#334155"
              strokeWidth="1.8"
              strokeLinecap="round"
            />
            <path
              d="M5.5 16.5 A7.5 7.5 0 0 1 18.5 16.5"
              stroke={toneColor}
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeDasharray="16 24"
              className={isActive ? "vs-glyph-gauge" : undefined}
            />
            <line
              x1="12"
              y1="14.5"
              x2="15.8"
              y2="10.8"
              stroke={isActive ? "#f59e0b" : toneColor}
              strokeWidth="1.8"
              strokeLinecap="round"
            />
            <circle cx="12" cy="14.5" r="1.6" fill={toneColor} />
          </>
        )}
      </svg>
    </span>
  );
}
