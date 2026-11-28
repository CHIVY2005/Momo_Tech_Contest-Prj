"use client";

import type { VerdictMotionTone } from "@/lib/motion/cyberMotion";

interface VerdictStatusEmblemProps {
  tone: VerdictMotionTone;
}

/**
 * Distinct one-shot transition emblem for each VeriShield risk state.
 * Keyed externally on `buildVerdictTransitionKey(report)` so the transition fires ONLY when
 * an analysis result changes and settles calmly without distracting infinite loops.
 *
 * Honesty guardrail: `safe_unverified` (SAFE verdict on an unverified transfer receipt screenshot)
 * pairs the emerald check with an amber balance-verification cue so completion is never misread
 * as absolute proof that funds arrived.
 */
export function VerdictStatusEmblem({ tone }: VerdictStatusEmblemProps) {
  return (
    <span
      aria-hidden="true"
      data-testid="verdict-status-emblem"
      data-verdict-tone={tone}
      className="vs-verdict-emblem relative inline-flex h-5 w-5 shrink-0 items-center justify-center"
    >
      <svg viewBox="0 0 24 24" fill="none" className="h-5 w-5 overflow-visible" focusable="false">
        {(tone === "safe" || tone === "safe_unverified") && (
          <>
            <circle
              cx="12"
              cy="12"
              r="10.5"
              stroke={tone === "safe_unverified" ? "#f59e0b" : "#10b981"}
              strokeWidth="1.2"
              className="vs-verdict-ring-once"
            />
            <path
              d="M12 3.2L19 6.2V11.8C19 16.5 16 19.8 12 21C8 19.8 5 16.5 5 11.8V6.2L12 3.2Z"
              stroke="#10b981"
              strokeWidth="1.8"
              strokeLinejoin="round"
              strokeDasharray="60"
              className="vs-verdict-draw-shield"
            />
            <path
              d="M8.8 12.2L11 14.4L15.4 9.8"
              stroke="#10b981"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeDasharray="16"
              className="vs-verdict-draw-check"
            />
            {tone === "safe_unverified" && (
              <circle
                cx="18.2"
                cy="6"
                r="2.4"
                fill="#f59e0b"
                stroke="#0b101b"
                strokeWidth="1.2"
              />
            )}
          </>
        )}

        {tone === "suspicious" && (
          <>
            <circle
              cx="12"
              cy="13"
              r="10"
              stroke="#f59e0b"
              strokeWidth="1.2"
              className="vs-verdict-ring-once"
            />
            <path
              d="M12 4L20.2 18.5H3.8L12 4Z"
              stroke="#f59e0b"
              strokeWidth="1.8"
              strokeLinejoin="round"
              className="vs-verdict-pop-once"
            />
            <line
              x1="12"
              y1="9.2"
              x2="12"
              y2="13.5"
              stroke="#fbbf24"
              strokeWidth="2"
              strokeLinecap="round"
            />
            <circle cx="12" cy="16.2" r="1.1" fill="#fbbf24" />
          </>
        )}

        {tone === "high_risk" && (
          <>
            <circle
              cx="12"
              cy="12"
              r="10.5"
              stroke="#f97316"
              strokeWidth="1.4"
              className="vs-verdict-ring-once"
            />
            <path
              d="M12 3.2L19 6.2V11.8C19 16.5 16 19.8 12 21C8 19.8 5 16.5 5 11.8V6.2L12 3.2Z"
              stroke="#f97316"
              strokeWidth="1.9"
              strokeLinejoin="round"
              className="vs-verdict-pop-once"
            />
            <line
              x1="12"
              y1="8.2"
              x2="12"
              y2="13"
              stroke="#fb923c"
              strokeWidth="2"
              strokeLinecap="round"
            />
            <circle cx="12" cy="16" r="1.15" fill="#fb923c" />
          </>
        )}

        {tone === "critical" && (
          <>
            <circle
              cx="12"
              cy="12"
              r="10.8"
              stroke="#ef4444"
              strokeWidth="1.5"
              className="vs-verdict-ring-critical"
            />
            <polygon
              points="8.2,3.4 15.8,3.4 20.6,8.2 20.6,15.8 15.8,20.6 8.2,20.6 3.4,15.8 3.4,8.2"
              stroke="#ef4444"
              strokeWidth="1.9"
              strokeLinejoin="round"
              className="vs-verdict-alert-lock"
            />
            <line
              x1="12"
              y1="7.8"
              x2="12"
              y2="12.8"
              stroke="#fca5a5"
              strokeWidth="2.1"
              strokeLinecap="round"
            />
            <circle cx="12" cy="15.9" r="1.2" fill="#fca5a5" />
          </>
        )}
      </svg>
    </span>
  );
}
