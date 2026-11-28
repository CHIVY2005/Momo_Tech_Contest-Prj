"use client";

import type { ScenarioIconKind } from "@/lib/motion/cyberMotion";

interface ScenarioCategoryIconProps {
  kind: ScenarioIconKind;
}

/**
 * Hover/focus-triggered one-shot animated cybersecurity icons for the 4 sample scenario cards:
 * Tin nhắn (message), Biên lai (receipt), Mã VietQR (vietqr), and Cuộc gọi (call).
 * Strictly zero continuous autoplay: animations fire once via parent `.vs-scenario-card:is(:hover, :focus-visible)`.
 */
export function ScenarioCategoryIcon({ kind }: ScenarioCategoryIconProps) {
  return (
    <svg
      viewBox="0 0 20 20"
      fill="none"
      aria-hidden="true"
      focusable="false"
      data-scenario-icon={kind}
      className="vs-scenario-svg h-3.5 w-3.5 shrink-0 text-amber-400"
    >
      {kind === "message" && (
        <>
          <path
            d="M4 5.2C4 4.54 4.54 4 5.2 4H14.8C15.46 4 16 4.54 16 5.2V11.8C16 12.46 15.46 13 14.8 13H8.2L5 15.6V13H5.2C4.54 13 4 12.46 4 11.8V5.2Z"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinejoin="round"
          />
          <line
            x1="7"
            y1="7.5"
            x2="13"
            y2="7.5"
            stroke="#38bdf8"
            strokeWidth="1.5"
            strokeLinecap="round"
            className="vs-sc-msg-line-1"
          />
          <line
            x1="7"
            y1="10"
            x2="11"
            y2="10"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
            className="vs-sc-msg-line-2"
          />
          <circle cx="15.5" cy="4.8" r="1.7" fill="#ef4444" className="vs-sc-msg-ping" />
        </>
      )}

      {kind === "receipt" && (
        <>
          <path
            d="M5 3.5H15V16.5L13 15.2L11 16.5L9 15.2L7 16.5L5 15.2V3.5Z"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinejoin="round"
          />
          <line x1="7.4" y1="7" x2="12.6" y2="7" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          <line x1="7.4" y1="10" x2="11.4" y2="10" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          <line
            x1="5.8"
            y1="5.5"
            x2="14.2"
            y2="5.5"
            stroke="#38bdf8"
            strokeWidth="1.6"
            strokeLinecap="round"
            className="vs-sc-receipt-scan"
          />
        </>
      )}

      {kind === "vietqr" && (
        <>
          <rect x="3.5" y="3.5" width="4.8" height="4.8" rx="0.9" stroke="currentColor" strokeWidth="1.5" className="vs-sc-qr-box" />
          <rect x="11.7" y="3.5" width="4.8" height="4.8" rx="0.9" stroke="currentColor" strokeWidth="1.5" className="vs-sc-qr-box" />
          <rect x="3.5" y="11.7" width="4.8" height="4.8" rx="0.9" stroke="currentColor" strokeWidth="1.5" className="vs-sc-qr-box" />
          <rect x="12" y="12" width="2" height="2" fill="currentColor" />
          <rect x="14.8" y="14.8" width="1.9" height="1.9" fill="currentColor" />
          <line
            x1="3"
            y1="6"
            x2="17"
            y2="6"
            stroke="#38bdf8"
            strokeWidth="1.6"
            strokeLinecap="round"
            className="vs-sc-qr-beam"
          />
        </>
      )}

      {kind === "call" && (
        <>
          <path
            d="M6.2 4.3L8.2 4.8L9 7.6L7.4 8.8C8.1 10.3 9.4 11.6 11 12.3L12.2 10.7L15 11.5L15.5 13.5C15.6 14.3 15 15.2 14.1 15.3C9.6 15.6 4.2 10.2 4.5 5.7C4.6 4.8 5.4 4.1 6.2 4.3Z"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinejoin="round"
            className="vs-sc-call-handset"
          />
          <path
            d="M11.8 5.2C13.3 5.7 14.3 6.7 14.8 8.2"
            stroke="#38bdf8"
            strokeWidth="1.4"
            strokeLinecap="round"
            className="vs-sc-call-wave-1"
          />
          <path
            d="M12.4 3C14.8 3.7 16.3 5.2 17 7.6"
            stroke="#38bdf8"
            strokeWidth="1.3"
            strokeLinecap="round"
            strokeOpacity="0.85"
            className="vs-sc-call-wave-2"
          />
        </>
      )}
    </svg>
  );
}
