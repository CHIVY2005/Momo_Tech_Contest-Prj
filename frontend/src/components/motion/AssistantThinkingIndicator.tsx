"use client";

interface AssistantThinkingIndicatorProps {
  label: string;
  compact?: boolean;
}

/**
 * Compact, compositor-only thinking indicator for Trợ lý VeriShield.
 * Uses pure inline SVG + CSS transforms inside `contain: layout style paint` so it never
 * interferes with Markdown streaming, scroll anchoring, or chat panel drag resizing.
 * Automatically pauses during panel resize (`.assistant-panel[data-resizing]`) and reduced motion.
 */
export function AssistantThinkingIndicator({
  label,
  compact = false,
}: AssistantThinkingIndicatorProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="assistant-thinking-indicator"
      style={{ contain: "layout style paint" }}
      className={
        compact
          ? "mt-2 flex min-h-[18px] items-center gap-2 text-[11px] text-ink-muted"
          : "flex min-h-[22px] items-center gap-2 py-0.5 text-xs text-ink-muted"
      }
    >
      <svg
        viewBox="0 0 22 14"
        fill="none"
        aria-hidden="true"
        focusable="false"
        className={compact ? "h-3 w-5 shrink-0" : "h-3.5 w-5.5 shrink-0"}
      >
        <rect
          x="2"
          y="3"
          width="3.2"
          height="8"
          rx="1.6"
          fill="#0ea5e9"
          className="vs-thinking-bar vs-thinking-bar-1"
        />
        <rect
          x="9.4"
          y="2"
          width="3.2"
          height="10"
          rx="1.6"
          fill="#f59e0b"
          className="vs-thinking-bar vs-thinking-bar-2"
        />
        <rect
          x="16.8"
          y="3"
          width="3.2"
          height="8"
          rx="1.6"
          fill="#38bdf8"
          className="vs-thinking-bar vs-thinking-bar-3"
        />
      </svg>
      <span className="min-w-0 truncate">{label}</span>
    </div>
  );
}
