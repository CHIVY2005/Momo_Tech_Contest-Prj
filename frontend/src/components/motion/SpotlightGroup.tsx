"use client";

import { type PointerEvent, type ReactNode, useCallback, useEffect, useRef } from "react";

import { spotlightPosition } from "@/lib/motion/motionMath";

interface SpotlightGroupProps {
  className?: string;
  children: ReactNode;
}

/**
 * One delegated `pointermove` listener for a grid of cards. Each descendant with class
 * `vs-spotlight` gets `--spot-x/--spot-y` set (rAF-throttled); the glow itself is pure CSS.
 */
export function SpotlightGroup({ className, children }: SpotlightGroupProps) {
  const rootRef = useRef<HTMLDivElement | null>(null);
  const rafRef = useRef(0);
  const pendingRef = useRef<{ card: HTMLElement; x: number; y: number } | null>(null);

  useEffect(() => () => window.cancelAnimationFrame(rafRef.current), []);

  const handlePointerMove = useCallback((event: PointerEvent<HTMLDivElement>) => {
    if (event.pointerType !== "mouse") return;
    const target = event.target as Element | null;
    const card = target?.closest<HTMLElement>(".vs-spotlight");
    if (!card || !rootRef.current?.contains(card)) return;
    pendingRef.current = { card, x: event.clientX, y: event.clientY };
    if (rafRef.current) return;
    rafRef.current = window.requestAnimationFrame(() => {
      rafRef.current = 0;
      const pending = pendingRef.current;
      if (!pending) return;
      const { xPct, yPct } = spotlightPosition(
        pending.card.getBoundingClientRect(),
        pending.x,
        pending.y,
      );
      pending.card.style.setProperty("--spot-x", `${xPct}%`);
      pending.card.style.setProperty("--spot-y", `${yPct}%`);
    });
  }, []);

  return (
    <div ref={rootRef} className={className} onPointerMove={handlePointerMove}>
      {children}
    </div>
  );
}
