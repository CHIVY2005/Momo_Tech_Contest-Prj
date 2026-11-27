"use client";

import { type ReactNode, useEffect, useRef } from "react";

import { staggerDelaysMs } from "@/lib/motion/motionMath";

interface DrawOnViewProps {
  children: ReactNode;
  /** Upper bound for the last arrow's start delay. */
  maxTotalMs?: number;
}

const ARROW_SELECTOR =
  "line[marker-end]:not([stroke-dasharray]), path[marker-end]:not([stroke-dasharray]), polyline[marker-end]:not([stroke-dasharray])";

/**
 * Progressive enhancement for static architecture SVGs: arrows are fully visible without JS,
 * and only after hydration (and when motion is allowed) are they hidden and drawn in DOM order
 * the first time the diagram scrolls into view.
 */
export function DrawOnView({ children, maxTotalMs = 900 }: DrawOnViewProps) {
  const rootRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const root = rootRef.current;
    if (!root || typeof IntersectionObserver === "undefined") return;
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;

    const arrows = Array.from(root.querySelectorAll<SVGGeometryElement>(ARROW_SELECTOR));
    if (arrows.length === 0) return;

    const delays = staggerDelaysMs(arrows.length, 45, maxTotalMs);
    arrows.forEach((el, i) => {
      const len = typeof el.getTotalLength === "function" ? el.getTotalLength() : 0;
      el.style.setProperty("--len", String(Math.ceil(len) + 1));
      el.style.setProperty("--delay", `${delays[i] ?? 0}ms`);
    });
    root.dataset.drawReady = "true";

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          root.dataset.drawn = "true";
          observer.disconnect();
        }
      },
      { threshold: 0.2 },
    );
    observer.observe(root);

    return () => {
      observer.disconnect();
      delete root.dataset.drawReady;
      delete root.dataset.drawn;
    };
  }, [maxTotalMs]);

  return (
    <div ref={rootRef} className="vs-draw">
      {children}
    </div>
  );
}
