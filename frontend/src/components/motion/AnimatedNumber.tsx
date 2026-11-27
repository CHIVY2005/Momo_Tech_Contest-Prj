"use client";

import { useEffect, useRef, useState } from "react";

import { countDurationMs, interpolateCount } from "@/lib/motion/motionMath";

interface AnimatedNumberProps {
  value: number;
  /** Count up from 0 on first mount (used for the risk score reveal). */
  animateOnMount?: boolean;
  format?: (n: number) => string;
  className?: string;
}

const defaultFormat = (n: number) => n.toLocaleString("vi-VN");

function reducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

/**
 * Odometer-style integer counter. Screen readers always get the final value via an sr-only twin.
 */
export function AnimatedNumber({
  value,
  animateOnMount = false,
  format = defaultFormat,
  className,
}: AnimatedNumberProps) {
  // `animateOnMount` components are only mounted client-side after a report arrives, so starting
  // at 0 avoids a value→0→value flash; reduced-motion users get the final value immediately.
  const initial = animateOnMount && !reducedMotion() ? 0 : value;
  const [display, setDisplay] = useState(initial);
  const displayRef = useRef(initial);
  const mountedRef = useRef(false);

  useEffect(() => {
    const isMount = !mountedRef.current;
    mountedRef.current = true;
    if (isMount && !animateOnMount) return;

    const from = displayRef.current;
    if (from === value || reducedMotion()) {
      displayRef.current = value;
      setDisplay(value);
      return;
    }

    const duration = countDurationMs(from, value);
    let raf = 0;
    let start: number | null = null;
    const tick = (now: number) => {
      if (start === null) start = now;
      const next = interpolateCount(from, value, (now - start) / duration);
      displayRef.current = next;
      setDisplay(next);
      if (next !== value) raf = window.requestAnimationFrame(tick);
    };
    raf = window.requestAnimationFrame(tick);
    return () => window.cancelAnimationFrame(raf);
  }, [value, animateOnMount]);

  return (
    <span className={className}>
      <span aria-hidden="true">{format(display)}</span>
      <span className="sr-only">{format(value)}</span>
    </span>
  );
}
