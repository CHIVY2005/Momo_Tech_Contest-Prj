/**
 * Pure motion helpers (no DOM, no JSX) so they can be unit-tested with `node --test`.
 */

export interface RectLike {
  left: number;
  top: number;
  width: number;
  height: number;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

export function easeOutCubic(t: number): number {
  const c = clamp(t, 0, 1);
  return 1 - (1 - c) ** 3;
}

export function interpolateCount(from: number, to: number, progress: number): number {
  const p = clamp(progress, 0, 1);
  if (p === 0) return Math.round(from);
  if (p === 1) return Math.round(to);
  return Math.round(from + (to - from) * easeOutCubic(p));
}

export function countDurationMs(from: number, to: number): number {
  return Math.min(600, Math.max(240, Math.abs(to - from) * 8));
}

export function staggerDelaysMs(count: number, stepMs: number, maxTotalMs: number): number[] {
  if (count <= 0) return [];
  const span = count - 1;
  const step = span > 0 && span * stepMs > maxTotalMs ? maxTotalMs / span : stepMs;
  return Array.from({ length: count }, (_, i) => Math.round(i * step));
}

export function spotlightPosition(
  rect: RectLike,
  clientX: number,
  clientY: number,
): { xPct: number; yPct: number } {
  if (rect.width <= 0 || rect.height <= 0) {
    return { xPct: 50, yPct: 50 };
  }
  const xPct = clamp(((clientX - rect.left) / rect.width) * 100, 0, 100);
  const yPct = clamp(((clientY - rect.top) / rect.height) * 100, 0, 100);
  return { xPct: Math.round(xPct * 10) / 10, yPct: Math.round(yPct * 10) / 10 };
}
