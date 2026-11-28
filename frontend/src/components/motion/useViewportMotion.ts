"use client";

import { useCallback, useEffect, useState } from "react";

import { shouldRunAmbientMotion } from "@/lib/motion/cyberMotion";

interface UseViewportMotionOptions {
  /** Extra pause condition (e.g., active drag, analyzing elsewhere, or collapsed). */
  paused?: boolean;
  /** IntersectionObserver threshold (default 0.05). */
  threshold?: number;
}

/**
 * Automatically pauses ambient CSS/SVG animations when the host element scrolls out of view,
 * when the browser tab becomes hidden, or when the user prefers reduced motion.
 * Uses a callback ref so conditionally mounted nodes (e.g. tab/view toggles) are always observed.
 */
export function useViewportMotion<T extends Element = HTMLDivElement>({
  paused = false,
  threshold = 0.05,
}: UseViewportMotionOptions = {}) {
  const [node, setNode] = useState<T | null>(null);
  const [inViewport, setInViewport] = useState(true);
  const [documentVisible, setDocumentVisible] = useState(true);
  const [reducedMotion, setReducedMotion] = useState(false);

  const ref = useCallback((el: T | null) => {
    setNode(el);
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const onVisibilityChange = () => {
      setDocumentVisible(document.visibilityState !== "hidden");
    };
    onVisibilityChange();
    document.addEventListener("visibilitychange", onVisibilityChange);

    const mq =
      typeof window.matchMedia === "function"
        ? window.matchMedia("(prefers-reduced-motion: reduce)")
        : null;

    if (!mq) {
      return () => {
        document.removeEventListener("visibilitychange", onVisibilityChange);
      };
    }

    setReducedMotion(mq.matches);
    const onMotionChange = (ev: MediaQueryListEvent) => setReducedMotion(ev.matches);
    mq.addEventListener("change", onMotionChange);

    return () => {
      mq.removeEventListener("change", onMotionChange);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, []);

  useEffect(() => {
    if (!node || typeof IntersectionObserver === "undefined") return;

    const observer = new IntersectionObserver(
      (entries) => {
        const entry = entries[0];
        if (entry) {
          setInViewport(entry.isIntersecting);
        }
      },
      { threshold },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [node, threshold]);

  const shouldAnimate = shouldRunAmbientMotion({
    inViewport,
    documentVisible,
    reducedMotion,
    pausedByInteraction: paused,
  });

  return { ref, shouldAnimate, reducedMotion };
}
