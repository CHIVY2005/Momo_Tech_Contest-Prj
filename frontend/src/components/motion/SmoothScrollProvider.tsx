"use client";

import Lenis from "lenis";
import { usePathname } from "next/navigation";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  ANCHOR_OFFSET_PX,
  createScrollLockCounter,
  parseSameDocumentHash,
  type ScrollLockCounter,
  shouldEnableSmoothScroll,
} from "@/lib/motion/scrollControl";

interface ScrollToOptions {
  offset?: number;
  immediate?: boolean;
}

interface SmoothScrollContextValue {
  isSmooth: boolean;
  scrollToElement: (el: HTMLElement, opts?: ScrollToOptions) => void;
  acquireLock: () => () => void;
}

const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia(REDUCED_MOTION_QUERY).matches
    : false;
}

const SmoothScrollContext = createContext<SmoothScrollContextValue>({
  isSmooth: false,
  scrollToElement: (el) => el.scrollIntoView({ block: "start" }),
  acquireLock: () => () => undefined,
});

function focusTarget(el: HTMLElement) {
  if (!el.hasAttribute("tabindex") && !/^(A|BUTTON|INPUT|SELECT|TEXTAREA)$/.test(el.tagName)) {
    el.setAttribute("tabindex", "-1");
  }
  el.focus({ preventScroll: true });
}

export function SmoothScrollProvider({ children }: { children: ReactNode }) {
  const lenisRef = useRef<Lenis | null>(null);
  const lockedRef = useRef(false);
  const counterRef = useRef<ScrollLockCounter | null>(null);
  const [isSmooth, setIsSmooth] = useState(false);
  const pathname = usePathname();

  if (counterRef.current === null) {
    counterRef.current = createScrollLockCounter((locked) => {
      lockedRef.current = locked;
      if (locked) lenisRef.current?.stop();
      else lenisRef.current?.start();
    });
  }

  // Lenis lifecycle: create only when motion is allowed; follow live OS preference changes.
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const media = window.matchMedia(REDUCED_MOTION_QUERY);

    const teardown = () => {
      lenisRef.current?.destroy();
      lenisRef.current = null;
      setIsSmooth(false);
    };

    const sync = () => {
      teardown();
      if (!shouldEnableSmoothScroll({ reducedMotion: media.matches, hasWindow: true })) return;
      const instance = new Lenis({
        autoRaf: true,
        lerp: 0.1,
        smoothWheel: true,
        syncTouch: false,
        stopInertiaOnNavigate: true,
        // Long pasted scam messages must scroll inside their own textarea, not drag the page.
        prevent: (node) => node instanceof HTMLTextAreaElement,
      });
      if (lockedRef.current) instance.stop();
      lenisRef.current = instance;
      setIsSmooth(true);
    };

    sync();
    media.addEventListener("change", sync);
    return () => {
      media.removeEventListener("change", sync);
      teardown();
    };
  }, []);

  // New route: re-measure limits and start the new page at the top (unless deep-linking a hash).
  const isFirstPathRef = useRef(true);
  useEffect(() => {
    // Consume the first-route flag even when Lenis is off (reduced motion at load), so a later
    // re-enable does not mistake the next navigation for the initial deep-link restore.
    const isFirstRoute = isFirstPathRef.current;
    isFirstPathRef.current = false;
    const lenis = lenisRef.current;
    if (!lenis) return;
    lenis.resize();
    if (!isFirstRoute && !window.location.hash) {
      lenis.scrollTo(0, { immediate: true, force: true });
    }
  }, [pathname]);

  const scrollToElement = useCallback((el: HTMLElement, opts?: ScrollToOptions) => {
    const lenis = lenisRef.current;
    if (lenis) {
      // Lenis clamps to a cached, debounced scroll limit; content that just rendered (verdict,
      // late sections) would otherwise cut the scroll short. Re-measure synchronously first.
      lenis.resize();
      // Lenis already subtracts the target's CSS scroll-margin-top (e.g. `scroll-mt-24`), so only
      // apply the header offset when the element has no scroll margin of its own.
      const ownMargin = Number.parseFloat(getComputedStyle(el).scrollMarginTop) || 0;
      lenis.scrollTo(el, {
        offset: opts?.offset ?? (ownMargin > 0 ? 0 : -ANCHOR_OFFSET_PX),
        immediate: opts?.immediate ?? false,
        force: true,
      });
      return;
    }
    el.scrollIntoView({
      behavior: opts?.immediate || prefersReducedMotion() ? "auto" : "smooth",
      block: "start",
    });
  }, []);

  // Same-document anchor clicks (skip-link, docs TOC) while Lenis drives the scroll.
  useEffect(() => {
    function onClick(event: MouseEvent) {
      if (!lenisRef.current || event.defaultPrevented || event.button !== 0) return;
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const anchor = (event.target as Element | null)?.closest?.("a");
      if (!anchor || (anchor.getAttribute("target") ?? "_self") !== "_self") return;
      const id = parseSameDocumentHash(anchor.getAttribute("href"), window.location.pathname);
      if (!id) return;
      const target = document.getElementById(id);
      if (!target) return;
      event.preventDefault();
      scrollToElement(target);
      if (window.location.hash !== `#${id}`) {
        window.history.pushState(null, "", `#${id}`);
      }
      focusTarget(target);
    }
    document.addEventListener("click", onClick, true);
    return () => document.removeEventListener("click", onClick, true);
  }, [scrollToElement]);

  const acquireLock = useCallback(() => {
    return counterRef.current?.acquire() ?? (() => undefined);
  }, []);

  const value = useMemo<SmoothScrollContextValue>(
    () => ({ isSmooth, scrollToElement, acquireLock }),
    [isSmooth, scrollToElement, acquireLock],
  );

  return <SmoothScrollContext.Provider value={value}>{children}</SmoothScrollContext.Provider>;
}

export function useSmoothScroll(): Pick<SmoothScrollContextValue, "isSmooth" | "scrollToElement"> {
  const { isSmooth, scrollToElement } = useContext(SmoothScrollContext);
  return { isSmooth, scrollToElement };
}

/** Freezes page (Lenis) scrolling while `active`; ref-counted across stacked drawers/modals. */
export function useScrollLock(active: boolean): void {
  const { acquireLock } = useContext(SmoothScrollContext);
  useEffect(() => {
    if (!active) return;
    return acquireLock();
  }, [active, acquireLock]);
}
