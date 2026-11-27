/**
 * Pure scroll-control helpers (no DOM, no JSX) so they can be unit-tested with `node --test`.
 */

/** Matches `scroll-margin-top: 84px` in globals.css (sticky header height + breathing room). */
export const ANCHOR_OFFSET_PX = 84;

const SAFE_ID_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

export function shouldEnableSmoothScroll(env: {
  reducedMotion: boolean;
  hasWindow: boolean;
}): boolean {
  return env.hasWindow && !env.reducedMotion;
}

/**
 * Returns the target element id only for same-document anchors (`#id` or `/<current path>#id`)
 * with a conservative id grammar; anything else returns null so the browser keeps default behavior.
 */
export function parseSameDocumentHash(
  href: string | null | undefined,
  currentPathname: string,
): string | null {
  if (!href) return null;
  const hashIndex = href.indexOf("#");
  if (hashIndex < 0) return null;
  const pathPart = href.slice(0, hashIndex);
  if (pathPart !== "" && pathPart !== currentPathname) return null;
  const id = href.slice(hashIndex + 1);
  return SAFE_ID_RE.test(id) ? id : null;
}

export function shouldAutoScrollIntoView(input: {
  targetTop: number;
  viewportHeight: number;
  headerHeight: number;
  alreadyScrolledForCase: boolean;
}): boolean {
  if (input.alreadyScrolledForCase) return false;
  return input.targetTop < input.headerHeight || input.targetTop > input.viewportHeight * 0.6;
}

export interface ScrollLockCounter {
  acquire(): () => void;
}

/** Ref-counted lock: `onChange(true)` on 0→1, `onChange(false)` on 1→0; release is idempotent. */
export function createScrollLockCounter(onChange: (locked: boolean) => void): ScrollLockCounter {
  let holders = 0;
  return {
    acquire() {
      holders += 1;
      if (holders === 1) onChange(true);
      let released = false;
      return () => {
        if (released) return;
        released = true;
        holders -= 1;
        if (holders === 0) onChange(false);
      };
    },
  };
}
