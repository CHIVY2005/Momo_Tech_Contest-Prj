"use client";

import {
  ArrowRight,
  BarChart3,
  BookOpen,
  ExternalLink,
  FileSearch,
  Lock,
  Network,
  Radar,
  Search,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";
import { usePathname, useRouter } from "next/navigation";
import {
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";

import { useScrollLock } from "@/components/motion/SmoothScrollProvider";
import {
  buildPaletteCommands,
  COMMAND_GROUP_LABELS,
  COMMAND_PALETTE_PLACEHOLDER,
  type CommandNavDirection,
  computeMinimalScrollTop,
  filterPaletteCommands,
  getNextActiveCommandId,
  groupPaletteCommands,
  hasPointerMoved,
  type PaletteCommand,
  type PointerPoint,
  resolveActiveCommandId,
} from "@/lib/commandPalette";

const useIsomorphicLayoutEffect =
  typeof window !== "undefined" ? useLayoutEffect : useEffect;

type InteractionMode = "keyboard" | "pointer";

function CommandIcon({ id }: { id: string }) {
  const cls = "h-4 w-4 shrink-0";
  if (id === "new-analysis" || id === "nav-home") return <FileSearch className={`${cls} text-amber-400`} aria-hidden="true" />;
  if (id === "open-assistant") return <Sparkles className={`${cls} text-amber-300`} aria-hidden="true" />;
  if (id === "ws-xai") return <BarChart3 className={`${cls} text-sky-400`} aria-hidden="true" />;
  if (id === "ws-graph") return <Network className={`${cls} text-sky-400`} aria-hidden="true" />;
  if (id === "nav-radar") return <Radar className={`${cls} text-sky-400`} aria-hidden="true" />;
  if (id === "nav-privacy") return <Lock className={`${cls} text-emerald-400`} aria-hidden="true" />;
  if (id === "nav-technical" || id.startsWith("safety-")) return <BookOpen className={`${cls} text-ink-secondary`} aria-hidden="true" />;
  return <ShieldCheck className={`${cls} text-amber-400`} aria-hidden="true" />;
}

export function CommandPalette() {
  const router = useRouter();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeId, setActiveId] = useState<string | null>(null);
  const [scrollSync, setScrollSync] = useState<{ seq: number; snapToTop: boolean }>({
    seq: 0,
    snapToTop: false,
  });
  const [activeCaseState, setActiveCaseState] = useState<{
    hasActiveCase: boolean;
    maskedCaseId: string | null;
  }>({ hasActiveCase: false, maskedCaseId: null });

  const openRef = useRef(false);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const itemRefs = useRef<Map<string, HTMLButtonElement>>(new Map());
  const openerRef = useRef<HTMLElement | null>(null);
  const isComposingRef = useRef(false);

  const interactionModeRef = useRef<InteractionMode>("keyboard");
  const lastPointerPosRef = useRef<PointerPoint | null>(null);
  const ignoreHoverUntilNextFrameRef = useRef(false);
  const hoverGuardRafRef = useRef<number | null>(null);

  useEffect(() => {
    openRef.current = open;
  }, [open]);

  useScrollLock(open);

  const armKeyboardScrollGuard = useCallback(() => {
    ignoreHoverUntilNextFrameRef.current = true;
    if (hoverGuardRafRef.current !== null) {
      window.cancelAnimationFrame(hoverGuardRafRef.current);
    }
    hoverGuardRafRef.current = window.requestAnimationFrame(() => {
      hoverGuardRafRef.current = null;
      ignoreHoverUntilNextFrameRef.current = false;
    });
  }, []);

  useEffect(() => {
    return () => {
      if (hoverGuardRafRef.current !== null) {
        window.cancelAnimationFrame(hoverGuardRafRef.current);
      }
    };
  }, []);

  const openPalette = useCallback((opener: HTMLElement | null) => {
    openerRef.current = opener;
    interactionModeRef.current = "keyboard";
    lastPointerPosRef.current = null;
    isComposingRef.current = false;
    setQuery("");
    setActiveId(null);
    setScrollSync((prev) => ({ seq: prev.seq + 1, snapToTop: true }));
    setOpen(true);
  }, []);

  const closePalette = useCallback((opts?: { restoreFocus?: boolean }) => {
    const shouldRestoreFocus = opts?.restoreFocus ?? true;
    if (hoverGuardRafRef.current !== null) {
      window.cancelAnimationFrame(hoverGuardRafRef.current);
      hoverGuardRafRef.current = null;
    }
    ignoreHoverUntilNextFrameRef.current = false;
    isComposingRef.current = false;
    setOpen(false);
    setQuery("");
    setActiveId(null);
    if (shouldRestoreFocus) {
      window.requestAnimationFrame(() => {
        const opener = openerRef.current;
        if (opener && opener.isConnected && opener !== document.body) {
          opener.focus({ preventScroll: true });
        }
      });
    }
  }, []);

  // Sync non-sensitive active case indicator from HomePage (zero PII)
  useEffect(() => {
    function handleCaseChange(ev: Event) {
      const detail = (
        ev as CustomEvent<{ hasActiveCase?: boolean; maskedCaseId?: string | null }>
      ).detail;
      setActiveCaseState({
        hasActiveCase: Boolean(detail?.hasActiveCase),
        maskedCaseId: detail?.maskedCaseId ?? null,
      });
    }
    window.addEventListener("verishield:active-case-changed", handleCaseChange);
    return () => window.removeEventListener("verishield:active-case-changed", handleCaseChange);
  }, []);

  // Global Ctrl+K / Cmd+K and custom open trigger
  useEffect(() => {
    function handleGlobalKeyDown(ev: globalThis.KeyboardEvent) {
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k" && !ev.altKey) {
        ev.preventDefault();
        if (openRef.current) {
          closePalette({ restoreFocus: true });
        } else {
          const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
          openPalette(opener);
        }
      }
    }

    function handleCustomOpen(ev: Event) {
      const detailOpener = (ev as CustomEvent<{ opener?: HTMLElement | null }>).detail?.opener;
      const opener =
        detailOpener instanceof HTMLElement
          ? detailOpener
          : document.activeElement instanceof HTMLElement
            ? document.activeElement
            : null;
      openPalette(opener);
    }

    window.addEventListener("keydown", handleGlobalKeyDown);
    window.addEventListener("verishield:open-command-palette", handleCustomOpen);
    return () => {
      window.removeEventListener("keydown", handleGlobalKeyDown);
      window.removeEventListener("verishield:open-command-palette", handleCustomOpen);
    };
  }, [closePalette, openPalette]);

  // Autofocus search input when palette opens without scrolling the background page
  useEffect(() => {
    if (!open) return;
    const raf = window.requestAnimationFrame(() => {
      inputRef.current?.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(raf);
  }, [open]);

  const allCommands = useMemo(
    () =>
      buildPaletteCommands({
        hasActiveCase: activeCaseState.hasActiveCase,
        maskedCaseId: activeCaseState.maskedCaseId,
        pathname,
      }),
    [activeCaseState.hasActiveCase, activeCaseState.maskedCaseId, pathname],
  );

  const filtered = useMemo(
    () => filterPaletteCommands(allCommands, query),
    [allCommands, query],
  );

  const { groups: grouped, flat: flatOrdered } = useMemo(
    () => groupPaletteCommands(filtered),
    [filtered],
  );

  const firstEnabledId = useMemo(
    () => resolveActiveCommandId(flatOrdered, null),
    [flatOrdered],
  );

  // Single source of truth: synchronously resolved so it can never go stale or out-of-bounds
  const resolvedActiveId = useMemo(
    () => resolveActiveCommandId(flatOrdered, activeId),
    [flatOrdered, activeId],
  );

  const activeItem = useMemo(
    () => (resolvedActiveId ? flatOrdered.find((cmd) => cmd.id === resolvedActiveId) ?? null : null),
    [flatOrdered, resolvedActiveId],
  );

  // Synchronize scroll container position instantaneously before paint on keyboard nav or query reset
  useIsomorphicLayoutEffect(() => {
    if (!open || scrollSync.seq === 0) return;
    const listEl = listRef.current;
    if (!listEl) return;

    if (!resolvedActiveId) {
      if (listEl.scrollTop !== 0) {
        armKeyboardScrollGuard();
        listEl.scrollTop = 0;
      }
      return;
    }

    const itemEl = itemRefs.current.get(resolvedActiveId);
    if (!itemEl) return;

    const listRect = listEl.getBoundingClientRect();
    const itemRect = itemEl.getBoundingClientRect();
    const computedStyle = window.getComputedStyle(listEl);
    const paddingTop = Number.parseFloat(computedStyle.paddingTop) || 0;
    const paddingBottom = Number.parseFloat(computedStyle.paddingBottom) || 0;

    const nextScrollTop = computeMinimalScrollTop({
      containerTop: listRect.top,
      containerBottom: listRect.bottom,
      scrollTop: listEl.scrollTop,
      scrollHeight: listEl.scrollHeight,
      clientHeight: listEl.clientHeight,
      itemTop: itemRect.top,
      itemBottom: itemRect.bottom,
      paddingTop,
      paddingBottom,
      snapToTop: scrollSync.snapToTop || resolvedActiveId === firstEnabledId,
    });

    if (nextScrollTop !== listEl.scrollTop) {
      armKeyboardScrollGuard();
      listEl.scrollTop = nextScrollTop;
    }
  }, [open, resolvedActiveId, firstEnabledId, scrollSync, armKeyboardScrollGuard]);

  const executeCommand = useCallback(
    (cmd: PaletteCommand) => {
      if (cmd.disabled) return;
      if (cmd.action.type === "navigate") {
        closePalette({ restoreFocus: false });
        router.push(cmd.action.href);
        return;
      }
      if (cmd.action.type === "external_official") {
        closePalette({ restoreFocus: true });
        window.open(cmd.action.href, "_blank", "noopener,noreferrer");
        return;
      }
      closePalette({ restoreFocus: false });
      window.dispatchEvent(new CustomEvent(cmd.action.name, { detail: cmd.action.detail }));
    },
    [closePalette, router],
  );

  const navigateSelection = useCallback(
    (direction: CommandNavDirection) => {
      const nextId = getNextActiveCommandId(flatOrdered, resolvedActiveId, direction);
      if (nextId === null) return;
      interactionModeRef.current = "keyboard";
      armKeyboardScrollGuard();
      setActiveId(nextId);
      setScrollSync((prev) => ({
        seq: prev.seq + 1,
        snapToTop: direction === "first" || nextId === firstEnabledId,
      }));
    },
    [flatOrdered, resolvedActiveId, firstEnabledId, armKeyboardScrollGuard],
  );

  function handleQueryChange(nextQuery: string) {
    interactionModeRef.current = "keyboard";
    setQuery(nextQuery);
    setActiveId(null);
    setScrollSync((prev) => ({ seq: prev.seq + 1, snapToTop: true }));
  }

  function handleKeyDown(ev: KeyboardEvent<HTMLDivElement>) {
    // Never interrupt Vietnamese or CJK IME composition
    if (isComposingRef.current || ev.nativeEvent.isComposing || ev.key === "Process") {
      return;
    }

    if (ev.key === "Escape") {
      ev.preventDefault();
      ev.stopPropagation();
      closePalette({ restoreFocus: true });
      return;
    }

    // Keep keyboard focus trapped inside the modal dialog (input <-> close button)
    if (ev.key === "Tab") {
      const inputEl = inputRef.current;
      const closeEl = closeButtonRef.current;
      if (inputEl && closeEl) {
        if (ev.shiftKey && document.activeElement === inputEl) {
          ev.preventDefault();
          closeEl.focus({ preventScroll: true });
        } else if (!ev.shiftKey && document.activeElement === closeEl) {
          ev.preventDefault();
          inputEl.focus({ preventScroll: true });
        }
      }
      return;
    }

    if (ev.altKey || ev.ctrlKey || ev.metaKey) {
      return;
    }

    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      if (document.activeElement !== inputRef.current) {
        inputRef.current?.focus({ preventScroll: true });
      }
      navigateSelection("next");
      return;
    }

    if (ev.key === "ArrowUp") {
      ev.preventDefault();
      if (document.activeElement !== inputRef.current) {
        inputRef.current?.focus({ preventScroll: true });
      }
      navigateSelection("prev");
      return;
    }

    if (ev.key === "Home" && !ev.shiftKey) {
      ev.preventDefault();
      if (document.activeElement !== inputRef.current) {
        inputRef.current?.focus({ preventScroll: true });
      }
      navigateSelection("first");
      return;
    }

    if (ev.key === "End" && !ev.shiftKey) {
      ev.preventDefault();
      if (document.activeElement !== inputRef.current) {
        inputRef.current?.focus({ preventScroll: true });
      }
      navigateSelection("last");
      return;
    }

    if (ev.key === "Enter") {
      // Allow Enter on the explicit Close button to activate it rather than executing a command
      if (ev.target === closeButtonRef.current) {
        return;
      }
      ev.preventDefault();
      if (activeItem && !activeItem.disabled) {
        executeCommand(activeItem);
      }
    }
  }

  function handleItemPointerMove(
    ev: ReactPointerEvent<HTMLButtonElement>,
    cmd: PaletteCommand,
  ) {
    if (cmd.disabled || ev.pointerType !== "mouse") return;
    const nextPoint: PointerPoint = { x: ev.clientX, y: ev.clientY };

    if (interactionModeRef.current === "keyboard") {
      if (ignoreHoverUntilNextFrameRef.current) {
        lastPointerPosRef.current = nextPoint;
        return;
      }
      if (
        lastPointerPosRef.current !== null &&
        !hasPointerMoved(lastPointerPosRef.current, nextPoint)
      ) {
        return;
      }
      interactionModeRef.current = "pointer";
    }

    lastPointerPosRef.current = nextPoint;
    if (resolvedActiveId !== cmd.id) {
      setActiveId(cmd.id);
    }
  }

  function handleItemPointerEnter(
    ev: ReactPointerEvent<HTMLButtonElement>,
    cmd: PaletteCommand,
  ) {
    if (cmd.disabled || ev.pointerType !== "mouse") return;
    if (interactionModeRef.current !== "pointer") return;
    lastPointerPosRef.current = { x: ev.clientX, y: ev.clientY };
    if (resolvedActiveId !== cmd.id) {
      setActiveId(cmd.id);
    }
  }

  function handleListScroll() {
    if (interactionModeRef.current === "keyboard") {
      armKeyboardScrollGuard();
    }
  }

  if (!open || typeof document === "undefined") {
    return null;
  }

  return createPortal(
    <div
      className="fixed inset-0 z-[80] flex items-start justify-center px-3 py-4 sm:px-4 sm:py-[10vh]"
      onKeyDown={handleKeyDown}
    >
      <div
        aria-hidden="true"
        onClick={() => closePalette({ restoreFocus: true })}
        className="fixed inset-0 bg-slate-950/75 backdrop-blur-xs"
      />

      <div
        role="dialog"
        aria-modal="true"
        aria-label="Bảng lệnh điều hướng nhanh VeriShield"
        className="relative z-10 flex max-h-[min(100%,520px)] w-full max-w-xl flex-col overflow-hidden rounded-2xl border border-border-strong bg-surface shadow-2xl"
      >
        {/* Fixed Search Input Header */}
        <div className="flex shrink-0 items-center gap-2 border-b border-border-subtle px-3 py-2.5 sm:px-3.5">
          <div className="vs-palette-search-field flex min-w-0 flex-1 items-center gap-2.5 rounded-xl border border-border-subtle/80 bg-surface-deep/65 px-3 py-2">
            <Search className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
            <input
              ref={inputRef}
              type="text"
              role="combobox"
              aria-autocomplete="list"
              aria-haspopup="listbox"
              aria-expanded={open}
              aria-controls="vs-command-listbox"
              aria-activedescendant={activeItem ? `vs-cmd-${activeItem.id}` : undefined}
              aria-label="Tìm kiếm lệnh hoặc chức năng"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              value={query}
              onCompositionStart={() => {
                isComposingRef.current = true;
              }}
              onCompositionEnd={() => {
                isComposingRef.current = false;
              }}
              onChange={(e) => handleQueryChange(e.target.value)}
              placeholder={COMMAND_PALETTE_PLACEHOLDER}
              className="vs-palette-input min-w-0 flex-1 bg-transparent text-sm text-ink placeholder:text-ink-muted"
            />
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            onClick={() => closePalette({ restoreFocus: true })}
            aria-label="Đóng bảng lệnh nhanh"
            className="inline-flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-xl border border-border-subtle bg-surface-subtle text-ink-muted transition-colors hover:border-border-strong hover:text-ink"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        {/* Scrollable Command List */}
        <div
          ref={listRef}
          id="vs-command-listbox"
          role="listbox"
          data-lenis-prevent
          aria-label="Danh sách lệnh khả dụng"
          onScroll={handleListScroll}
          className="vs-palette-list min-h-0 flex-1 overflow-x-hidden overflow-y-auto overscroll-contain p-2"
        >
          {grouped.length === 0 ? (
            <p className="px-3 py-8 text-center text-xs text-ink-muted">
              Không tìm thấy lệnh phù hợp với &ldquo;{query}&rdquo;.
            </p>
          ) : (
            grouped.map(({ group, items }) => {
              const groupLabelId = `vs-cmd-group-${group}`;
              return (
                <div
                  key={group}
                  role="group"
                  aria-labelledby={groupLabelId}
                  className="mb-2 last:mb-0"
                >
                  <div
                    id={groupLabelId}
                    role="presentation"
                    className="px-2.5 py-1.5 text-[10px] font-bold tracking-wider text-ink-muted uppercase select-none"
                  >
                    {COMMAND_GROUP_LABELS[group]}
                  </div>
                  <div className="space-y-0.5">
                    {items.map((cmd) => {
                      const isDisabled = Boolean(cmd.disabled);
                      const isSelected = !isDisabled && cmd.id === resolvedActiveId;
                      return (
                        <button
                          key={cmd.id}
                          ref={(node) => {
                            if (node) {
                              itemRefs.current.set(cmd.id, node);
                            } else {
                              itemRefs.current.delete(cmd.id);
                            }
                          }}
                          id={`vs-cmd-${cmd.id}`}
                          type="button"
                          role="option"
                          tabIndex={-1}
                          disabled={isDisabled}
                          aria-disabled={isDisabled || undefined}
                          aria-selected={isSelected}
                          onMouseDown={(ev) => ev.preventDefault()}
                          onPointerMove={(ev) => handleItemPointerMove(ev, cmd)}
                          onPointerEnter={(ev) => handleItemPointerEnter(ev, cmd)}
                          onClick={() => executeCommand(cmd)}
                          className={`flex w-full items-center justify-between gap-3 rounded-xl px-3 py-2.5 text-left ${
                            isDisabled
                              ? "cursor-not-allowed opacity-45 text-ink-muted"
                              : isSelected
                                ? "cursor-pointer bg-amber-500/15 text-ink ring-1 ring-inset ring-amber-400/25"
                                : "cursor-pointer text-ink-secondary"
                          }`}
                        >
                          <div className="flex min-w-0 items-start gap-2.5">
                            <span className="mt-0.5">
                              <CommandIcon id={cmd.id} />
                            </span>
                            <div className="min-w-0">
                              <p className="truncate text-xs font-semibold text-ink">{cmd.label}</p>
                              <p className="truncate text-[11px] text-ink-muted">{cmd.description}</p>
                            </div>
                          </div>
                          {cmd.action.type === "external_official" ? (
                            <ExternalLink
                              className="h-3.5 w-3.5 shrink-0 text-sky-400"
                              aria-hidden="true"
                            />
                          ) : (
                            <ArrowRight
                              className={`h-3.5 w-3.5 shrink-0 ${
                                isSelected ? "text-amber-300" : "text-ink-muted/60"
                              }`}
                              aria-hidden="true"
                            />
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Fixed Keyboard Shortcuts Footer */}
        <footer className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-border-subtle bg-surface-subtle/90 px-4 py-2 text-[10.5px] text-ink-muted">
          <div className="flex items-center gap-3">
            <span>
              <kbd className="rounded border border-border-strong bg-surface px-1 py-0.5 font-mono text-[10px] text-ink-secondary">
                ↑↓
              </kbd>{" "}
              di chuyển
            </span>
            <span>
              <kbd className="rounded border border-border-strong bg-surface px-1 py-0.5 font-mono text-[10px] text-ink-secondary">
                Enter
              </kbd>{" "}
              chọn
            </span>
            <span>
              <kbd className="rounded border border-border-strong bg-surface px-1 py-0.5 font-mono text-[10px] text-ink-secondary">
                Esc
              </kbd>{" "}
              đóng
            </span>
          </div>
          <span>Không hiển thị dữ liệu nhạy cảm từ hồ sơ khác</span>
        </footer>
      </div>
    </div>,
    document.body,
  );
}
