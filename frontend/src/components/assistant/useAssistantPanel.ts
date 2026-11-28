import { type HTMLAttributes, type RefObject, useEffect, useLayoutEffect, useRef, useState } from "react";

import { assistantWidthBounds, clampAssistantWidth, DEFAULT_ASSISTANT_WIDTH, nextAssistantWidth } from "@/lib/assistantLayout";

const WIDTH_KEY = "verishield.assistant.width";
const WIDTH_PROPERTY = "--assistant-width";

interface PanelDrag {
  pointerId: number;
  panel: HTMLElement;
  handle: HTMLDivElement;
  startX: number;
  startWidth: number;
  latestX: number;
  paintedWidth: number;
  frame: number | null;
}

function releaseDrag(active: PanelDrag) {
  if (active.frame !== null) cancelAnimationFrame(active.frame);
  delete active.panel.dataset.resizing;
  delete document.documentElement.dataset.assistantResizing;
  if (active.handle.hasPointerCapture(active.pointerId)) active.handle.releasePointerCapture(active.pointerId);
}

export function useAssistantPanel(
  drawerRef: RefObject<HTMLElement | null>,
  canResize: boolean,
  suspendScroll: () => void,
  resumeScroll: (restore: boolean) => void,
) {
  const [preferredWidth, setPreferredWidth] = useState(DEFAULT_ASSISTANT_WIDTH);
  const [viewport, setViewport] = useState(1024);
  const viewportRef = useRef(1024);
  const drag = useRef<PanelDrag | null>(null);
  const enabled = canResize && viewport >= 640;

  useEffect(() => {
    const measure = () => {
      viewportRef.current = document.documentElement.clientWidth;
      setViewport(viewportRef.current);
    };
    measure();
    try {
      const saved = Number(localStorage.getItem(WIDTH_KEY));
      if (Number.isFinite(saved) && saved >= 400) setPreferredWidth(saved);
    } catch {
      setPreferredWidth(DEFAULT_ASSISTANT_WIDTH);
    }
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, []);

  useLayoutEffect(() => {
    if (!enabled) return;
    return () => {
      const active = drag.current;
      if (!active) return;
      drag.current = null;
      active.panel.style.setProperty(WIDTH_PROPERTY, `${active.startWidth}px`);
      releaseDrag(active);
      resumeScroll(false);
    };
  }, [enabled, resumeScroll]);

  const width = clampAssistantWidth(preferredWidth, viewport);
  const bounds = assistantWidthBounds(viewport);
  function remember(next: number) {
    setPreferredWidth(next);
    try { localStorage.setItem(WIDTH_KEY, String(next)); } catch { return; }
  }

  function paintWidth(active: PanelDrag) {
    const next = clampAssistantWidth(active.startWidth + active.startX - active.latestX, viewportRef.current);
    if (next !== active.paintedWidth) {
      active.panel.style.setProperty(WIDTH_PROPERTY, `${next}px`);
      active.paintedWidth = next;
    }
  }

  function finish(pointerId: number, finalX?: number) {
    const active = drag.current;
    if (!active || active.pointerId !== pointerId) return;
    drag.current = null;
    if (finalX !== undefined) active.latestX = finalX;
    paintWidth(active);
    releaseDrag(active);
    resumeScroll(true);
    if (active.paintedWidth !== active.startWidth) remember(active.paintedWidth);
  }

  const separator: HTMLAttributes<HTMLDivElement> = {
    role: "separator",
    tabIndex: 0,
    title: "Kéo hoặc dùng phím mũi tên để đổi chiều rộng; nhấp đúp để đặt lại",
    "aria-label": "Chiều rộng khung chat",
    "aria-orientation": "vertical",
    "aria-controls": "assistant-chat-panel",
    "aria-valuemin": bounds.min,
    "aria-valuemax": bounds.max,
    "aria-valuenow": width,
    "aria-valuetext": `${width} pixel`,
    onPointerDown(event) {
      const panel = drawerRef.current;
      if (!enabled || !panel || !event.isPrimary || event.button !== 0 || drag.current) return;
      event.preventDefault();
      const handle = event.currentTarget;
      handle.setPointerCapture(event.pointerId);
      suspendScroll();
      handle.focus({ preventScroll: true });
      drag.current = {
        pointerId: event.pointerId, panel, handle, startX: event.clientX, startWidth: width,
        latestX: event.clientX, paintedWidth: width, frame: null,
      };
      panel.dataset.resizing = "true";
      document.documentElement.dataset.assistantResizing = "true";
    },
    onPointerMove(event) {
      const active = drag.current;
      if (!active || active.pointerId !== event.pointerId) return;
      active.latestX = event.clientX;
      if (active.frame !== null) return;
      active.frame = requestAnimationFrame(() => {
        active.frame = null;
        paintWidth(active);
      });
    },
    onPointerUp: (event) => finish(event.pointerId, event.clientX),
    onPointerCancel: (event) => finish(event.pointerId),
    onLostPointerCapture: (event) => finish(event.pointerId),
    onDoubleClick: () => { if (!drag.current) remember(DEFAULT_ASSISTANT_WIDTH); },
    onKeyDown(event) {
      if (drag.current) return;
      const next = nextAssistantWidth(event.key, width, viewport);
      if (next === null) return;
      event.preventDefault();
      remember(event.key === "Enter" ? DEFAULT_ASSISTANT_WIDTH : next);
    },
  };

  return { width, mobile: viewport < 640, separator };
}
