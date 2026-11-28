"use client";

import {
  Layers,
  Maximize2,
  RotateCcw,
  X,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import { type PointerEvent, useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import { useScrollLock } from "@/components/motion/SmoothScrollProvider";

export interface LightboxMetadataItem {
  label: string;
  value: string;
}

interface EvidenceImageLightboxProps {
  open: boolean;
  title: string;
  imageUrl: string;
  overlayUrl?: string | null;
  overlayLabel?: string;
  metadata?: LightboxMetadataItem[];
  onClose: () => void;
}

const MIN_ZOOM = 0.5;
const MAX_ZOOM = 4;

export function EvidenceImageLightbox({
  open,
  title,
  imageUrl,
  overlayUrl = null,
  overlayLabel = "Lớp vùng bất thường (ELA)",
  metadata = [],
  onClose,
}: EvidenceImageLightboxProps) {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [overlayOpacity, setOverlayOpacity] = useState(0);
  const [dragging, setDragging] = useState(false);
  const dragOriginRef = useRef<{ clientX: number; clientY: number; startX: number; startY: number } | null>(null);
  const closeBtnRef = useRef<HTMLButtonElement | null>(null);

  useScrollLock(open);

  const resetView = useCallback(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, []);

  useEffect(() => {
    if (!open) return;
    resetView();
    setOverlayOpacity(0);
    const raf = window.requestAnimationFrame(() => closeBtnRef.current?.focus());
    return () => window.cancelAnimationFrame(raf);
  }, [open, imageUrl, resetView]);

  useEffect(() => {
    if (!open) return;
    function handleKey(ev: KeyboardEvent) {
      if (ev.key === "Escape") {
        ev.preventDefault();
        onClose();
      } else if (ev.key === "+" || ev.key === "=") {
        ev.preventDefault();
        setZoom((z) => Math.min(MAX_ZOOM, Number((z + 0.25).toFixed(2))));
      } else if (ev.key === "-") {
        ev.preventDefault();
        setZoom((z) => Math.max(MIN_ZOOM, Number((z - 0.25).toFixed(2))));
      } else if (ev.key === "0") {
        ev.preventDefault();
        resetView();
      }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [open, onClose, resetView]);

  if (!open || typeof document === "undefined") {
    return null;
  }

  function handlePointerDown(ev: PointerEvent<HTMLDivElement>) {
    if (ev.button !== 0) return;
    ev.currentTarget.setPointerCapture(ev.pointerId);
    setDragging(true);
    dragOriginRef.current = {
      clientX: ev.clientX,
      clientY: ev.clientY,
      startX: pan.x,
      startY: pan.y,
    };
  }

  function handlePointerMove(ev: PointerEvent<HTMLDivElement>) {
    if (!dragging || !dragOriginRef.current) return;
    const origin = dragOriginRef.current;
    setPan({
      x: origin.startX + (ev.clientX - origin.clientX),
      y: origin.startY + (ev.clientY - origin.clientY),
    });
  }

  function handlePointerEnd(ev: PointerEvent<HTMLDivElement>) {
    if (!dragging) return;
    setDragging(false);
    dragOriginRef.current = null;
    if (ev.currentTarget.hasPointerCapture(ev.pointerId)) {
      ev.currentTarget.releasePointerCapture(ev.pointerId);
    }
  }

  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Xem phóng to bằng chứng: ${title}`}
      className="fixed inset-0 z-[70] flex flex-col bg-slate-950/92 backdrop-blur-xs"
    >
      {/* Lightbox Top Bar */}
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle bg-surface px-4 py-3">
        <div className="flex min-w-0 items-center gap-2">
          <Maximize2 className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
          <h2 className="truncate text-xs font-bold text-ink sm:text-sm">{title}</h2>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <div
            role="group"
            aria-label="Điều khiển thu phóng ảnh"
            className="inline-flex items-center rounded-lg border border-border-strong bg-surface-deep p-0.5 text-xs"
          >
            <button
              type="button"
              onClick={() => setZoom((z) => Math.max(MIN_ZOOM, Number((z - 0.25).toFixed(2))))}
              aria-label="Thu nhỏ ảnh"
              className="inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-md text-ink-secondary hover:bg-surface-subtle hover:text-ink"
            >
              <ZoomOut className="h-4 w-4" aria-hidden="true" />
            </button>
            <span className="tabular-num min-w-[48px] text-center font-mono text-[11px] font-semibold text-ink">
              {Math.round(zoom * 100)}%
            </span>
            <button
              type="button"
              onClick={() => setZoom((z) => Math.min(MAX_ZOOM, Number((z + 0.25).toFixed(2))))}
              aria-label="Phóng to ảnh"
              className="inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-md text-ink-secondary hover:bg-surface-subtle hover:text-ink"
            >
              <ZoomIn className="h-4 w-4" aria-hidden="true" />
            </button>
            <button
              type="button"
              onClick={resetView}
              aria-label="Đặt lại khung nhìn ảnh"
              title="Đặt lại (phím 0)"
              className="inline-flex h-8 cursor-pointer items-center gap-1 rounded-md px-2 text-[11px] text-ink-secondary hover:bg-surface-subtle hover:text-ink"
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">Đặt lại</span>
            </button>
          </div>

          {overlayUrl && (
            <div className="flex items-center gap-2 rounded-lg border border-border-strong bg-surface-deep px-2.5 py-1 text-[11px]">
              <Layers className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
              <label htmlFor="lightbox-ela-opacity" className="hidden text-ink-secondary md:inline">
                {overlayLabel}
              </label>
              <input
                id="lightbox-ela-opacity"
                type="range"
                min={0}
                max={100}
                value={overlayOpacity}
                onChange={(e) => setOverlayOpacity(Number(e.target.value))}
                aria-label="Độ phủ bản đồ vùng bất thường ELA"
                className="w-20 cursor-pointer accent-amber-400"
              />
              <span className="tabular-num w-8 font-mono text-[10px] text-amber-300">
                {overlayOpacity}%
              </span>
            </div>
          )}

          <button
            ref={closeBtnRef}
            type="button"
            onClick={onClose}
            aria-label="Đóng xem phóng to"
            className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-lg border border-border-strong bg-surface-subtle text-ink-secondary hover:border-amber-400 hover:text-ink"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      </header>

      {/* Interactive Zoom & Pan Canvas */}
      <div
        data-lenis-prevent-wheel
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerEnd}
        onPointerCancel={handlePointerEnd}
        onWheel={(ev) => {
          ev.preventDefault();
          const delta = ev.deltaY < 0 ? 0.2 : -0.2;
          setZoom((z) => Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, Number((z + delta).toFixed(2)))));
        }}
        className={`relative flex min-h-0 flex-1 items-center justify-center overflow-hidden p-4 select-none ${
          dragging ? "cursor-grabbing" : "cursor-grab"
        }`}
      >
        <div
          style={{
            transform: `translate3d(${pan.x}px, ${pan.y}px, 0) scale(${zoom})`,
          }}
          className="relative max-h-full max-w-full will-change-transform"
        >
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={imageUrl}
            alt={title}
            draggable={false}
            className="max-h-[72vh] max-w-[88vw] rounded-lg border border-border-subtle bg-surface-deep object-contain"
          />
          {overlayUrl && overlayOpacity > 0 && (
            /* eslint-disable-next-line @next/next/no-img-element */
            <img
              src={overlayUrl}
              alt={overlayLabel}
              draggable={false}
              style={{ opacity: overlayOpacity / 100 }}
              className="pointer-events-none absolute inset-0 h-full w-full rounded-lg object-contain"
            />
          )}
        </div>
      </div>

      {/* Metadata Strip */}
      {metadata.length > 0 && (
        <footer className="border-t border-border-subtle bg-surface px-4 py-2.5">
          <dl className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-[11px]">
            {metadata.map((item) => (
              <div key={item.label} className="flex items-center gap-1.5">
                <dt className="text-ink-muted">{item.label}:</dt>
                <dd className="tabular-num font-mono font-semibold text-ink">{item.value}</dd>
              </div>
            ))}
          </dl>
        </footer>
      )}
    </div>,
    document.body,
  );
}
