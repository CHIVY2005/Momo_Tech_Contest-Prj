"use client";

import { Columns2, Eye, Info, Layers, SlidersHorizontal } from "lucide-react";
import { useState } from "react";

import type { ImageForensicsResult } from "@/lib/types";

interface ElaCompareViewProps {
  forensics: ImageForensicsResult;
  originalPreviewUrl: string | null;
}

export function ElaCompareView({ forensics, originalPreviewUrl }: ElaCompareViewProps) {
  const elaSrc = forensics.ela_heatmap_base64
    ? `data:image/png;base64,${forensics.ela_heatmap_base64}`
    : null;
  const canCompare = Boolean(originalPreviewUrl && elaSrc);
  const [viewMode, setViewMode] = useState<"slider" | "side-by-side">("slider");
  const [splitPct, setSplitPct] = useState<number>(52);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
          <p className="text-[11px] text-ink-muted">Điểm Nghi vấn Vật lý</p>
          <p className="tabular-num mt-0.5 font-mono text-base font-bold text-amber-300">
            {forensics.tamper_score}/100
          </p>
        </div>
        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
          <p className="text-[11px] text-ink-muted">Kích thước &amp; Định dạng</p>
          <p className="tabular-num mt-0.5 font-mono text-xs font-semibold text-ink">
            {forensics.width}&times;{forensics.height} ({forensics.format})
          </p>
        </div>
        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
          <p className="text-[11px] text-ink-muted">Perceptual dHash</p>
          <p className="tabular-num mt-0.5 truncate font-mono text-xs text-sky-300">
            {forensics.dhash_hex}
          </p>
        </div>
        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
          <p className="text-[11px] text-ink-muted">Độ lệch dòng chữ OCR (CV)</p>
          <p className="tabular-num mt-0.5 font-mono text-xs font-semibold text-ink">
            {forensics.ocr_height_cv.toFixed(3)}
            {forensics.exif_software ? ` · EXIF: ${forensics.exif_software}` : ""}
          </p>
        </div>
      </div>

      {canCompare && originalPreviewUrl && elaSrc ? (
        <div className="space-y-3 rounded-xl border border-border-subtle bg-surface-subtle p-3.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-ink">
              <Layers className="h-4 w-4 text-amber-400" aria-hidden="true" />
              <span>Đối chiếu Ảnh gốc &amp; Bản đồ nhiệt ELA ({forensics.filename})</span>
            </div>
            <div
              role="group"
              aria-label="Chế độ xem pháp y ELA"
              className="inline-flex rounded-lg border border-border-strong bg-surface-deep p-0.5 text-[11px]"
            >
              <button
                type="button"
                aria-pressed={viewMode === "slider"}
                onClick={() => setViewMode("slider")}
                className={`inline-flex min-h-[32px] cursor-pointer items-center gap-1 rounded-md px-2.5 py-1 font-medium transition-colors ${
                  viewMode === "slider"
                    ? "bg-amber-500/20 text-amber-200"
                    : "text-ink-muted hover:text-ink"
                }`}
              >
                <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Thanh kéo</span>
              </button>
              <button
                type="button"
                aria-pressed={viewMode === "side-by-side"}
                onClick={() => setViewMode("side-by-side")}
                className={`inline-flex min-h-[32px] cursor-pointer items-center gap-1 rounded-md px-2.5 py-1 font-medium transition-colors ${
                  viewMode === "side-by-side"
                    ? "bg-amber-500/20 text-amber-200"
                    : "text-ink-muted hover:text-ink"
                }`}
              >
                <Columns2 className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Song song</span>
              </button>
            </div>
          </div>

          {viewMode === "slider" ? (
            <div className="space-y-2.5">
              <div className="relative mx-auto flex min-h-[260px] max-h-[360px] w-full items-center justify-center overflow-hidden rounded-lg border border-border-subtle bg-surface-deep">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={originalPreviewUrl}
                  alt={`Ảnh gốc kiểm chứng ${forensics.filename}`}
                  className="max-h-[356px] w-full object-contain"
                />
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={elaSrc}
                  alt="Lớp bản đồ nhiệt Error Level Analysis phủ đối chiếu"
                  className="pointer-events-none absolute inset-0 h-full w-full object-contain"
                  style={{ clipPath: `inset(0 0 0 ${splitPct}%)` }}
                />
                <div
                  aria-hidden="true"
                  className="pointer-events-none absolute inset-y-0 w-0.5 bg-amber-400 shadow-[0_0_8px_rgba(245,158,11,0.9)]"
                  style={{ left: `${splitPct}%` }}
                />
                <span className="pointer-events-none absolute top-2 left-2 rounded bg-surface-deep/85 px-2 py-0.5 text-[10px] font-semibold text-ink">
                  Ảnh gốc
                </span>
                <span className="pointer-events-none absolute top-2 right-2 rounded bg-surface-deep/85 px-2 py-0.5 text-[10px] font-semibold text-amber-300">
                  Nhiệt ELA
                </span>
              </div>

              <div className="flex items-center gap-3">
                <label htmlFor="ela-split-slider" className="shrink-0 text-[11px] font-medium text-ink-secondary">
                  Kéo so sánh (hoặc dùng phím &larr;/&rarr;):
                </label>
                <input
                  id="ela-split-slider"
                  type="range"
                  min={0}
                  max={100}
                  value={splitPct}
                  onChange={(e) => setSplitPct(Number(e.target.value))}
                  aria-valuetext={`Hiển thị ${splitPct}% ảnh gốc và ${100 - splitPct}% bản đồ nhiệt ELA`}
                  className="h-2 flex-1 cursor-pointer accent-amber-400"
                />
                <span className="tabular-num w-10 text-right font-mono text-[11px] text-amber-300">
                  {splitPct}%
                </span>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <figure className="rounded-lg border border-border-subtle bg-surface-deep p-2.5">
                <figcaption className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-ink">
                  <Eye className="h-4 w-4 text-ink-muted" aria-hidden="true" />
                  <span>Ảnh gốc ({forensics.filename})</span>
                </figcaption>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={originalPreviewUrl}
                  alt={`Ảnh kiểm chứng ${forensics.filename}`}
                  className="max-h-72 w-full rounded object-contain bg-surface-deep"
                />
              </figure>

              <figure className="rounded-lg border border-border-subtle bg-surface-deep p-2.5">
                <figcaption className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-amber-300">
                  <Layers className="h-4 w-4 text-amber-400" aria-hidden="true" />
                  <span>Bản đồ Nhiệt ELA (Error Level Analysis)</span>
                </figcaption>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={elaSrc}
                  alt="Bản đồ nhiệt Error Level Analysis làm nổi bật vùng cắt ghép chữ số"
                  className="max-h-72 w-full rounded object-contain bg-surface-deep"
                />
              </figure>
            </div>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {originalPreviewUrl && (
            <figure className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
              <figcaption className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-ink">
                <Eye className="h-4 w-4 text-ink-muted" aria-hidden="true" />
                <span>Ảnh gốc người dùng cung cấp ({forensics.filename})</span>
              </figcaption>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={originalPreviewUrl}
                alt={`Ảnh kiểm chứng ${forensics.filename}`}
                className="max-h-72 w-full rounded-lg bg-surface-deep object-contain"
              />
            </figure>
          )}

          {elaSrc && (
            <figure
              className={`rounded-xl border border-border-subtle bg-surface-subtle p-3 ${
                !originalPreviewUrl ? "md:col-span-2" : ""
              }`}
            >
              <figcaption className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-amber-300">
                <Layers className="h-4 w-4 text-amber-400" aria-hidden="true" />
                <span>Bản đồ Nhiệt Sai số Nén JPEG (Error Level Analysis — ELA)</span>
              </figcaption>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={elaSrc}
                alt="Bản đồ nhiệt Error Level Analysis làm nổi bật vùng cắt ghép chữ số"
                className="max-h-72 w-full rounded-lg bg-surface-deep object-contain"
              />
            </figure>
          )}
        </div>
      )}

      {/* Plain-language ELA legend & technical limitations (Forensic UX + Merchant Honesty) */}
      <div className="grid grid-cols-1 gap-2.5 rounded-xl border border-border-subtle bg-surface-subtle p-3.5 text-[11px] sm:grid-cols-2">
        <div>
          <p className="mb-1 flex items-center gap-1.5 font-semibold text-ink">
            <Info className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
            <span>Cách đọc Bản đồ nhiệt ELA</span>
          </p>
          <p className="leading-relaxed text-ink-secondary">
            Ảnh chụp màn hình chưa chỉnh sửa thường có mật độ sáng tối đồng đều. Vùng{" "}
            <strong className="text-amber-300">phát sáng cục bộ bất thường</strong> quanh chữ số tiền,
            tên người nhận hoặc logo gợi ý vùng ảnh vừa bị chèn đè ở chu kỳ nén khác.
          </p>
        </div>
        <div className="border-t border-border-subtle pt-2.5 sm:border-t-0 sm:border-l sm:pt-0 sm:pl-3">
          <p className="mb-1 font-semibold text-amber-200">Giới hạn kỹ thuật (Không thay thế số dư)</p>
          <p className="leading-relaxed text-ink-secondary">
            ELA chỉ phát hiện bất thường nén/cắt ghép ảnh (nhiều lần nén qua Zalo/Messenger có thể làm
            nhiễu tín hiệu). <strong>Tuyệt đối không coi điểm ELA thấp là bằng chứng tiền đã vào tài khoản.</strong>
          </p>
        </div>
      </div>

      {forensics.ocr_text && (
        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
          <p className="mb-1 text-xs font-semibold text-ink-secondary">
            Văn bản trích xuất nội bộ (RapidOCR)
          </p>
          <pre className="max-h-36 overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-ink-secondary">
            {forensics.ocr_text}
          </pre>
        </div>
      )}
    </div>
  );
}
