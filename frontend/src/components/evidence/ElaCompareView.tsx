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
      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
          <p className="text-[11px] text-ink-muted">Mức nghi vấn chỉnh sửa hình ảnh</p>
          <p className="tabular-num mt-0.5 font-mono text-base font-bold text-amber-300">
            {forensics.tamper_score}/100
          </p>
        </div>
        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
          <p className="text-[11px] text-ink-muted">Kích thước và định dạng tệp</p>
          <p className="tabular-num mt-0.5 font-mono text-xs font-semibold text-ink">
            {forensics.width}&times;{forensics.height} ({forensics.format})
          </p>
        </div>
      </div>

      {canCompare && originalPreviewUrl && elaSrc ? (
        <div className="space-y-3 rounded-xl border border-border-subtle bg-surface-subtle p-3.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-ink">
              <Layers className="h-4 w-4 text-amber-400" aria-hidden="true" />
              <span>So sánh ảnh gốc và vùng nghi vấn chỉnh sửa ({forensics.filename})</span>
            </div>
            <div
              role="group"
              aria-label="Chế độ so sánh hình ảnh"
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
                  alt={`Ảnh gốc đã tải lên ${forensics.filename}`}
                  className="max-h-[356px] w-full object-contain"
                />
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={elaSrc}
                  alt="Bản đồ làm nổi bật vùng nghi vấn chỉnh sửa hình ảnh"
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
                  Vùng bất thường
                </span>
              </div>

              <div className="flex items-center gap-3">
                <label htmlFor="ela-split-slider" className="shrink-0 text-[11px] font-medium text-ink-secondary">
                  Kéo để so sánh (hoặc dùng phím &larr;/&rarr;):
                </label>
                <input
                  id="ela-split-slider"
                  type="range"
                  min={0}
                  max={100}
                  value={splitPct}
                  onChange={(e) => setSplitPct(Number(e.target.value))}
                  aria-valuetext={`Hiển thị ${splitPct}% ảnh gốc và ${100 - splitPct}% bản đồ vùng bất thường`}
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
                  alt={`Ảnh gốc đã tải lên ${forensics.filename}`}
                  className="max-h-72 w-full rounded bg-surface-deep object-contain"
                />
              </figure>

              <figure className="rounded-lg border border-border-subtle bg-surface-deep p-2.5">
                <figcaption className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-amber-300">
                  <Layers className="h-4 w-4 text-amber-400" aria-hidden="true" />
                  <span>Bản đồ vùng có dấu hiệu chỉnh sửa</span>
                </figcaption>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={elaSrc}
                  alt="Bản đồ làm nổi bật các vùng nghi ngờ cắt ghép chữ số"
                  className="max-h-72 w-full rounded bg-surface-deep object-contain"
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
                <span>Ảnh gốc đã tải lên ({forensics.filename})</span>
              </figcaption>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={originalPreviewUrl}
                alt={`Ảnh gốc đã tải lên ${forensics.filename}`}
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
                <span>Bản đồ vùng có dấu hiệu chỉnh sửa ảnh</span>
              </figcaption>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={elaSrc}
                alt="Bản đồ làm nổi bật các vùng nghi ngờ cắt ghép chữ số"
                className="max-h-72 w-full rounded-lg bg-surface-deep object-contain"
              />
            </figure>
          )}
        </div>
      )}

      {/* Plain-language legend & limitations */}
      <div className="grid grid-cols-1 gap-2.5 rounded-xl border border-border-subtle bg-surface-subtle p-3.5 text-[11px] sm:grid-cols-2">
        <div>
          <p className="mb-1 flex items-center gap-1.5 font-semibold text-ink">
            <Info className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
            <span>Cách đọc bản đồ vùng bất thường</span>
          </p>
          <p className="leading-relaxed text-ink-secondary">
            Ảnh chụp màn hình bình thường có độ sáng tối khá đồng đều. Nếu có{" "}
            <strong className="text-amber-300">vùng sáng nổi bật bất thường</strong> quanh số tiền,
            tên người nhận hoặc logo, rất có thể vùng đó đã bị cắt ghép hoặc chỉnh sửa.
          </p>
        </div>
        <div className="border-t border-border-subtle pt-2.5 sm:border-t-0 sm:border-l sm:pt-0 sm:pl-3">
          <p className="mb-1 font-semibold text-amber-200">Lưu ý quan trọng</p>
          <p className="leading-relaxed text-ink-secondary">
            Ảnh gửi qua Zalo hoặc Messenger nhiều lần có thể bị giảm chất lượng và gây nhiễu.{" "}
            <strong>Mức nghi vấn thấp không phải là bằng chứng tiền đã vào tài khoản.</strong>
          </p>
        </div>
      </div>

      {forensics.ocr_text && (
        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3">
          <p className="mb-1 text-xs font-semibold text-ink-secondary">Văn bản đọc được từ ảnh</p>
          <pre data-lenis-prevent className="max-h-36 overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-ink-secondary">
            {forensics.ocr_text}
          </pre>
        </div>
      )}

      <details className="rounded-xl border border-border-subtle bg-surface-subtle/70 px-3.5 py-2.5 text-[11px]">
        <summary className="cursor-pointer font-medium text-ink-secondary hover:text-ink">
          Thông tin kỹ thuật phân tích hình ảnh
        </summary>
        <dl className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-3">
          <div>
            <dt className="text-ink-muted">Mã vân tay ảnh (Perceptual dHash)</dt>
            <dd className="tabular-num mt-0.5 truncate font-mono text-sky-300">
              {forensics.dhash_hex}
            </dd>
          </div>
          <div>
            <dt className="text-ink-muted">Độ lệch chiều cao chữ OCR (CV)</dt>
            <dd className="tabular-num mt-0.5 font-mono text-ink">
              {forensics.ocr_height_cv.toFixed(3)}
            </dd>
          </div>
          <div>
            <dt className="text-ink-muted">Phần mềm ghi nhận trong EXIF</dt>
            <dd className="mt-0.5 font-mono text-ink">
              {forensics.exif_software ?? "Không có"}
            </dd>
          </div>
          {forensics.ocr_provider && (
            <div>
              <dt className="text-ink-muted">Bộ máy trích xuất OCR</dt>
              <dd className="tabular-num mt-0.5 font-mono text-ink">
                {forensics.ocr_provider}
                {typeof forensics.ocr_confidence === "number" && forensics.ocr_confidence > 0
                  ? ` (${Math.round(forensics.ocr_confidence * 100)}%)`
                  : ""}
              </dd>
            </div>
          )}
        </dl>
        <p className="mt-2 text-ink-muted">
          Kỹ thuật áp dụng: Error Level Analysis (ELA), đối chiếu metadata EXIF và trích xuất ký tự
          ONNX (RapidOCR PP-OCRv5 Latin).
        </p>
      </details>
    </div>
  );
}
