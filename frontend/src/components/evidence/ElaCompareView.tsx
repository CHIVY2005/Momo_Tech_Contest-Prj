"use client";

import { Eye, Layers } from "lucide-react";

import type { ImageForensicsResult } from "@/lib/types";

interface ElaCompareViewProps {
  forensics: ImageForensicsResult;
  originalPreviewUrl: string | null;
}

export function ElaCompareView({ forensics, originalPreviewUrl }: ElaCompareViewProps) {
  const elaSrc = forensics.ela_heatmap_base64
    ? `data:image/png;base64,${forensics.ela_heatmap_base64}`
    : null;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-3">
          <p className="text-[11px] text-slate-400">Điểm Nghi vấn Vật lý</p>
          <p className="mt-0.5 font-[family-name:var(--font-mono)] text-base font-bold text-amber-300">
            {forensics.tamper_score}/100
          </p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-3">
          <p className="text-[11px] text-slate-400">Kích thước &amp; Định dạng</p>
          <p className="mt-0.5 font-[family-name:var(--font-mono)] text-xs font-semibold text-slate-200">
            {forensics.width}&times;{forensics.height} ({forensics.format})
          </p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-3">
          <p className="text-[11px] text-slate-400">Perceptual dHash</p>
          <p className="mt-0.5 truncate font-[family-name:var(--font-mono)] text-xs text-sky-300">
            {forensics.dhash_hex}
          </p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-3">
          <p className="text-[11px] text-slate-400">Độ lệch dòng chữ OCR (CV)</p>
          <p className="mt-0.5 font-[family-name:var(--font-mono)] text-xs font-semibold text-slate-200">
            {forensics.ocr_height_cv.toFixed(3)}
            {forensics.exif_software ? ` · EXIF: ${forensics.exif_software}` : ""}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {originalPreviewUrl && (
          <figure className="rounded-xl border border-slate-800 bg-[#0b1120] p-3">
            <figcaption className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-slate-200">
              <Eye className="h-4 w-4 text-slate-400" aria-hidden="true" />
              <span>Ảnh gốc người dùng cung cấp ({forensics.filename})</span>
            </figcaption>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={originalPreviewUrl}
              alt={`Ảnh kiểm chứng ${forensics.filename}`}
              className="max-h-72 w-full rounded-lg object-contain bg-slate-950"
            />
          </figure>
        )}

        {elaSrc && (
          <figure className="rounded-xl border border-slate-800 bg-[#0b1120] p-3">
            <figcaption className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-amber-300">
              <Layers className="h-4 w-4 text-amber-400" aria-hidden="true" />
              <span>Bản đồ Nhiệt Sai số Nén JPEG (Error Level Analysis — ELA)</span>
            </figcaption>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={elaSrc}
              alt="Bản đồ nhiệt Error Level Analysis làm nổi bật vùng cắt ghép chữ số"
              className="max-h-72 w-full rounded-lg object-contain bg-slate-950"
            />
          </figure>
        )}
      </div>

      {forensics.ocr_text && (
        <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-3">
          <p className="mb-1 text-xs font-semibold text-slate-300">
            Văn bản trích xuất nội bộ (RapidOCR)
          </p>
          <pre className="max-h-36 overflow-auto whitespace-pre-wrap font-[family-name:var(--font-mono)] text-[11px] leading-relaxed text-slate-300">
            {forensics.ocr_text}
          </pre>
        </div>
      )}
    </div>
  );
}
