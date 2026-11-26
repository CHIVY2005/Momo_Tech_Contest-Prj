"use client";

import {
  AlertCircle,
  FileAudio,
  FileCheck2,
  ImagePlus,
  Loader2,
  Upload,
  X,
} from "lucide-react";
import { type DragEvent, useEffect, useId, useRef, useState } from "react";

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

interface MediaKindConfig {
  acceptAttr: string;
  allowedExtensions: readonly string[];
  allowedMimePrefixes: readonly string[];
  formatsLabel: string;
  unsupportedMessage: string;
  accentBorderHover: string;
  accentDragBg: string;
  accentSelectedBorder: string;
  accentIconColor: string;
  Icon: typeof ImagePlus;
}

const MEDIA_CONFIGS: Record<"image" | "audio", MediaKindConfig> = {
  image: {
    acceptAttr: ".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp",
    allowedExtensions: [".jpg", ".jpeg", ".png", ".webp"],
    allowedMimePrefixes: ["image/jpeg", "image/png", "image/webp"],
    formatsLabel: "JPG, PNG, WebP · tối đa 10 MB",
    unsupportedMessage: "Định dạng chưa được hỗ trợ. Vui lòng chọn tệp ảnh JPG, PNG hoặc WebP.",
    accentBorderHover: "hover:border-amber-400/60",
    accentDragBg: "border-amber-400 bg-amber-500/10",
    accentSelectedBorder: "border-amber-400/55 bg-amber-500/10",
    accentIconColor: "text-amber-400",
    Icon: ImagePlus,
  },
  audio: {
    acceptAttr: ".wav,.mp3,.m4a,.ogg,audio/wav,audio/x-wav,audio/mpeg,audio/mp4,audio/x-m4a,audio/ogg",
    allowedExtensions: [".wav", ".mp3", ".m4a", ".ogg"],
    allowedMimePrefixes: [
      "audio/wav",
      "audio/x-wav",
      "audio/wave",
      "audio/mpeg",
      "audio/mp3",
      "audio/mp4",
      "audio/x-m4a",
      "audio/m4a",
      "audio/ogg",
    ],
    formatsLabel: "WAV, MP3, M4A, OGG · tối đa 10 MB",
    unsupportedMessage:
      "Định dạng chưa được hỗ trợ. Vui lòng chọn tệp âm thanh WAV, MP3, M4A hoặc OGG.",
    accentBorderHover: "hover:border-sky-400/60",
    accentDragBg: "border-sky-400 bg-sky-500/10",
    accentSelectedBorder: "border-sky-400/55 bg-sky-500/10",
    accentIconColor: "text-sky-400",
    Icon: FileAudio,
  },
};

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function validateSelectedFile(file: File, kind: "image" | "audio"): string | null {
  if (file.size <= 0) {
    return "Tệp không có dữ liệu. Vui lòng chọn tệp khác.";
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    return `Tệp "${file.name}" vượt quá dung lượng tối đa 10 MB. Vui lòng chọn tệp nhỏ hơn.`;
  }
  const cfg = MEDIA_CONFIGS[kind];
  const lowerName = file.name.toLowerCase();
  const extMatches = cfg.allowedExtensions.some((ext) => lowerName.endsWith(ext));
  const mime = (file.type || "").toLowerCase();
  const mimeMatches = mime !== "" && cfg.allowedMimePrefixes.includes(mime);
  if (!extMatches && !mimeMatches) {
    return cfg.unsupportedMessage;
  }
  return null;
}

interface MediaUploadZoneProps {
  kind: "image" | "audio";
  label: string;
  file: File | null;
  isUploading: boolean;
  onFileChange: (file: File | null) => void;
}

export function MediaUploadZone({
  kind,
  label,
  file,
  isUploading,
  onFileChange,
}: MediaUploadZoneProps) {
  const cfg = MEDIA_CONFIGS[kind];
  const Icon = cfg.Icon;
  const inputId = useId();
  const hintId = useId();
  const errorId = useId();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (file === null && inputRef.current) {
      inputRef.current.value = "";
    }
  }, [file]);

  function applyFile(candidate: File | null) {
    if (!candidate) {
      setError(null);
      onFileChange(null);
      return;
    }
    const validationErr = validateSelectedFile(candidate, kind);
    if (validationErr) {
      if (inputRef.current) {
        inputRef.current.value = "";
      }
      setError(validationErr);
      onFileChange(null);
      return;
    }
    setError(null);
    onFileChange(candidate);
  }

  function handleDragOver(ev: DragEvent<HTMLDivElement>) {
    ev.preventDefault();
    ev.stopPropagation();
    if (!isUploading) {
      setIsDragOver(true);
    }
  }

  function handleDragLeave(ev: DragEvent<HTMLDivElement>) {
    ev.preventDefault();
    ev.stopPropagation();
    const nextTarget = ev.relatedTarget as Node | null;
    if (!nextTarget || !ev.currentTarget.contains(nextTarget)) {
      setIsDragOver(false);
    }
  }

  function handleDrop(ev: DragEvent<HTMLDivElement>) {
    ev.preventDefault();
    ev.stopPropagation();
    setIsDragOver(false);
    if (isUploading) return;
    const dropped = ev.dataTransfer.files?.[0] ?? null;
    if (dropped) {
      applyFile(dropped);
    }
  }

  function handleRemove() {
    if (isUploading) return;
    setError(null);
    if (inputRef.current) {
      inputRef.current.value = "";
    }
    onFileChange(null);
  }

  const isSelected = file !== null;
  const isActivelyUploading = isUploading && isSelected;

  const containerStyle = error
    ? "border-rose-500/70 bg-rose-500/10"
    : isDragOver
      ? cfg.accentDragBg
      : isSelected
        ? cfg.accentSelectedBorder
        : `border-border-strong bg-surface-subtle ${cfg.accentBorderHover}`;

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <label htmlFor={inputId} className="text-xs font-semibold text-ink-secondary">
          {label}
        </label>
        <span id={hintId} className="text-[11px] text-ink-muted">
          {cfg.formatsLabel}
        </span>
      </div>

      <div
        onDragEnter={handleDragOver}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`relative rounded-xl border border-dashed p-3 transition-colors ${containerStyle}`}
      >
        <input
          ref={inputRef}
          id={inputId}
          type="file"
          accept={cfg.acceptAttr}
          disabled={isUploading}
          aria-describedby={error ? `${hintId} ${errorId}` : hintId}
          aria-invalid={Boolean(error)}
          onChange={(e) => applyFile(e.target.files?.[0] ?? null)}
          className="sr-only"
        />

        {isSelected && file ? (
          <div className="flex items-center justify-between gap-2.5">
            <div className="flex min-w-0 items-center gap-2.5">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border-subtle bg-surface">
                {isActivelyUploading ? (
                  <Loader2 className={`h-4 w-4 animate-spin ${cfg.accentIconColor}`} aria-hidden="true" />
                ) : (
                  <FileCheck2 className={`h-4 w-4 ${cfg.accentIconColor}`} aria-hidden="true" />
                )}
              </div>
              <div className="min-w-0">
                <p className="truncate text-xs font-semibold text-ink" title={file.name}>
                  {file.name}
                </p>
                <p className="tabular-num text-[11px] text-ink-muted">
                  {isActivelyUploading
                    ? "Đang tải và phân tích tệp..."
                    : formatFileSize(file.size)}
                </p>
              </div>
            </div>

            {!isUploading && (
              <div className="flex shrink-0 items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => inputRef.current?.click()}
                  className="min-h-[34px] cursor-pointer rounded-lg border border-border-strong bg-surface px-2.5 py-1 text-[11px] font-medium text-ink-secondary transition-colors hover:border-amber-400 hover:text-ink"
                >
                  Đổi tệp
                </button>
                <button
                  type="button"
                  onClick={handleRemove}
                  aria-label={`Xóa tệp ${file.name}`}
                  className="inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-lg border border-border-subtle bg-surface text-ink-muted transition-colors hover:border-rose-400/70 hover:text-rose-200"
                >
                  <X className="h-4 w-4" aria-hidden="true" />
                </button>
              </div>
            )}
          </div>
        ) : (
          <button
            type="button"
            disabled={isUploading}
            onClick={() => inputRef.current?.click()}
            className="flex min-h-[56px] w-full cursor-pointer items-center justify-between gap-3 rounded-lg text-left transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <div className="flex min-w-0 items-center gap-2.5">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border-subtle bg-surface">
                <Icon className={`h-4 w-4 ${cfg.accentIconColor}`} aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <p className="text-xs font-medium text-ink">
                  {isDragOver
                    ? "Thả tệp vào đây để đính kèm"
                    : "Kéo thả tệp vào đây hoặc chọn tệp"}
                </p>
                <p className="text-[11px] text-ink-muted">
                  {kind === "image"
                    ? "Hỗ trợ ảnh chụp màn hình, biên lai hoặc mã QR"
                    : "Hỗ trợ tệp ghi âm cuộc gọi đáng ngờ"}
                </p>
              </div>
            </div>
            <span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-border-strong bg-surface px-2.5 py-1.5 text-[11px] font-semibold text-ink-secondary">
              <Upload className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Chọn tệp</span>
            </span>
          </button>
        )}
      </div>

      {error && (
        <p
          id={errorId}
          role="alert"
          className="flex items-start gap-1.5 text-[11px] leading-snug text-rose-300"
        >
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </p>
      )}
    </div>
  );
}
