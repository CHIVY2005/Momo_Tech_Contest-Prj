"use client";

import {
  AlertCircle,
  ClipboardPaste,
  FileAudio,
  ImagePlus,
  Link2,
  Loader2,
  ScanSearch,
  Upload,
  X,
} from "lucide-react";
import {
  type ClipboardEvent,
  type DragEvent,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  ATTACHMENT_LIMITS,
  extractClipboardImages,
  extractUrlsFromText,
  formatAttachmentSize,
  validateAttachmentBatch,
} from "@/lib/composerUtils";

interface MultimodalComposerProps {
  text: string;
  imageFiles: File[];
  audioFiles: File[];
  isAnalyzing: boolean;
  onTextChange: (nextText: string) => void;
  onAttachmentsChange: (nextImages: File[], nextAudios: File[]) => void;
}

const IMAGE_ACCEPT = ".jpg,.jpeg,.png,.webp,.gif,image/jpeg,image/png,image/webp,image/gif";
const AUDIO_ACCEPT =
  ".wav,.mp3,.m4a,.ogg,.webm,audio/wav,audio/x-wav,audio/mpeg,audio/mp4,audio/x-m4a,audio/ogg,audio/webm";

export function MultimodalComposer({
  text,
  imageFiles,
  audioFiles,
  isAnalyzing,
  onTextChange,
  onAttachmentsChange,
}: MultimodalComposerProps) {
  const textareaId = useId();
  const errorId = useId();
  const imageInputRef = useRef<HTMLInputElement | null>(null);
  const audioInputRef = useRef<HTMLInputElement | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [attachError, setAttachError] = useState<string | null>(null);
  const [pasteNotice, setPasteNotice] = useState<string | null>(null);
  const [previewEntries, setPreviewEntries] = useState<Array<{ file: File; url: string }>>([]);

  useEffect(() => {
    const created = imageFiles.map((file) => ({
      file,
      url: URL.createObjectURL(file),
    }));
    setPreviewEntries(created);
    return () => {
      for (const entry of created) {
        URL.revokeObjectURL(entry.url);
      }
    };
  }, [imageFiles]);

  useEffect(() => {
    if (!pasteNotice) return;
    const timer = window.setTimeout(() => setPasteNotice(null), 3200);
    return () => window.clearTimeout(timer);
  }, [pasteNotice]);

  const detectedUrls = useMemo(() => extractUrlsFromText(text), [text]);
  const totalBytes = useMemo(
    () =>
      imageFiles.reduce((acc, f) => acc + f.size, 0) +
      audioFiles.reduce((acc, f) => acc + f.size, 0),
    [imageFiles, audioFiles],
  );

  function mergeIncomingFiles(incoming: File[], sourceLabel?: string) {
    if (incoming.length === 0 || isAnalyzing) return;
    const res = validateAttachmentBatch(imageFiles, audioFiles, incoming);
    if (res.errors.length > 0) {
      setAttachError(res.errors[0] ?? null);
    } else {
      setAttachError(null);
    }
    if (res.acceptedImages.length > 0 || res.acceptedAudios.length > 0) {
      onAttachmentsChange(
        [...imageFiles, ...res.acceptedImages],
        [...audioFiles, ...res.acceptedAudios],
      );
      if (sourceLabel === "clipboard" && res.acceptedImages.length > 0) {
        setPasteNotice(
          res.acceptedImages.length === 1
            ? "Đã dán 1 hình ảnh từ bộ nhớ tạm."
            : `Đã dán ${res.acceptedImages.length} hình ảnh từ bộ nhớ tạm.`,
        );
      }
    }
  }

  function handlePaste(ev: ClipboardEvent<HTMLDivElement | HTMLTextAreaElement>) {
    if (isAnalyzing) return;
    const { images, hasPlainText } = extractClipboardImages(ev.clipboardData);
    if (images.length === 0) {
      // Normal text paste: keep native textarea behavior untouched
      return;
    }
    if (!hasPlainText) {
      ev.preventDefault();
    }
    mergeIncomingFiles(images, "clipboard");
  }

  function handleDragOver(ev: DragEvent<HTMLDivElement>) {
    ev.preventDefault();
    ev.stopPropagation();
    if (!isAnalyzing) {
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
    if (isAnalyzing) return;
    const dropped = Array.from(ev.dataTransfer.files ?? []);
    if (dropped.length > 0) {
      mergeIncomingFiles(dropped);
    }
  }

  function removeImageAt(idx: number) {
    if (isAnalyzing) return;
    setAttachError(null);
    onAttachmentsChange(
      imageFiles.filter((_, i) => i !== idx),
      audioFiles,
    );
  }

  function removeAudioAt(idx: number) {
    if (isAnalyzing) return;
    setAttachError(null);
    onAttachmentsChange(
      imageFiles,
      audioFiles.filter((_, i) => i !== idx),
    );
  }

  const hasAttachments = imageFiles.length > 0 || audioFiles.length > 0;

  return (
    <div className="space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <label htmlFor={textareaId} className="text-xs font-semibold text-ink-secondary">
          Nội dung cần kiểm tra
        </label>
        <span className="inline-flex items-center gap-1.5 text-[11px] text-ink-muted">
          <ClipboardPaste className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
          <span>Ctrl+V dán ảnh · Kéo thả tệp</span>
        </span>
      </div>

      <div
        onPaste={handlePaste}
        onDragEnter={handleDragOver}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`relative rounded-2xl border transition-colors ${
          attachError
            ? "border-rose-500/65 bg-surface-subtle"
            : isDragOver
              ? "border-amber-400 bg-amber-500/10 ring-2 ring-amber-400/25"
              : "border-border-strong bg-surface-subtle focus-within:border-amber-400"
        }`}
      >
        {/* Hidden multipart file inputs */}
        <input
          ref={imageInputRef}
          type="file"
          multiple
          accept={IMAGE_ACCEPT}
          disabled={isAnalyzing}
          aria-label="Chọn hình ảnh đính kèm"
          onChange={(e) => {
            const picked = Array.from(e.target.files ?? []);
            e.target.value = "";
            mergeIncomingFiles(picked);
          }}
          className="sr-only"
        />
        <input
          ref={audioInputRef}
          type="file"
          multiple
          accept={AUDIO_ACCEPT}
          disabled={isAnalyzing}
          aria-label="Chọn tệp ghi âm đính kèm"
          onChange={(e) => {
            const picked = Array.from(e.target.files ?? []);
            e.target.value = "";
            mergeIncomingFiles(picked);
          }}
          className="sr-only"
        />

        {/* Inline attachment thumbnail & audio strip inside the composer */}
        {hasAttachments && (
          <div
            aria-label="Tệp đã đính kèm"
            className="flex flex-wrap gap-2.5 border-b border-border-subtle/80 px-3.5 pt-3 pb-2.5"
          >
            {previewEntries.map(({ file, url }, idx) => (
              <div
                key={`${file.name}-${file.size}-${idx}`}
                className="group relative flex items-center gap-2 rounded-xl border border-amber-500/35 bg-surface p-1.5 pr-2"
              >
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={url}
                  alt={`Xem trước ảnh ${file.name}`}
                  className="h-12 w-12 shrink-0 rounded-lg border border-border-subtle bg-surface-deep object-cover"
                />
                <div className="max-w-[140px] min-w-0">
                  <p className="truncate text-[11px] font-semibold text-ink" title={file.name}>
                    {file.name}
                  </p>
                  <p className="tabular-num text-[10px] text-ink-muted">
                    {formatAttachmentSize(file.size)}
                  </p>
                </div>
                {!isAnalyzing && (
                  <button
                    type="button"
                    onClick={() => removeImageAt(idx)}
                    aria-label={`Xóa tệp ${file.name}`}
                    className="inline-flex h-7 w-7 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-border-subtle bg-surface-subtle text-ink-muted transition-colors hover:border-rose-400/70 hover:text-rose-200"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                )}
              </div>
            ))}

            {audioFiles.map((file, idx) => (
              <div
                key={`${file.name}-${file.size}-${idx}`}
                className="flex items-center gap-2 rounded-xl border border-sky-500/40 bg-surface px-2.5 py-2"
              >
                <FileAudio className="h-4 w-4 shrink-0 text-sky-400" aria-hidden="true" />
                <div className="max-w-[160px] min-w-0">
                  <p className="truncate text-[11px] font-semibold text-ink" title={file.name}>
                    {file.name}
                  </p>
                  <p className="tabular-num text-[10px] text-ink-muted">
                    {formatAttachmentSize(file.size)}
                  </p>
                </div>
                {!isAnalyzing && (
                  <button
                    type="button"
                    onClick={() => removeAudioAt(idx)}
                    aria-label={`Xóa tệp ghi âm ${file.name}`}
                    className="inline-flex h-7 w-7 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-border-subtle bg-surface-subtle text-ink-muted transition-colors hover:border-rose-400/70 hover:text-rose-200"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Standard native textarea (no contenteditable) */}
        <textarea
          id={textareaId}
          rows={4}
          value={text}
          disabled={isAnalyzing}
          aria-describedby={attachError ? errorId : undefined}
          onChange={(e) => onTextChange(e.target.value)}
          placeholder="Dán tin nhắn, đường dẫn hoặc bấm Ctrl+V để dán ảnh chụp màn hình, biên lai, mã QR..."
          className="block w-full resize-y rounded-t-2xl bg-transparent px-3.5 py-3 text-sm leading-relaxed text-ink placeholder:text-ink-muted focus:outline-none disabled:opacity-60"
        />

        {/* Drag-over overlay hint */}
        {isDragOver && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-2xl bg-surface-deep/75 backdrop-blur-[1px]">
            <div className="flex items-center gap-2 rounded-xl border border-amber-400 bg-surface px-4 py-2.5 text-xs font-semibold text-amber-200 shadow-lg">
              <Upload className="h-4 w-4 text-amber-300" aria-hidden="true" />
              <span>Thả hình ảnh hoặc tệp ghi âm vào đây để đính kèm</span>
            </div>
          </div>
        )}

        {/* Composer bottom toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border-subtle/80 px-3 py-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={isAnalyzing || imageFiles.length >= ATTACHMENT_LIMITS.maxImages}
              onClick={() => imageInputRef.current?.click()}
              className="inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-lg border border-border-strong bg-surface px-2.5 py-1.5 text-xs font-medium text-ink-secondary transition-colors hover:border-amber-400/70 hover:text-ink disabled:cursor-not-allowed disabled:opacity-50"
            >
              <ImagePlus className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
              <span>
                Thêm ảnh ({imageFiles.length}/{ATTACHMENT_LIMITS.maxImages})
              </span>
            </button>

            <button
              type="button"
              disabled={isAnalyzing || audioFiles.length >= ATTACHMENT_LIMITS.maxAudios}
              onClick={() => audioInputRef.current?.click()}
              className="inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-lg border border-border-strong bg-surface px-2.5 py-1.5 text-xs font-medium text-ink-secondary transition-colors hover:border-sky-400/70 hover:text-ink disabled:cursor-not-allowed disabled:opacity-50"
            >
              <FileAudio className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
              <span>
                Thêm ghi âm ({audioFiles.length}/{ATTACHMENT_LIMITS.maxAudios})
              </span>
            </button>

            <span className="tabular-num hidden text-[11px] text-ink-muted sm:inline">
              {hasAttachments
                ? `Đã chọn ${formatAttachmentSize(totalBytes)} / 20 MB`
                : "Tối đa 4 ảnh, 2 ghi âm (≤ 10 MB/tệp)"}
            </span>
          </div>

          <button
            type="submit"
            disabled={isAnalyzing}
            className="inline-flex min-h-[42px] cursor-pointer items-center gap-2 rounded-xl bg-amber-500 px-5 py-2 text-sm font-bold text-slate-950 shadow-md transition-colors hover:bg-amber-400 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-300 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                <span>Đang kiểm tra...</span>
              </>
            ) : (
              <>
                <ScanSearch className="h-4 w-4" aria-hidden="true" />
                <span>Kiểm tra ngay</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Auto-detected URLs pill bar */}
      {detectedUrls.length > 0 && (
        <div
          aria-label="Đường dẫn được phát hiện tự động trong văn bản"
          className="flex flex-wrap items-center gap-1.5 rounded-xl border border-sky-500/30 bg-sky-500/8 px-3 py-2 text-[11px]"
        >
          <span className="inline-flex items-center gap-1 font-semibold text-sky-200">
            <Link2 className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
            <span>Tự phát hiện {detectedUrls.length} đường dẫn:</span>
          </span>
          {detectedUrls.map((u) => (
            <code
              key={u}
              title={u}
              className="max-w-[260px] truncate rounded-md border border-sky-500/35 bg-surface px-2 py-0.5 font-mono text-[11px] text-sky-200"
            >
              {u}
            </code>
          ))}
        </div>
      )}

      {pasteNotice && (
        <p role="status" className="text-[11px] font-medium text-emerald-300">
          {pasteNotice}
        </p>
      )}

      {attachError && (
        <p
          id={errorId}
          role="alert"
          className="flex items-start gap-1.5 text-[11px] leading-snug text-rose-300"
        >
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>{attachError}</span>
        </p>
      )}
    </div>
  );
}
