import type { AnalyzeMode } from "./types";

export const ATTACHMENT_LIMITS = {
  maxImages: 4,
  maxAudios: 2,
  maxFileBytes: 10 * 1024 * 1024,
  maxTotalBytes: 20 * 1024 * 1024,
} as const;

export const ALLOWED_IMAGE_MIMES = new Set([
  "image/jpeg",
  "image/jpg",
  "image/png",
  "image/webp",
  "image/gif",
]);

export const ALLOWED_IMAGE_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp", ".gif"] as const;

export const ALLOWED_AUDIO_MIMES = new Set([
  "audio/wav",
  "audio/x-wav",
  "audio/wave",
  "audio/mpeg",
  "audio/mp3",
  "audio/mp4",
  "audio/x-m4a",
  "audio/m4a",
  "audio/ogg",
  "audio/webm",
]);

export const ALLOWED_AUDIO_EXTENSIONS = [".wav", ".mp3", ".m4a", ".ogg", ".webm"] as const;

const NON_URL_FILE_EXTS = new Set([
  "apk",
  "pdf",
  "jpg",
  "jpeg",
  "png",
  "webp",
  "gif",
  "wav",
  "mp3",
  "m4a",
  "ogg",
  "json",
  "exe",
  "doc",
  "docx",
  "xls",
  "xlsx",
  "txt",
  "csv",
]);

const EXPLICIT_URL_RE = /https?:\/\/[^\s<>'"()[\]{}]+/gi;
const SCHEMELESS_URL_RE =
  /(?<![/@\w])(?:www\.|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})(?::\d{1,5})?(?:[/?#][^\s<>'"()[\]{}]*)?/gi;
const TRAILING_PUNCT_RE = /[.,!?;:)'"»\]]+$/;

export function formatAttachmentSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Extract unique explicit http(s) and scheme-less web links from free text without catching filenames.
 */
export function extractUrlsFromText(text: string, maxUrls = 6): string[] {
  if (!text.trim()) return [];
  const found: string[] = [];
  const seen = new Set<string>();

  const pushUnique = (raw: string) => {
    const cleaned = raw.trim().replace(TRAILING_PUNCT_RE, "");
    if (!cleaned || seen.has(cleaned)) return;
    seen.add(cleaned);
    found.push(cleaned);
  };

  for (const m of text.matchAll(EXPLICIT_URL_RE)) {
    if (m[0]) pushUnique(m[0]);
  }

  const withoutExplicit = text.replace(EXPLICIT_URL_RE, " ");
  for (const m of withoutExplicit.matchAll(SCHEMELESS_URL_RE)) {
    const token = (m[0] ?? "").trim().replace(TRAILING_PUNCT_RE, "");
    if (!token) continue;
    let parsed: URL;
    try {
      parsed = new URL(`https://${token}`);
    } catch {
      continue;
    }
    const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
    const labels = host.split(".").filter(Boolean);
    if (labels.length < 2) continue;
    const tld = labels[labels.length - 1] ?? "";
    const hasPathOrQuery =
      (parsed.pathname && parsed.pathname !== "/") ||
      Boolean(parsed.search) ||
      Boolean(parsed.hash) ||
      Boolean(parsed.port);
    if (!hasPathOrQuery && !host.startsWith("www.") && NON_URL_FILE_EXTS.has(tld)) {
      continue;
    }
    pushUnique(`https://${token}`);
  }

  return found.slice(0, maxUrls);
}

export interface ClipboardItemLike {
  kind: string;
  type: string;
  getAsFile: () => File | null;
}

export interface ClipboardDataLike {
  getData: (format: string) => string;
  items?: ArrayLike<ClipboardItemLike> | null;
  files?: ArrayLike<File> | null;
}

function mimeToImageExt(mime: string): string {
  const low = mime.toLowerCase();
  if (low.includes("jpeg") || low.includes("jpg")) return "jpg";
  if (low.includes("webp")) return "webp";
  if (low.includes("gif")) return "gif";
  return "png";
}

function ensureNamedClipboardFile(file: File, index: number): File {
  const existingName = (file.name || "").trim();
  if (existingName && existingName.toLowerCase() !== "image.png") {
    return file;
  }
  const ext = mimeToImageExt(file.type || "image/png");
  return new File([file], `clipboard-image-${index}.${ext}`, {
    type: file.type || "image/png",
    lastModified: file.lastModified || Date.now(),
  });
}

/**
 * Extract image files from a browser ClipboardEvent while detecting whether plain text is present.
 */
export function extractClipboardImages(clipboardData: ClipboardDataLike | null | undefined): {
  images: File[];
  hasPlainText: boolean;
} {
  if (!clipboardData) {
    return { images: [], hasPlainText: false };
  }
  const plainText = (clipboardData.getData("text/plain") || "").trim();
  const hasPlainText = plainText.length > 0;
  const collected: File[] = [];

  if (clipboardData.items && clipboardData.items.length > 0) {
    for (let i = 0; i < clipboardData.items.length; i += 1) {
      const item = clipboardData.items[i];
      if (!item || item.kind !== "file") continue;
      if (!item.type.toLowerCase().startsWith("image/")) continue;
      const f = item.getAsFile();
      if (f && f.size > 0) {
        collected.push(ensureNamedClipboardFile(f, collected.length + 1));
      }
    }
  }

  if (collected.length === 0 && clipboardData.files && clipboardData.files.length > 0) {
    for (let i = 0; i < clipboardData.files.length; i += 1) {
      const f = clipboardData.files[i];
      if (!f || f.size <= 0) continue;
      if (f.type.toLowerCase().startsWith("image/")) {
        collected.push(ensureNamedClipboardFile(f, collected.length + 1));
      }
    }
  }

  return { images: collected, hasPlainText };
}

export function classifyAttachmentKind(file: File): "image" | "audio" | null {
  const mime = (file.type || "").split(";")[0]?.trim().toLowerCase() ?? "";
  const lowerName = (file.name || "").toLowerCase();

  if (mime === "image/svg+xml" || lowerName.endsWith(".svg")) {
    return null;
  }
  const isImageMime = mime !== "" && ALLOWED_IMAGE_MIMES.has(mime);
  const isImageExt = ALLOWED_IMAGE_EXTENSIONS.some((ext) => lowerName.endsWith(ext));
  if (isImageMime || (mime === "" && isImageExt)) {
    return "image";
  }

  const isAudioMime = mime !== "" && ALLOWED_AUDIO_MIMES.has(mime);
  const isAudioExt = ALLOWED_AUDIO_EXTENSIONS.some((ext) => lowerName.endsWith(ext));
  if (isAudioMime || (mime === "" && isAudioExt)) {
    return "audio";
  }
  return null;
}

export interface BatchValidationResult {
  acceptedImages: File[];
  acceptedAudios: File[];
  errors: string[];
}

/**
 * Validate incoming images/audios against count, per-file size, total batch cap, and allowlists.
 */
export function validateAttachmentBatch(
  existingImages: readonly File[],
  existingAudios: readonly File[],
  incomingFiles: readonly File[],
): BatchValidationResult {
  const acceptedImages: File[] = [];
  const acceptedAudios: File[] = [];
  const errors: string[] = [];

  let imgCount = existingImages.length;
  let audCount = existingAudios.length;
  let runningBytes =
    existingImages.reduce((acc, f) => acc + f.size, 0) +
    existingAudios.reduce((acc, f) => acc + f.size, 0);

  for (const file of incomingFiles) {
    if (file.size <= 0) {
      errors.push(`Tệp "${file.name || "không tên"}" không có dữ liệu.`);
      continue;
    }
    if (file.size > ATTACHMENT_LIMITS.maxFileBytes) {
      errors.push(`Tệp "${file.name}" vượt quá giới hạn 10 MB mỗi tệp.`);
      continue;
    }

    const kind = classifyAttachmentKind(file);
    if (!kind) {
      errors.push(
        `Định dạng tệp "${file.name}" chưa được hỗ trợ. Chỉ nhận ảnh (JPG, PNG, WebP, GIF) hoặc âm thanh (WAV, MP3, M4A, OGG, WebM).`,
      );
      continue;
    }

    if (kind === "image" && imgCount >= ATTACHMENT_LIMITS.maxImages) {
      errors.push(`Chỉ hỗ trợ tối đa ${ATTACHMENT_LIMITS.maxImages} hình ảnh cho mỗi lần kiểm tra.`);
      continue;
    }
    if (kind === "audio" && audCount >= ATTACHMENT_LIMITS.maxAudios) {
      errors.push(`Chỉ hỗ trợ tối đa ${ATTACHMENT_LIMITS.maxAudios} tệp ghi âm cho mỗi lần kiểm tra.`);
      continue;
    }

    if (runningBytes + file.size > ATTACHMENT_LIMITS.maxTotalBytes) {
      errors.push("Tổng dung lượng các tệp đính kèm không được vượt quá 20 MB.");
      continue;
    }

    runningBytes += file.size;
    if (kind === "image") {
      imgCount += 1;
      acceptedImages.push(file);
    } else {
      audCount += 1;
      acceptedAudios.push(file);
    }
  }

  return { acceptedImages, acceptedAudios, errors };
}

/**
 * Option A automatic backend mode inference without exposing 3 mode cards in UI.
 */
export function inferAnalyzeMode(params: {
  expectedMerchantAccount: string;
  transferAmount: string;
  inActiveCall: boolean;
}): AnalyzeMode {
  if (params.expectedMerchantAccount.trim()) {
    return "merchant";
  }
  if (params.inActiveCall || params.transferAmount.trim()) {
    return "wallet_transfer";
  }
  return "personal";
}
