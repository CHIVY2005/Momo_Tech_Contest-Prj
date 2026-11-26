"use client";

import {
  ChevronDown,
  ChevronUp,
  FileAudio,
  ImagePlus,
  Link2,
  Loader2,
  PhoneCall,
  RotateCcw,
  ScanSearch,
  Store,
  UserCheck,
  Wallet,
  X,
} from "lucide-react";
import { type FormEvent, type KeyboardEvent, useEffect, useRef, useState } from "react";

import { MODE_COPY } from "@/lib/copy";
import type { AnalyzeMode } from "@/lib/types";

const MAX_CLIENT_UPLOAD_BYTES = 10 * 1024 * 1024;

export interface WorkbenchFormState {
  mode: AnalyzeMode;
  text: string;
  url: string;
  inActiveCall: boolean;
  transferAmount: string;
  expectedMerchantAccount: string;
  imageFile: File | null;
  audioFile: File | null;
}

interface InputWorkbenchProps {
  value: WorkbenchFormState;
  isAnalyzing: boolean;
  activeDemoTitle: string | null;
  collapsed?: boolean;
  canCollapse?: boolean;
  onToggleCollapsed?: () => void;
  onChange: (next: WorkbenchFormState) => void;
  onSubmit: () => void;
  onClearDemo: () => void;
}

const MODE_OPTIONS: Array<{
  id: AnalyzeMode;
  label: string;
  hint: string;
  Icon: typeof UserCheck;
}> = [
  {
    id: "personal",
    label: MODE_COPY.personal.label,
    hint: MODE_COPY.personal.hint,
    Icon: UserCheck,
  },
  {
    id: "merchant",
    label: MODE_COPY.merchant.label,
    hint: MODE_COPY.merchant.hint,
    Icon: Store,
  },
  {
    id: "wallet_transfer",
    label: MODE_COPY.wallet_transfer.label,
    hint: MODE_COPY.wallet_transfer.hint,
    Icon: Wallet,
  },
];

export function InputWorkbench({
  value,
  isAnalyzing,
  activeDemoTitle,
  collapsed = false,
  canCollapse = false,
  onToggleCollapsed,
  onChange,
  onSubmit,
  onClearDemo,
}: InputWorkbenchProps) {
  const [fileError, setFileError] = useState<string | null>(null);
  const imgInputRef = useRef<HTMLInputElement | null>(null);
  const audInputRef = useRef<HTMLInputElement | null>(null);
  const radioRefs = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    if (value.imageFile === null && imgInputRef.current) {
      imgInputRef.current.value = "";
    }
  }, [value.imageFile]);

  useEffect(() => {
    if (value.audioFile === null && audInputRef.current) {
      audInputRef.current.value = "";
    }
  }, [value.audioFile]);

  function updateField<K extends keyof WorkbenchFormState>(
    key: K,
    fieldVal: WorkbenchFormState[K],
  ) {
    onChange({ ...value, [key]: fieldVal });
  }

  function handleFileChange(kind: "imageFile" | "audioFile", file: File | null) {
    setFileError(null);
    if (file && file.size > MAX_CLIENT_UPLOAD_BYTES) {
      if (kind === "imageFile" && imgInputRef.current) {
        imgInputRef.current.value = "";
      }
      if (kind === "audioFile" && audInputRef.current) {
        audInputRef.current.value = "";
      }
      updateField(kind, null);
      setFileError(
        `Tệp "${file.name}" vượt quá dung lượng tối đa 10 MB. Vui lòng chọn tệp nhỏ hơn.`,
      );
      return;
    }
    updateField(kind, file);
  }

  function handleFormSubmit(ev: FormEvent) {
    ev.preventDefault();
    onSubmit();
  }

  function handleRadioKeyDown(ev: KeyboardEvent<HTMLButtonElement>, idx: number) {
    let nextIdx = idx;
    if (ev.key === "ArrowRight" || ev.key === "ArrowDown") {
      nextIdx = (idx + 1) % MODE_OPTIONS.length;
    } else if (ev.key === "ArrowLeft" || ev.key === "ArrowUp") {
      nextIdx = (idx - 1 + MODE_OPTIONS.length) % MODE_OPTIONS.length;
    } else {
      return;
    }
    ev.preventDefault();
    const target = MODE_OPTIONS[nextIdx];
    if (target) {
      updateField("mode", target.id);
      radioRefs.current[nextIdx]?.focus();
    }
  }

  const activeModeMeta = MODE_OPTIONS.find((m) => m.id === value.mode) ?? MODE_OPTIONS[0];
  const ActiveModeIcon = activeModeMeta?.Icon ?? UserCheck;

  if (collapsed && onToggleCollapsed) {
    const snippetSource =
      activeDemoTitle ??
      (value.text.trim() || value.url.trim() || value.imageFile?.name || value.audioFile?.name || "Phiên kiểm tra hiện tại");
    const snippet =
      snippetSource.length > 92 ? `${snippetSource.slice(0, 90)}…` : snippetSource;

    return (
      <section
        aria-label="Tóm tắt thông tin đang kiểm tra"
        className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border-subtle bg-surface/95 px-4 py-3 shadow-md"
      >
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2 text-xs">
          <span className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-amber-500/35 bg-amber-500/15 px-2.5 py-1 font-semibold text-amber-200">
            <ActiveModeIcon className="h-3.5 w-3.5 text-amber-300" aria-hidden="true" />
            <span>{activeModeMeta?.label ?? value.mode}</span>
          </span>

          <span className="truncate font-medium text-ink">{snippet}</span>

          {value.inActiveCall && (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-md border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-semibold text-rose-200">
              <PhoneCall className="h-3 w-3" aria-hidden="true" />
              <span>Đang nghe điện thoại</span>
            </span>
          )}
          {value.imageFile && (
            <span className="shrink-0 rounded-md border border-border-strong bg-surface-subtle px-2 py-0.5 font-mono text-[11px] text-ink-secondary">
              Ảnh: {value.imageFile.name}
            </span>
          )}
          {value.audioFile && (
            <span className="shrink-0 rounded-md border border-border-strong bg-surface-subtle px-2 py-0.5 font-mono text-[11px] text-ink-secondary">
              Ghi âm: {value.audioFile.name}
            </span>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {activeDemoTitle && (
            <button
              type="button"
              onClick={onClearDemo}
              className="inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-lg border border-border-strong bg-surface-subtle px-3 py-1.5 text-xs font-medium text-ink-secondary transition-colors hover:border-amber-400 hover:text-ink"
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Nhập nội dung khác</span>
            </button>
          )}
          <button
            type="button"
            aria-expanded={false}
            onClick={onToggleCollapsed}
            className="inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-200 transition-colors hover:border-amber-400 hover:bg-amber-500/20"
          >
            <span>Chỉnh sửa thông tin</span>
            <ChevronDown className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      </section>
    );
  }

  return (
    <form
      onSubmit={handleFormSubmit}
      className="rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-lg sm:p-5"
    >
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-base font-bold text-ink">Công cụ kiểm tra lừa đảo</h2>
          <p className="text-xs text-ink-muted">
            Dán tin nhắn, đường dẫn hoặc tải lên ảnh biên lai, mã QR và tệp ghi âm để kiểm tra dấu
            hiệu bất thường.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {activeDemoTitle && (
            <div className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-xs text-amber-200">
              <span>Tình huống mẫu: {activeDemoTitle}</span>
              <button
                type="button"
                onClick={onClearDemo}
                aria-label="Xóa tình huống mẫu để nhập nội dung khác"
                className="inline-flex h-7 w-7 cursor-pointer items-center justify-center rounded text-amber-300 hover:bg-amber-500/20"
              >
                <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          )}
          {canCollapse && onToggleCollapsed && (
            <button
              type="button"
              aria-expanded={true}
              onClick={onToggleCollapsed}
              className="inline-flex min-h-[36px] cursor-pointer items-center gap-1 rounded-lg border border-border-strong bg-surface-subtle px-2.5 py-1 text-xs font-medium text-ink-secondary hover:border-amber-400 hover:text-ink"
            >
              <span>Thu gọn</span>
              <ChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      <div
        role="radiogroup"
        aria-label="Chế độ thẩm định"
        className="mb-4 grid grid-cols-1 gap-2 sm:grid-cols-3"
      >
        {MODE_OPTIONS.map(({ id, label, hint, Icon }, idx) => {
          const selected = value.mode === id;
          return (
            <button
              key={id}
              ref={(el) => {
                radioRefs.current[idx] = el;
              }}
              type="button"
              role="radio"
              tabIndex={selected ? 0 : -1}
              aria-checked={selected}
              onClick={() => updateField("mode", id)}
              onKeyDown={(ev) => handleRadioKeyDown(ev, idx)}
              className={`min-h-[60px] cursor-pointer rounded-xl border p-3 text-left transition-colors ${
                selected
                  ? "border-amber-400 bg-amber-500/15 text-ink"
                  : "border-border-subtle bg-surface-subtle text-ink-secondary hover:border-border-strong hover:bg-surface-elevated"
              }`}
            >
              <div className="flex items-center gap-2 text-xs font-semibold">
                <Icon
                  className={`h-4 w-4 shrink-0 ${selected ? "text-amber-300" : "text-ink-muted"}`}
                  aria-hidden="true"
                />
                <span>{label}</span>
              </div>
              <p className="mt-1 text-[11px] text-ink-muted">{hint}</p>
            </button>
          );
        })}
      </div>

      <div className="space-y-3.5">
        <div>
          <label
            htmlFor="wb-text-input"
            className="mb-1.5 block text-xs font-semibold text-ink-secondary"
          >
            Nội dung tin nhắn, cuộc trò chuyện hoặc mô tả giao dịch
          </label>
          <textarea
            id="wb-text-input"
            rows={4}
            value={value.text}
            onChange={(e) => updateField("text", e.target.value)}
            placeholder="Dán tin nhắn SMS, Zalo, yêu cầu chuyển tiền hoặc tình huống bạn nghi ngờ tại đây..."
            className="w-full rounded-xl border border-border-strong bg-surface-subtle px-3.5 py-2.5 text-sm text-ink placeholder:text-ink-muted focus:border-amber-400"
          />
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label
              htmlFor="wb-url-input"
              className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-ink-secondary"
            >
              <Link2 className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
              <span>Đường dẫn đáng ngờ (tùy chọn)</span>
            </label>
            <input
              id="wb-url-input"
              type="text"
              value={value.url}
              onChange={(e) => updateField("url", e.target.value)}
              placeholder="https://..."
              className="w-full rounded-xl border border-border-strong bg-surface-subtle px-3 py-2.5 font-mono text-xs text-ink placeholder:text-ink-muted focus:border-amber-400"
            />
          </div>

          {value.mode === "merchant" ? (
            <div>
              <label
                htmlFor="wb-merchant-stk"
                className="mb-1.5 block text-xs font-semibold text-amber-300"
              >
                Số tài khoản nhận tiền của cửa hàng (đối chiếu biên lai hoặc QR)
              </label>
              <input
                id="wb-merchant-stk"
                type="text"
                value={value.expectedMerchantAccount}
                onChange={(e) => updateField("expectedMerchantAccount", e.target.value)}
                placeholder="Ví dụ: 190311112222"
                className="tabular-num w-full rounded-xl border border-amber-500/45 bg-surface-subtle px-3 py-2.5 font-mono text-xs text-ink placeholder:text-ink-muted focus:border-amber-400"
              />
            </div>
          ) : (
            <div>
              <label
                htmlFor="wb-transfer-amount"
                className="mb-1.5 block text-xs font-semibold text-ink-secondary"
              >
                Số tiền dự kiến chuyển (VND, tùy chọn)
              </label>
              <input
                id="wb-transfer-amount"
                type="number"
                min={0}
                value={value.transferAmount}
                onChange={(e) => updateField("transferAmount", e.target.value)}
                placeholder="Ví dụ: 15000000"
                className="tabular-num w-full rounded-xl border border-border-strong bg-surface-subtle px-3 py-2.5 font-mono text-xs text-ink placeholder:text-ink-muted focus:border-amber-400"
              />
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border-subtle bg-surface-subtle px-3.5 py-2.5">
          <div className="flex items-start gap-2.5">
            <PhoneCall
              className={`mt-0.5 h-4 w-4 shrink-0 ${value.inActiveCall ? "text-rose-400" : "text-ink-muted"}`}
              aria-hidden="true"
            />
            <div>
              <span id="wb-active-call-label" className="text-xs font-semibold text-ink">
                Tôi đang nghe điện thoại khi chuẩn bị chuyển tiền
              </span>
              <p className="mt-0.5 text-[11px] text-ink-muted">
                Tự động tăng mức cảnh báo rủi ro và tạm dừng để kiểm tra 30 giây khi người lạ đang
                thúc giục bạn qua điện thoại.
              </p>
            </div>
          </div>

          <button
            id="wb-active-call-toggle"
            type="button"
            role="switch"
            aria-checked={value.inActiveCall}
            aria-labelledby="wb-active-call-label"
            onClick={() => updateField("inActiveCall", !value.inActiveCall)}
            className="inline-flex min-h-[44px] min-w-[44px] cursor-pointer items-center justify-center rounded-lg px-1"
          >
            <span
              className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors ${
                value.inActiveCall
                  ? "border-rose-400/70 bg-rose-500/85"
                  : "border-border-strong bg-surface-elevated"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 rounded-full bg-white shadow transition-transform ${
                  value.inActiveCall ? "translate-x-5" : "translate-x-1"
                }`}
              />
            </span>
          </button>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-dashed border-border-strong bg-surface-subtle p-3 transition-colors hover:border-amber-500/50">
            <div className="flex items-center justify-between gap-2">
              <label
                htmlFor="wb-image-upload"
                className="flex cursor-pointer items-center gap-2 text-xs font-semibold text-ink-secondary"
              >
                <ImagePlus className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
                <span>Ảnh chụp màn hình, biên lai hoặc mã QR (tối đa 10 MB)</span>
              </label>
              {value.imageFile && (
                <button
                  type="button"
                  onClick={() => {
                    updateField("imageFile", null);
                    if (imgInputRef.current) imgInputRef.current.value = "";
                  }}
                  aria-label="Gỡ tệp hình ảnh đã chọn"
                  className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-lg text-ink-muted hover:bg-surface-elevated hover:text-ink"
                >
                  <X className="h-4 w-4" aria-hidden="true" />
                </button>
              )}
            </div>
            <input
              ref={imgInputRef}
              id="wb-image-upload"
              type="file"
              accept="image/jpeg,image/png,image/webp"
              onChange={(e) => handleFileChange("imageFile", e.target.files?.[0] ?? null)}
              className="mt-2 block w-full cursor-pointer text-xs text-ink-muted file:mr-2.5 file:cursor-pointer file:rounded-lg file:border-0 file:bg-surface-elevated file:px-3 file:py-2 file:text-xs file:font-medium file:text-ink hover:file:bg-slate-700"
            />
          </div>

          <div className="rounded-xl border border-dashed border-border-strong bg-surface-subtle p-3 transition-colors hover:border-sky-500/50">
            <div className="flex items-center justify-between gap-2">
              <label
                htmlFor="wb-audio-upload"
                className="flex cursor-pointer items-center gap-2 text-xs font-semibold text-ink-secondary"
              >
                <FileAudio className="h-4 w-4 shrink-0 text-sky-400" aria-hidden="true" />
                <span>Tệp ghi âm cuộc gọi (.wav, .mp3, .m4a — tối đa 10 MB)</span>
              </label>
              {value.audioFile && (
                <button
                  type="button"
                  onClick={() => {
                    updateField("audioFile", null);
                    if (audInputRef.current) audInputRef.current.value = "";
                  }}
                  aria-label="Gỡ tệp ghi âm đã chọn"
                  className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-lg text-ink-muted hover:bg-surface-elevated hover:text-ink"
                >
                  <X className="h-4 w-4" aria-hidden="true" />
                </button>
              )}
            </div>
            <input
              ref={audInputRef}
              id="wb-audio-upload"
              type="file"
              accept="audio/*"
              onChange={(e) => handleFileChange("audioFile", e.target.files?.[0] ?? null)}
              className="mt-2 block w-full cursor-pointer text-xs text-ink-muted file:mr-2.5 file:cursor-pointer file:rounded-lg file:border-0 file:bg-surface-elevated file:px-3 file:py-2 file:text-xs file:font-medium file:text-ink hover:file:bg-slate-700"
            />
          </div>
        </div>

        {fileError && (
          <p
            role="alert"
            className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-200"
          >
            {fileError}
          </p>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <p className="text-[11px] text-ink-muted">
            Dữ liệu được phân tích an toàn và không lưu dữ liệu định danh cá nhân chưa qua xử lý.
          </p>
          <button
            type="submit"
            disabled={isAnalyzing}
            className="inline-flex min-h-[44px] cursor-pointer items-center gap-2 rounded-xl bg-amber-500 px-5 py-2.5 text-sm font-bold text-slate-950 shadow-md transition-colors hover:bg-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
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
    </form>
  );
}
