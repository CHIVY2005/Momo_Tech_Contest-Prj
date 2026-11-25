"use client";

import {
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
import { type FormEvent, useRef, useState } from "react";

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
    label: "Cá nhân",
    hint: "Tin nhắn, đường link, QR, ghi âm cuộc gọi",
    Icon: UserCheck,
  },
  {
    id: "merchant",
    label: "Chủ cửa hàng",
    hint: "Pháp y ảnh biên lai chuyển khoản & VietQR",
    Icon: Store,
  },
  {
    id: "wallet_transfer",
    label: "Ví Trước Chuyển Tiền",
    hint: "Cảm biến đang nghe máy + Khóa làm nguội 30s",
    Icon: Wallet,
  },
];

export function InputWorkbench({
  value,
  isAnalyzing,
  activeDemoTitle,
  onChange,
  onSubmit,
  onClearDemo,
}: InputWorkbenchProps) {
  const [fileError, setFileError] = useState<string | null>(null);
  const imgInputRef = useRef<HTMLInputElement | null>(null);
  const audInputRef = useRef<HTMLInputElement | null>(null);

  function updateField<K extends keyof WorkbenchFormState>(
    key: K,
    fieldVal: WorkbenchFormState[K],
  ) {
    onChange({ ...value, [key]: fieldVal });
  }

  function handleFileChange(kind: "imageFile" | "audioFile", file: File | null) {
    setFileError(null);
    if (file && file.size > MAX_CLIENT_UPLOAD_BYTES) {
      setFileError(
        `Tệp "${file.name}" vượt quá giới hạn an toàn 10 MB. Vui lòng chọn tệp nhỏ hơn.`,
      );
      return;
    }
    updateField(kind, file);
  }

  function handleFormSubmit(ev: FormEvent) {
    ev.preventDefault();
    onSubmit();
  }

  return (
    <form
      onSubmit={handleFormSubmit}
      className="rounded-2xl border border-slate-800 bg-[#111827]/95 p-5 shadow-lg"
    >
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-base font-bold text-slate-50">
            Bàn Điều tra Đa phương thức (Multimodal Workbench)
          </h2>
          <p className="text-xs text-slate-400">
            Kết hợp phân tích văn bản, URL Punycode/SSRF, pháp y ELA ảnh biên lai và chuyển ngữ cuộc gọi.
          </p>
        </div>
        {activeDemoTitle && (
          <div className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-xs text-amber-200">
            <span>Kịch bản mẫu: {activeDemoTitle}</span>
            <button
              type="button"
              onClick={onClearDemo}
              aria-label="Xóa kịch bản mẫu để nhập tự do"
              className="cursor-pointer rounded p-0.5 text-amber-300 hover:bg-amber-500/20"
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        )}
      </div>

      <div
        role="tablist"
        aria-label="Chế độ thẩm định"
        className="mb-4 grid grid-cols-1 gap-2 sm:grid-cols-3"
      >
        {MODE_OPTIONS.map(({ id, label, hint, Icon }) => {
          const selected = value.mode === id;
          return (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={selected}
              onClick={() => updateField("mode", id)}
              className={`cursor-pointer rounded-xl border p-3 text-left transition-colors ${
                selected
                  ? "border-amber-400 bg-amber-500/15 text-slate-50"
                  : "border-slate-800 bg-[#0b1120] text-slate-300 hover:border-slate-600"
              }`}
            >
              <div className="flex items-center gap-2 text-xs font-semibold">
                <Icon
                  className={`h-4 w-4 ${selected ? "text-amber-400" : "text-slate-400"}`}
                  aria-hidden="true"
                />
                <span>{label}</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-400">{hint}</p>
            </button>
          );
        })}
      </div>

      <div className="space-y-3.5">
        <div>
          <label
            htmlFor="wb-text-input"
            className="mb-1.5 block text-xs font-semibold text-slate-200"
          >
            Nội dung tin nhắn / hội thoại / mô tả giao dịch
          </label>
          <textarea
            id="wb-text-input"
            rows={4}
            value={value.text}
            onChange={(e) => updateField("text", e.target.value)}
            placeholder="Dán tin nhắn SMS, Zalo, nội dung yêu cầu chuyển khoản hoặc kịch bản nghi ngờ tại đây..."
            className="w-full rounded-xl border border-slate-700/90 bg-[#0b1120] px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:border-amber-400"
          />
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label
              htmlFor="wb-url-input"
              className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-slate-200"
            >
              <Link2 className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
              <span>Đường dẫn đáng ngờ (URL / Link rút gọn)</span>
            </label>
            <input
              id="wb-url-input"
              type="text"
              value={value.url}
              onChange={(e) => updateField("url", e.target.value)}
              placeholder="https://..."
              className="w-full rounded-xl border border-slate-700/90 bg-[#0b1120] px-3 py-2 font-[family-name:var(--font-mono)] text-xs text-slate-100 placeholder:text-slate-500 focus:border-amber-400"
            />
          </div>

          {value.mode === "merchant" ? (
            <div>
              <label
                htmlFor="wb-merchant-stk"
                className="mb-1.5 block text-xs font-semibold text-amber-300"
              >
                STK nhận tiền chuẩn của cửa hàng (đối chiếu Bill/QR)
              </label>
              <input
                id="wb-merchant-stk"
                type="text"
                value={value.expectedMerchantAccount}
                onChange={(e) => updateField("expectedMerchantAccount", e.target.value)}
                placeholder="VD: 190311112222"
                className="w-full rounded-xl border border-amber-500/40 bg-[#0b1120] px-3 py-2 font-[family-name:var(--font-mono)] text-xs text-slate-100 placeholder:text-slate-500 focus:border-amber-400"
              />
            </div>
          ) : (
            <div>
              <label
                htmlFor="wb-transfer-amount"
                className="mb-1.5 block text-xs font-semibold text-slate-200"
              >
                Số tiền dự kiến chuyển (VND — tùy chọn)
              </label>
              <input
                id="wb-transfer-amount"
                type="number"
                min={0}
                value={value.transferAmount}
                onChange={(e) => updateField("transferAmount", e.target.value)}
                placeholder="VD: 15000000"
                className="w-full rounded-xl border border-slate-700/90 bg-[#0b1120] px-3 py-2 font-[family-name:var(--font-mono)] text-xs text-slate-100 placeholder:text-slate-500 focus:border-amber-400"
              />
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-[#0b1120] px-3.5 py-2.5">
          <div className="flex items-center gap-2.5">
            <PhoneCall
              className={`h-4 w-4 ${value.inActiveCall ? "text-rose-400" : "text-slate-400"}`}
              aria-hidden="true"
            />
            <div>
              <label
                htmlFor="wb-active-call-toggle"
                className="cursor-pointer text-xs font-semibold text-slate-100"
              >
                Tín hiệu ngữ cảnh: Đang trong cuộc gọi thoại (`in_active_call`)
              </label>
              <p className="text-[11px] text-slate-400">
                Kích hoạt cộng hưởng rủi ro &amp; Khóa làm nguội 30 giây khi kẻ gian thúc ép qua điện thoại.
              </p>
            </div>
          </div>
          <input
            id="wb-active-call-toggle"
            type="checkbox"
            checked={value.inActiveCall}
            onChange={(e) => updateField("inActiveCall", e.target.checked)}
            className="h-4 w-4 cursor-pointer accent-amber-500"
          />
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-dashed border-slate-700 bg-[#0b1120] p-3">
            <div className="flex items-center justify-between gap-2">
              <label
                htmlFor="wb-image-upload"
                className="flex cursor-pointer items-center gap-2 text-xs font-semibold text-slate-200"
              >
                <ImagePlus className="h-4 w-4 text-amber-400" aria-hidden="true" />
                <span>Ảnh chụp màn hình / Biên lai / Mã QR (&le;10MB)</span>
              </label>
              {value.imageFile && (
                <button
                  type="button"
                  onClick={() => {
                    updateField("imageFile", null);
                    if (imgInputRef.current) imgInputRef.current.value = "";
                  }}
                  aria-label="Gỡ tệp hình ảnh đã chọn"
                  className="cursor-pointer rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                >
                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              )}
            </div>
            <input
              ref={imgInputRef}
              id="wb-image-upload"
              type="file"
              accept="image/jpeg,image/png,image/webp"
              onChange={(e) => handleFileChange("imageFile", e.target.files?.[0] ?? null)}
              className="mt-2 block w-full cursor-pointer text-xs text-slate-400 file:mr-2.5 file:cursor-pointer file:rounded-lg file:border-0 file:bg-slate-800 file:px-2.5 file:py-1.5 file:text-xs file:font-medium file:text-slate-200 hover:file:bg-slate-700"
            />
          </div>

          <div className="rounded-xl border border-dashed border-slate-700 bg-[#0b1120] p-3">
            <div className="flex items-center justify-between gap-2">
              <label
                htmlFor="wb-audio-upload"
                className="flex cursor-pointer items-center gap-2 text-xs font-semibold text-slate-200"
              >
                <FileAudio className="h-4 w-4 text-sky-400" aria-hidden="true" />
                <span>Tệp ghi âm cuộc gọi (.wav/.mp3/.m4a &le;10MB)</span>
              </label>
              {value.audioFile && (
                <button
                  type="button"
                  onClick={() => {
                    updateField("audioFile", null);
                    if (audInputRef.current) audInputRef.current.value = "";
                  }}
                  aria-label="Gỡ tệp âm thanh đã chọn"
                  className="cursor-pointer rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                >
                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              )}
            </div>
            <input
              ref={audInputRef}
              id="wb-audio-upload"
              type="file"
              accept="audio/*"
              onChange={(e) => handleFileChange("audioFile", e.target.files?.[0] ?? null)}
              className="mt-2 block w-full cursor-pointer text-xs text-slate-400 file:mr-2.5 file:cursor-pointer file:rounded-lg file:border-0 file:bg-slate-800 file:px-2.5 file:py-1.5 file:text-xs file:font-medium file:text-slate-200 hover:file:bg-slate-700"
            />
          </div>
        </div>

        {fileError && (
          <p role="alert" className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
            {fileError}
          </p>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <p className="text-[11px] text-slate-400">
            Tầng 1 chạy nội bộ (&lt;50ms) · Tầng 2 cô lập thẻ{" "}
            <code className="font-[family-name:var(--font-mono)] text-slate-300">
              &lt;UNTRUSTED_USER_CONTENT&gt;
            </code>
          </p>
          <button
            type="submit"
            disabled={isAnalyzing}
            className="inline-flex cursor-pointer items-center gap-2 rounded-xl bg-amber-500 px-5 py-2.5 text-sm font-bold text-slate-950 shadow-md transition-colors hover:bg-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                <span>Đang điều tra đa tầng...</span>
              </>
            ) : (
              <>
                <ScanSearch className="h-4 w-4" aria-hidden="true" />
                <span>Phân tích &amp; Kiểm chứng Ngay</span>
              </>
            )}
          </button>
        </div>
      </div>
    </form>
  );
}
