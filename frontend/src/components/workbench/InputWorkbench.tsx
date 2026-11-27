"use client";

import {
  ChevronDown,
  ChevronUp,
  FileAudio,
  Image as ImageIcon,
  PhoneCall,
  RotateCcw,
  SlidersHorizontal,
} from "lucide-react";
import Link from "next/link";
import { type FormEvent, useState } from "react";

import { formatVndInputDisplay, parseRawAmountDigits } from "@/lib/formatters";

import { MultimodalComposer } from "./MultimodalComposer";

export interface WorkbenchFormState {
  text: string;
  inActiveCall: boolean;
  transferAmount: string;
  expectedMerchantAccount: string;
  imageFiles: File[];
  audioFiles: File[];
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
  const [extraOpen, setExtraOpen] = useState(false);

  const extraFieldsCount =
    (value.transferAmount.trim() ? 1 : 0) +
    (value.expectedMerchantAccount.trim() ? 1 : 0) +
    (value.inActiveCall ? 1 : 0);

  const isExtraExpanded = extraOpen || extraFieldsCount > 0;

  function updateField<K extends keyof WorkbenchFormState>(
    key: K,
    fieldVal: WorkbenchFormState[K],
  ) {
    onChange({ ...value, [key]: fieldVal });
  }

  function handleFormSubmit(ev: FormEvent) {
    ev.preventDefault();
    onSubmit();
  }

  if (collapsed && onToggleCollapsed) {
    const snippetSource =
      activeDemoTitle ??
      (value.text.trim() ||
        value.imageFiles[0]?.name ||
        value.audioFiles[0]?.name ||
        "Phiên kiểm tra hiện tại");
    const snippet =
      snippetSource.length > 92 ? `${snippetSource.slice(0, 90)}…` : snippetSource;

    return (
      <section
        aria-label="Tóm tắt thông tin đang kiểm tra"
        className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border-subtle bg-surface/95 px-4 py-3 shadow-md"
      >
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2 text-xs">
          <span className="truncate font-medium text-ink">{snippet}</span>

          {value.inActiveCall && (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-md border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-semibold text-rose-200">
              <PhoneCall className="h-3 w-3" aria-hidden="true" />
              <span>Đang nghe điện thoại</span>
            </span>
          )}
          {value.imageFiles.length > 0 && (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border-strong bg-surface-subtle px-2 py-0.5 font-mono text-[11px] text-ink-secondary">
              <ImageIcon className="h-3 w-3 text-amber-400" aria-hidden="true" />
              <span>
                {value.imageFiles.length === 1
                  ? value.imageFiles[0]?.name
                  : `${value.imageFiles.length} hình ảnh`}
              </span>
            </span>
          )}
          {value.audioFiles.length > 0 && (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border-strong bg-surface-subtle px-2 py-0.5 font-mono text-[11px] text-ink-secondary">
              <FileAudio className="h-3 w-3 text-sky-400" aria-hidden="true" />
              <span>
                {value.audioFiles.length === 1
                  ? value.audioFiles[0]?.name
                  : `${value.audioFiles.length} bản ghi âm`}
              </span>
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
      <div className="mb-3.5 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-base font-bold text-ink">Gửi nội dung cần kiểm tra</h2>

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

      <div className="space-y-3.5">
        <MultimodalComposer
          text={value.text}
          imageFiles={value.imageFiles}
          audioFiles={value.audioFiles}
          isAnalyzing={isAnalyzing}
          onTextChange={(nextText) => updateField("text", nextText)}
          onAttachmentsChange={(nextImages, nextAudios) =>
            onChange({ ...value, imageFiles: nextImages, audioFiles: nextAudios })
          }
        />

        {/* Collapsible Additional Transaction Details area */}
        <div className="rounded-xl border border-border-subtle bg-surface-subtle/85">
          <button
            type="button"
            aria-expanded={isExtraExpanded}
            aria-controls="wb-extra-transaction-panel"
            onClick={() => setExtraOpen((prev) => !prev)}
            className="flex min-h-[42px] w-full cursor-pointer items-center justify-between gap-2 rounded-xl px-3.5 py-2 text-left text-xs font-semibold text-ink-secondary transition-colors hover:text-ink"
          >
            <span className="inline-flex items-center gap-2">
              <SlidersHorizontal className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
              <span>Thông tin giao dịch bổ sung (tùy chọn)</span>
              {extraFieldsCount > 0 && (
                <span className="tabular-num rounded-md border border-amber-500/40 bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] text-amber-200">
                  {extraFieldsCount} mục
                </span>
              )}
            </span>
            {isExtraExpanded ? (
              <ChevronUp className="h-4 w-4 shrink-0 text-ink-muted" aria-hidden="true" />
            ) : (
              <ChevronDown className="h-4 w-4 shrink-0 text-ink-muted" aria-hidden="true" />
            )}
          </button>

          {isExtraExpanded && (
            <div
              id="wb-extra-transaction-panel"
              className="space-y-3 border-t border-border-subtle px-3.5 pt-3 pb-3.5"
            >
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label
                    htmlFor="wb-transfer-amount"
                    className="mb-1.5 block text-xs font-semibold text-ink-secondary"
                  >
                    Số tiền dự kiến chuyển (tùy chọn)
                  </label>
                  <div className="relative">
                    <input
                      id="wb-transfer-amount"
                      type="text"
                      inputMode="numeric"
                      autoComplete="off"
                      value={formatVndInputDisplay(value.transferAmount)}
                      onChange={(e) =>
                        updateField("transferAmount", parseRawAmountDigits(e.target.value))
                      }
                      placeholder="Ví dụ: 15.000.000"
                      className="tabular-num w-full rounded-xl border border-border-strong bg-surface py-2.5 pr-12 pl-3 font-mono text-xs text-ink placeholder:text-ink-muted focus:border-amber-400"
                    />
                    <span
                      aria-hidden="true"
                      className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 font-mono text-[11px] text-ink-muted"
                    >
                      VND
                    </span>
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="wb-merchant-stk"
                    className="mb-1.5 block text-xs font-semibold text-amber-300"
                  >
                    Số tài khoản nhận của cửa hàng (khi đối chiếu biên lai)
                  </label>
                  <input
                    id="wb-merchant-stk"
                    type="text"
                    value={value.expectedMerchantAccount}
                    onChange={(e) => updateField("expectedMerchantAccount", e.target.value)}
                    placeholder="Ví dụ: 190311112222"
                    className="tabular-num w-full rounded-xl border border-amber-500/45 bg-surface px-3 py-2.5 font-mono text-xs text-ink placeholder:text-ink-muted focus:border-amber-400"
                  />
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border-subtle bg-surface px-3.5 py-2.5">
                <div className="flex items-start gap-2.5">
                  <PhoneCall
                    className={`mt-0.5 h-4 w-4 shrink-0 ${
                      value.inActiveCall ? "text-rose-400" : "text-ink-muted"
                    }`}
                    aria-hidden="true"
                  />
                  <div>
                    <span id="wb-active-call-label" className="text-xs font-semibold text-ink">
                      Tôi đang nghe điện thoại khi chuẩn bị chuyển tiền
                    </span>
                    <p className="mt-0.5 text-[11px] text-ink-muted">
                      Tăng mức cảnh báo và bật nhắc tạm dừng 30 giây nếu đang có người thúc giục qua
                      điện thoại.
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
                  className="inline-flex min-h-[44px] min-w-[44px] cursor-pointer items-center justify-center rounded-lg px-1 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-400"
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
            </div>
          )}
        </div>

        <p className="text-[11px] leading-relaxed text-ink-muted">
          Số điện thoại và số tài khoản được che giấu trước khi lưu hồ sơ; tệp ảnh và ghi âm gốc
          không lưu trong cơ sở dữ liệu. Xem chi tiết tại{" "}
          <Link
            href="/privacy"
            className="font-medium text-ink-secondary underline decoration-border-strong underline-offset-2 transition-colors hover:text-ink"
          >
            Chính sách quyền riêng tư
          </Link>
          .
        </p>
      </div>
    </form>
  );
}
