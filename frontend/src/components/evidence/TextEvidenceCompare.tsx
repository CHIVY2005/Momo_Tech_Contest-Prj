"use client";

import { Check, Copy, FileText, Highlighter, ScanText } from "lucide-react";
import { useMemo, useState } from "react";

import { defangUrlForDisplay, maskDisplayIoc } from "@/lib/formatters";
import { highlightSuspiciousText } from "@/lib/explainableAi";
import type { AnalysisReport } from "@/lib/types";

interface TextEvidenceCompareProps {
  report: AnalysisReport;
  submittedText?: string;
}

function HighlightedBlock({
  text,
  phrases,
}: {
  text: string;
  phrases: readonly string[];
}) {
  const segments = useMemo(() => highlightSuspiciousText(text, phrases), [text, phrases]);
  return (
    <p className="whitespace-pre-wrap break-words font-mono text-[11.5px] leading-relaxed text-ink-secondary">
      {segments.map((seg, idx) =>
        seg.highlighted ? (
          <mark
            key={`hl-${idx}`}
            className="rounded border border-amber-400/50 bg-amber-500/22 px-1 py-0.5 font-semibold text-amber-100"
          >
            {seg.text}
          </mark>
        ) : (
          <span key={`pl-${idx}`}>{seg.text}</span>
        ),
      )}
    </p>
  );
}

export function TextEvidenceCompare({
  report,
  submittedText = "",
}: TextEvidenceCompareProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const ocrTexts = useMemo(() => {
    const list =
      report.image_forensics_list && report.image_forensics_list.length > 0
        ? report.image_forensics_list
        : report.image_forensics
          ? [report.image_forensics]
          : [];
    return list
      .map((item, idx) => ({
        label: list.length > 1 ? `Văn bản OCR (Ảnh ${idx + 1})` : "Văn bản trích xuất từ ảnh (OCR)",
        text: item.ocr_text.trim(),
        provider: item.ocr_provider,
        confidence: item.ocr_confidence,
      }))
      .filter((item) => item.text.length > 0);
  }, [report.image_forensics, report.image_forensics_list]);

  const indicators = useMemo(() => {
    const out: Array<{ key: string; label: string; value: string; copyText: string }> = [];
    for (const phone of report.iocs.phones) {
      const masked = maskDisplayIoc(phone);
      out.push({ key: `tel-${masked}`, label: "SĐT", value: masked, copyText: masked });
    }
    for (const acct of report.iocs.bank_accounts) {
      const masked = maskDisplayIoc(acct);
      out.push({ key: `stk-${masked}`, label: "STK", value: masked, copyText: masked });
    }
    for (const dom of report.iocs.domains) {
      out.push({
        key: `dom-${dom}`,
        label: "Tên miền",
        value: defangUrlForDisplay(dom),
        copyText: defangUrlForDisplay(dom),
      });
    }
    for (const u of report.iocs.urls) {
      const defanged = defangUrlForDisplay(u);
      out.push({ key: `url-${u}`, label: "URL (vô hiệu hóa)", value: defanged, copyText: defanged });
    }
    return out;
  }, [report.iocs]);

  async function handleCopy(key: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      window.setTimeout(() => setCopiedKey((curr) => (curr === key ? null : curr)), 1800);
    } catch {
      // Clipboard unavailable
    }
  }

  const trimmedSubmitted = submittedText.trim();
  const hasExtracted = ocrTexts.length > 0 || Boolean(report.transcript?.trim());

  return (
    <div className="space-y-3.5">
      {report.highlighted_phrases.length > 0 && (
        <div className="rounded-xl border border-amber-500/35 bg-amber-500/8 p-3">
          <p className="mb-1.5 inline-flex items-center gap-1.5 text-[11px] font-semibold text-amber-200">
            <Highlighter className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
            <span>Cụm từ đáng ngờ được làm nổi bật ({report.highlighted_phrases.length})</span>
          </p>
          <div className="flex flex-wrap gap-1.5">
            {report.highlighted_phrases.map((phrase, idx) => (
              <span
                key={`${phrase}-${idx}`}
                className="rounded-md border border-amber-400/45 bg-amber-500/18 px-2 py-0.5 text-[11px] font-medium text-amber-100"
              >
                &ldquo;{phrase}&rdquo;
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Side-by-side Original vs Extracted OCR / Transcript */}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3.5">
          <div className="mb-2 flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-ink">
              <FileText className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
              <span>Nội dung gốc bạn gửi</span>
            </span>
            {trimmedSubmitted && (
              <button
                type="button"
                onClick={() => void handleCopy("orig-text", trimmedSubmitted)}
                className="inline-flex cursor-pointer items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium text-ink-muted hover:bg-surface hover:text-ink"
              >
                {copiedKey === "orig-text" ? (
                  <>
                    <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                    <span className="text-emerald-300">Đã sao chép</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3" aria-hidden="true" />
                    <span>Sao chép</span>
                  </>
                )}
              </button>
            )}
          </div>
          {trimmedSubmitted ? (
            <div data-lenis-prevent className="max-h-56 overflow-y-auto rounded-lg bg-surface-deep/75 p-2.5">
              <HighlightedBlock text={trimmedSubmitted} phrases={report.highlighted_phrases} />
            </div>
          ) : (
            <p className="text-xs text-ink-muted">
              Không có văn bản nhập trực tiếp trong lượt kiểm tra này.
            </p>
          )}
        </div>

        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3.5">
          <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-ink">
            <ScanText className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
            <span>Văn bản trích xuất (OCR / Ghi âm)</span>
          </div>

          {!hasExtracted ? (
            <p className="text-xs text-ink-muted">
              Không có văn bản trích xuất từ hình ảnh hoặc tệp ghi âm trong hồ sơ này.
            </p>
          ) : (
            <div className="space-y-2.5">
              {ocrTexts.map((entry, idx) => (
                <div key={`ocr-${idx}`} className="space-y-1">
                  <div className="flex flex-wrap items-center justify-between gap-1 text-[10.5px] text-ink-muted">
                    <span>{entry.label}</span>
                    {entry.provider && (
                      <span className="tabular-num font-mono">
                        {entry.provider}
                        {typeof entry.confidence === "number" && entry.confidence > 0
                          ? ` · ${Math.round(entry.confidence * 100)}%`
                          : ""}
                      </span>
                    )}
                  </div>
                  <div data-lenis-prevent className="max-h-44 overflow-y-auto rounded-lg bg-surface-deep/75 p-2.5">
                    <HighlightedBlock text={entry.text} phrases={report.highlighted_phrases} />
                  </div>
                </div>
              ))}

              {report.transcript?.trim() && (
                <div className="space-y-1">
                  <p className="text-[10.5px] text-ink-muted">Lời thoại chuyển từ tệp ghi âm (STT)</p>
                  <div data-lenis-prevent className="max-h-44 overflow-y-auto rounded-lg bg-surface-deep/75 p-2.5">
                    <HighlightedBlock
                      text={report.transcript.trim()}
                      phrases={report.highlighted_phrases}
                    />
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Extracted Indicators Copy Strip (Masked & Defanged — NEVER clickable phishing links) */}
      <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3.5">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs font-semibold text-ink">
            Chỉ báo trích xuất đã che giấu / vô hiệu hóa ({indicators.length})
          </p>
          {indicators.length > 0 && (
            <button
              type="button"
              onClick={() =>
                void handleCopy(
                  "all-indicators",
                  indicators.map((i) => `${i.label}: ${i.copyText}`).join("\n"),
                )
              }
              className="vs-pressable inline-flex min-h-[28px] cursor-pointer items-center gap-1 rounded-md border border-border-strong bg-surface px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:border-amber-400 hover:text-ink"
            >
              {copiedKey === "all-indicators" ? (
                <>
                  <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                  <span className="text-emerald-300">Đã sao chép toàn bộ</span>
                </>
              ) : (
                <>
                  <Copy className="h-3 w-3" aria-hidden="true" />
                  <span>Sao chép tất cả chỉ báo</span>
                </>
              )}
            </button>
          )}
        </div>

        {indicators.length === 0 ? (
          <p className="text-xs text-ink-muted">
            Chưa tách được số điện thoại, số tài khoản hoặc tên miền cụ thể nào.
          </p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {indicators.map((ind) => (
              <button
                key={ind.key}
                type="button"
                onClick={() => void handleCopy(ind.key, ind.copyText)}
                title="Nhấp để sao chép chỉ báo đã vô hiệu hóa an toàn"
                className="inline-flex max-w-full cursor-pointer items-center gap-1.5 rounded-lg border border-border-strong bg-surface px-2.5 py-1 font-mono text-[11px] text-ink-secondary transition-colors hover:border-sky-400 hover:text-ink"
              >
                <span className="text-[10px] font-sans font-semibold text-amber-300">
                  {ind.label}:
                </span>
                <span className="max-w-[220px] truncate">{ind.value}</span>
                {copiedKey === ind.key ? (
                  <Check className="h-3 w-3 shrink-0 text-emerald-400" aria-hidden="true" />
                ) : (
                  <Copy className="h-3 w-3 shrink-0 text-ink-muted" aria-hidden="true" />
                )}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
