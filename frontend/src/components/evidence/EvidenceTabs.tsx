"use client";

import {
  FileCheck2,
  FileText,
  GlobeLock,
  Image as ImageIcon,
  ListChecks,
  QrCode,
  X,
} from "lucide-react";
import { type KeyboardEvent, useEffect, useRef, useState } from "react";

import { shouldShowReceiptCard } from "@/lib/api";
import { formatEvidenceSource, SEVERITY_COPY } from "@/lib/copy";
import type { EvidenceTabKey } from "@/lib/explainableAi";
import type { AnalysisReport, SeverityLevel } from "@/lib/types";

import { ElaCompareView } from "./ElaCompareView";
import { PhishingSandboxCard } from "./PhishingSandboxCard";
import { ReceiptCheckCard } from "./ReceiptCheckCard";
import { TextEvidenceCompare } from "./TextEvidenceCompare";
import { VietQrCard } from "./VietQrCard";

export type ExtendedEvidenceTabKey = EvidenceTabKey | "text";

interface EvidenceTabsProps {
  report: AnalysisReport;
  originalPreviewUrl: string | null;
  originalPreviewUrls?: string[];
  submittedText?: string;
  activeTab?: ExtendedEvidenceTabKey;
  onTabChange?: (tab: ExtendedEvidenceTabKey) => void;
  highlightedSource?: string | null;
  onClearHighlightedSource?: () => void;
}

const SEVERITY_STYLES: Record<SeverityLevel, string> = {
  CRITICAL: "bg-rose-500/20 text-rose-200 border-rose-500/45",
  HIGH: "bg-orange-500/20 text-orange-200 border-orange-500/45",
  MEDIUM: "bg-amber-500/20 text-amber-200 border-amber-500/45",
  LOW: "bg-sky-500/20 text-sky-200 border-sky-500/45",
  INFO: "bg-surface-elevated text-ink-secondary border-border-strong",
};

export function EvidenceTabs({
  report,
  originalPreviewUrl,
  originalPreviewUrls = [],
  submittedText = "",
  activeTab: controlledTab,
  onTabChange,
  highlightedSource = null,
  onClearHighlightedSource,
}: EvidenceTabsProps) {
  const [internalTab, setInternalTab] = useState<ExtendedEvidenceTabKey>("all");
  const [selectedImageIdx, setSelectedImageIdx] = useState<number>(0);
  const [severityFilter, setSeverityFilter] = useState<"ALL" | SeverityLevel>("ALL");
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  const activeTab = controlledTab ?? internalTab;

  function selectTab(next: ExtendedEvidenceTabKey) {
    setInternalTab(next);
    onTabChange?.(next);
  }

  useEffect(() => {
    setSeverityFilter("ALL");
    setSelectedImageIdx(0);
  }, [report.case_id]);

  const showReceiptCard = shouldShowReceiptCard(report);
  const allForensics =
    report.image_forensics_list && report.image_forensics_list.length > 0
      ? report.image_forensics_list
      : report.image_forensics
        ? [report.image_forensics]
        : [];
  const safeImageIdx = Math.min(selectedImageIdx, Math.max(0, allForensics.length - 1));
  const activeForensics = allForensics[safeImageIdx] ?? report.image_forensics ?? null;
  const activePreviewUrl =
    originalPreviewUrls[safeImageIdx] ?? (safeImageIdx === 0 ? originalPreviewUrl : null);

  const indicatorCount =
    report.iocs.phones.length +
    report.iocs.bank_accounts.length +
    report.iocs.domains.length +
    report.iocs.urls.length +
    report.highlighted_phrases.length;

  const tabs: Array<{
    id: ExtendedEvidenceTabKey;
    label: string;
    count: number;
    Icon: typeof ListChecks;
  }> = [
    {
      id: "all",
      label: "Tổng hợp bằng chứng",
      count: report.evidence.length,
      Icon: ListChecks,
    },
    {
      id: "text",
      label: "Văn bản & Dấu hiệu",
      count: indicatorCount,
      Icon: FileText,
    },
    {
      id: "ela",
      label: "Tính xác thực hình ảnh",
      count: allForensics.length,
      Icon: ImageIcon,
    },
    {
      id: "receipt",
      label: "Đối chiếu biên lai",
      count: showReceiptCard ? 1 : 0,
      Icon: FileCheck2,
    },
    {
      id: "vietqr",
      label: "Kiểm tra mã VietQR",
      count: report.vietqr_findings.length,
      Icon: QrCode,
    },
    {
      id: "url",
      label: "Kiểm tra đường dẫn",
      count: report.url_findings.length + (report.sandbox ? 1 : 0),
      Icon: GlobeLock,
    },
  ];

  const filteredEvidence = report.evidence.filter((ev) => {
    if (severityFilter !== "ALL" && ev.severity !== severityFilter) return false;
    return true;
  });

  const sortedEvidence = highlightedSource
    ? [...filteredEvidence].sort((a, b) => {
        const aMatch = a.source === highlightedSource ? 1 : 0;
        const bMatch = b.source === highlightedSource ? 1 : 0;
        return bMatch - aMatch;
      })
    : filteredEvidence;

  function handleTabKeyDown(ev: KeyboardEvent<HTMLButtonElement>, idx: number) {
    let nextIdx = idx;
    if (ev.key === "ArrowRight") {
      nextIdx = (idx + 1) % tabs.length;
    } else if (ev.key === "ArrowLeft") {
      nextIdx = (idx - 1 + tabs.length) % tabs.length;
    } else if (ev.key === "Home") {
      nextIdx = 0;
    } else if (ev.key === "End") {
      nextIdx = tabs.length - 1;
    } else {
      return;
    }
    ev.preventDefault();
    const targetTab = tabs[nextIdx];
    if (targetTab) {
      selectTab(targetTab.id);
      tabRefs.current[nextIdx]?.focus();
    }
  }

  return (
    <section
      id="evidence-viewer-panel"
      aria-label="Chi tiết bằng chứng kiểm tra"
      className="scroll-mt-[84px] rounded-2xl border border-border-subtle bg-surface/95 p-5 shadow-lg"
    >
      <div
        role="tablist"
        aria-label="Các mục bằng chứng kiểm tra"
        className="mb-4 flex flex-wrap gap-2 border-b border-border-subtle pb-3"
      >
        {tabs.map(({ id, label, count, Icon }, idx) => {
          const selected = activeTab === id;
          return (
            <button
              key={id}
              ref={(el) => {
                tabRefs.current[idx] = el;
              }}
              id={`ev-tab-${id}`}
              type="button"
              role="tab"
              tabIndex={selected ? 0 : -1}
              aria-selected={selected}
              aria-controls={`ev-panel-${id}`}
              onClick={() => selectTab(id)}
              onKeyDown={(ev) => handleTabKeyDown(ev, idx)}
              className={`vs-pressable inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold ${
                selected
                  ? "border-amber-400 bg-amber-500/15 text-amber-200"
                  : "border-border-subtle bg-surface-subtle text-ink-secondary hover:border-border-strong hover:text-ink"
              }`}
            >
              <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span>{label}</span>
              <span className="tabular-num rounded bg-surface-elevated px-1.5 py-0.5 font-mono text-[10px] text-ink-secondary">
                {count}
              </span>
            </button>
          );
        })}
      </div>

      <div id={`ev-panel-${activeTab}`} role="tabpanel" aria-labelledby={`ev-tab-${activeTab}`}>
        {activeTab === "all" && (
          <div className="space-y-3">
            {(highlightedSource || report.evidence.length > 2) && (
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div
                  role="group"
                  aria-label="Lọc bằng chứng theo mức độ nghiêm trọng"
                  className="flex flex-wrap items-center gap-1.5 text-[10.5px]"
                >
                  {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const).map((lvl) => {
                    const count =
                      lvl === "ALL"
                        ? report.evidence.length
                        : report.evidence.filter((e) => e.severity === lvl).length;
                    if (lvl !== "ALL" && count === 0) return null;
                    const active = severityFilter === lvl;
                    return (
                      <button
                        key={lvl}
                        type="button"
                        aria-pressed={active}
                        onClick={() => setSeverityFilter(lvl)}
                        className={`tabular-num min-h-[28px] cursor-pointer rounded-md border px-2 py-0.5 font-semibold transition-colors ${
                          active
                            ? "border-amber-400 bg-amber-500/15 text-amber-200"
                            : "border-border-subtle bg-surface-subtle text-ink-muted hover:text-ink-secondary"
                        }`}
                      >
                        {lvl === "ALL" ? `Tất cả (${count})` : `${SEVERITY_COPY[lvl]} (${count})`}
                      </button>
                    );
                  })}
                </div>

                {highlightedSource && (
                  <div className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/45 bg-amber-500/12 px-2.5 py-1 text-[11px] text-amber-200">
                    <span>Đang nổi bật: {formatEvidenceSource(highlightedSource)}</span>
                    {onClearHighlightedSource && (
                      <button
                        type="button"
                        onClick={onClearHighlightedSource}
                        aria-label="Bỏ đánh dấu nguồn bằng chứng"
                        className="inline-flex h-5 w-5 cursor-pointer items-center justify-center rounded hover:bg-amber-500/25"
                      >
                        <X className="h-3 w-3" aria-hidden="true" />
                      </button>
                    )}
                  </div>
                )}
              </div>
            )}

            {sortedEvidence.length === 0 ? (
              <p className="text-xs text-ink-muted">
                Chưa ghi nhận dấu hiệu bất thường nào từ dữ liệu bạn cung cấp.
              </p>
            ) : (
              sortedEvidence.map((ev, idx) => {
                const isHighlighted = highlightedSource !== null && ev.source === highlightedSource;
                return (
                  <div
                    key={`${ev.source}-${ev.title}-${idx}`}
                    className={`rounded-xl border p-3.5 transition-colors ${
                      isHighlighted
                        ? "border-amber-400/75 bg-amber-500/10 ring-1 ring-amber-400/35"
                        : "border-border-subtle bg-surface-subtle"
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-ink">{ev.title}</span>
                      <div className="flex items-center gap-1.5">
                        <span className="text-[11px] text-ink-muted">
                          {formatEvidenceSource(ev.source)}
                        </span>
                        <span
                          className={`rounded border px-2 py-0.5 text-[10px] font-bold ${
                            SEVERITY_STYLES[ev.severity]
                          }`}
                        >
                          {SEVERITY_COPY[ev.severity]}
                        </span>
                      </div>
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-ink-secondary">{ev.detail}</p>
                    {ev.snippet && (
                      <code className="mt-1.5 block truncate rounded bg-surface-elevated px-2 py-1 font-mono text-[11px] text-amber-200">
                        {ev.snippet}
                      </code>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}

        {activeTab === "text" && (
          <TextEvidenceCompare report={report} submittedText={submittedText} />
        )}

        {activeTab === "ela" &&
          (activeForensics ? (
            <div className="space-y-3">
              {allForensics.length > 1 && (
                <div
                  role="group"
                  aria-label="Chọn hình ảnh để xem chi tiết"
                  className="flex flex-wrap gap-1.5"
                >
                  {allForensics.map((imgItem, idx) => (
                    <button
                      key={`${imgItem.dhash_hex}-${idx}`}
                      type="button"
                      aria-pressed={idx === safeImageIdx}
                      onClick={() => setSelectedImageIdx(idx)}
                      className={`inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors ${
                        idx === safeImageIdx
                          ? "border-amber-400 bg-amber-500/15 text-amber-200"
                          : "border-border-subtle bg-surface-subtle text-ink-secondary hover:border-border-strong hover:text-ink"
                      }`}
                    >
                      <span>Ảnh {idx + 1}</span>
                      <span className="tabular-num font-mono text-[10px] text-ink-muted">
                        ({imgItem.tamper_score}/100)
                      </span>
                    </button>
                  ))}
                </div>
              )}
              <ElaCompareView
                forensics={activeForensics}
                originalPreviewUrl={activePreviewUrl}
              />
            </div>
          ) : (
            <p className="text-xs text-ink-muted">
              Chưa có hình ảnh nào được tải lên trong lượt kiểm tra này.
            </p>
          ))}

        {activeTab === "receipt" &&
          (showReceiptCard ? (
            <ReceiptCheckCard
              receipt={report.receipt_logic}
              verificationStatus={report.receipt_verification_status}
              merchantBalanceWarning={report.actions.merchant_balance_warning}
              imageForensics={report.image_forensics}
            />
          ) : (
            <p className="text-xs text-ink-muted">
              Nội dung này không phải ảnh chụp biên lai chuyển khoản ngân hàng.
            </p>
          ))}

        {activeTab === "vietqr" && <VietQrCard items={report.vietqr_findings} />}

        {activeTab === "url" && (
          <PhishingSandboxCard urls={report.url_findings} sandbox={report.sandbox} />
        )}
      </div>
    </section>
  );
}
