"use client";

import { FileCheck2, GlobeLock, Image as ImageIcon, ListChecks, QrCode } from "lucide-react";
import { type KeyboardEvent, useRef, useState } from "react";

import { shouldShowReceiptCard } from "@/lib/api";
import type { AnalysisReport, SeverityLevel } from "@/lib/types";

import { ElaCompareView } from "./ElaCompareView";
import { PhishingSandboxCard } from "./PhishingSandboxCard";
import { ReceiptCheckCard } from "./ReceiptCheckCard";
import { VietQrCard } from "./VietQrCard";

interface EvidenceTabsProps {
  report: AnalysisReport;
  originalPreviewUrl: string | null;
}

type EvidenceTabKey = "all" | "ela" | "receipt" | "vietqr" | "url";

const SEVERITY_STYLES: Record<SeverityLevel, string> = {
  CRITICAL: "bg-rose-500/20 text-rose-200 border-rose-500/40",
  HIGH: "bg-orange-500/20 text-orange-200 border-orange-500/40",
  MEDIUM: "bg-amber-500/20 text-amber-200 border-amber-500/40",
  LOW: "bg-sky-500/20 text-sky-200 border-sky-500/40",
  INFO: "bg-slate-800 text-slate-300 border-slate-700",
};

export function EvidenceTabs({ report, originalPreviewUrl }: EvidenceTabsProps) {
  const [activeTab, setActiveTab] = useState<EvidenceTabKey>("all");
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  const showReceiptCard = shouldShowReceiptCard(report);

  const tabs: Array<{
    id: EvidenceTabKey;
    label: string;
    count: number;
    Icon: typeof ListChecks;
  }> = [
    {
      id: "all",
      label: "Bằng chứng Tổng hợp",
      count: report.evidence.length,
      Icon: ListChecks,
    },
    {
      id: "ela",
      label: "Pháp y Ảnh & ELA",
      count: report.image_forensics ? 1 : 0,
      Icon: ImageIcon,
    },
    {
      id: "receipt",
      label: "Nghiệp vụ Biên lai",
      count: showReceiptCard ? 1 : 0,
      Icon: FileCheck2,
    },
    {
      id: "vietqr",
      label: "Giải mã VietQR",
      count: report.vietqr_findings.length,
      Icon: QrCode,
    },
    {
      id: "url",
      label: "URL & Sandbox",
      count: report.url_findings.length + (report.sandbox ? 1 : 0),
      Icon: GlobeLock,
    },
  ];

  function handleTabKeyDown(ev: KeyboardEvent<HTMLButtonElement>, idx: number) {
    let nextIdx = idx;
    if (ev.key === "ArrowRight") {
      nextIdx = (idx + 1) % tabs.length;
    } else if (ev.key === "ArrowLeft") {
      nextIdx = (idx - 1 + tabs.length) % tabs.length;
    } else {
      return;
    }
    ev.preventDefault();
    const targetTab = tabs[nextIdx];
    if (targetTab) {
      setActiveTab(targetTab.id);
      tabRefs.current[nextIdx]?.focus();
    }
  }

  return (
    <section
      aria-label="Hồ sơ bằng chứng pháp y chi tiết"
      className="rounded-2xl border border-slate-800 bg-[#111827]/95 p-5 shadow-lg"
    >
      <div
        role="tablist"
        aria-label="Các lớp bằng chứng kỹ thuật"
        className="mb-4 flex flex-wrap gap-2 border-b border-slate-800 pb-3"
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
              onClick={() => setActiveTab(id)}
              onKeyDown={(ev) => handleTabKeyDown(ev, idx)}
              className={`inline-flex cursor-pointer items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors ${
                selected
                  ? "border-amber-400 bg-amber-500/15 text-amber-200"
                  : "border-slate-800 bg-[#0b1120] text-slate-300 hover:border-slate-600"
              }`}
            >
              <Icon className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{label}</span>
              <span className="rounded bg-slate-900 px-1.5 py-0.5 font-[family-name:var(--font-mono)] text-[10px] text-slate-300">
                {count}
              </span>
            </button>
          );
        })}
      </div>

      <div id={`ev-panel-${activeTab}`} role="tabpanel" aria-labelledby={`ev-tab-${activeTab}`}>
        {activeTab === "all" && (
          <div className="space-y-2.5">
            {report.evidence.length === 0 ? (
              <p className="text-xs text-slate-400">
                Không ghi nhận chỉ báo rủi ro kỹ thuật nào trên nội dung vừa kiểm tra.
              </p>
            ) : (
              report.evidence.map((ev, idx) => (
                <div
                  key={`${ev.source}-${ev.title}-${idx}`}
                  className="rounded-xl border border-slate-800 bg-[#0b1120] p-3.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-100">{ev.title}</span>
                    <div className="flex items-center gap-1.5">
                      <span className="font-[family-name:var(--font-mono)] text-[10px] text-slate-400">
                        {ev.source}
                      </span>
                      <span
                        className={`rounded border px-2 py-0.5 font-[family-name:var(--font-mono)] text-[10px] font-bold ${
                          SEVERITY_STYLES[ev.severity]
                        }`}
                      >
                        {ev.severity}
                      </span>
                    </div>
                  </div>
                  <p className="mt-1 text-xs leading-relaxed text-slate-300">{ev.detail}</p>
                  {ev.snippet && (
                    <code className="mt-1.5 block truncate rounded bg-slate-900 px-2 py-1 font-[family-name:var(--font-mono)] text-[11px] text-amber-200">
                      {ev.snippet}
                    </code>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "ela" &&
          (report.image_forensics ? (
            <ElaCompareView
              forensics={report.image_forensics}
              originalPreviewUrl={originalPreviewUrl}
            />
          ) : (
            <p className="text-xs text-slate-400">
              Chưa có tệp hình ảnh nào được tải lên trong phiên phân tích này.
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
            <p className="text-xs text-slate-400">
              Nội dung hiện tại không phải ảnh chụp biên lai chuyển khoản ngân hàng.
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
