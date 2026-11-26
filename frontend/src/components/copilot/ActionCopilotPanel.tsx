"use client";

import { Check, Copy, FileDown, HeartHandshake, MessageSquareReply, Shield } from "lucide-react";
import { useState } from "react";

import { getReportPdfUrl } from "@/lib/api";
import type { AnalysisReport } from "@/lib/types";

interface ActionCopilotPanelProps {
  report: AnalysisReport;
}

export function ActionCopilotPanel({ report }: ActionCopilotPanelProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const { actions } = report;

  async function copyText(key: string, content: string) {
    try {
      await navigator.clipboard.writeText(content);
      setCopiedKey(key);
      window.setTimeout(() => {
        setCopiedKey((curr) => (curr === key ? null : curr));
      }, 2000);
    } catch {
      // Clipboard API unavailable in non-secure context
    }
  }

  return (
    <aside
      aria-labelledby="action-copilot-heading"
      className="space-y-4 rounded-2xl border border-border-subtle bg-surface/95 p-5 shadow-lg"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-amber-400" aria-hidden="true" />
          <h3 id="action-copilot-heading" className="text-sm font-bold text-ink">
            Hướng dẫn xử lý nhanh
          </h3>
        </div>

        <a
          href={getReportPdfUrl(report.case_id)}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex min-h-[38px] items-center gap-1.5 rounded-lg border border-amber-500/45 bg-amber-500/15 px-3 py-1.5 text-xs font-semibold text-amber-200 transition-colors hover:bg-amber-500/25"
        >
          <FileDown className="h-3.5 w-3.5" aria-hidden="true" />
          <span>Tải báo cáo bằng chứng (PDF)</span>
        </a>
      </div>

      {actions.urgent_steps.length > 0 && (
        <div className="rounded-xl border border-border-subtle bg-surface-subtle p-3.5">
          <p className="mb-2 text-xs font-semibold text-ink">Việc cần làm ngay:</p>
          <ol className="list-inside list-decimal space-y-1.5 text-xs leading-relaxed text-ink-secondary">
            {actions.urgent_steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
        </div>
      )}

      {actions.counter_replies.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-ink">
            <MessageSquareReply className="h-4 w-4 text-sky-400" aria-hidden="true" />
            <span>Gợi ý câu trả lời an toàn (sao chép một chạm):</span>
          </div>
          {actions.counter_replies.map((reply, idx) => {
            const key = `reply-${idx}`;
            const isCopied = copiedKey === key;
            return (
              <div
                key={key}
                className="flex items-start justify-between gap-2 rounded-xl border border-border-subtle bg-surface-subtle p-3"
              >
                <p className="text-xs leading-relaxed text-ink-secondary">&ldquo;{reply}&rdquo;</p>
                <button
                  type="button"
                  onClick={() => void copyText(key, reply)}
                  aria-label={`Sao chép gợi ý câu trả lời số ${idx + 1}`}
                  className="inline-flex min-h-[34px] shrink-0 cursor-pointer items-center gap-1 rounded-lg border border-border-strong bg-surface-elevated px-2.5 py-1 text-[11px] font-medium text-ink hover:border-amber-400"
                >
                  {isCopied ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                      <span>Đã sao chép</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>Sao chép</span>
                    </>
                  )}
                </button>
              </div>
            );
          })}
        </div>
      )}

      {actions.family_shield_message && (
        <div className="rounded-xl border border-sky-500/35 bg-sky-500/10 p-3.5">
          <div className="mb-1.5 flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-sky-200">
              <HeartHandshake className="h-4 w-4 text-sky-400" aria-hidden="true" />
              <span>Gửi cảnh báo nhanh cho người thân</span>
            </div>
            <button
              type="button"
              onClick={() => void copyText("family", actions.family_shield_message)}
              className="inline-flex min-h-[34px] cursor-pointer items-center gap-1 rounded-lg border border-sky-500/45 bg-surface-subtle px-2.5 py-1 text-[11px] font-medium text-sky-200 hover:border-sky-300"
            >
              {copiedKey === "family" ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                  <span>Đã sao chép</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Sao chép tin nhắn</span>
                </>
              )}
            </button>
          </div>
          <p className="text-xs leading-relaxed text-ink-secondary">
            {actions.family_shield_message}
          </p>
        </div>
      )}
    </aside>
  );
}
