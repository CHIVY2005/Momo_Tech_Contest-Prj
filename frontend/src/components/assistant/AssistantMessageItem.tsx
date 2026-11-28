"use client";

import {
  AlertCircle,
  AlertTriangle,
  BookMarked,
  Check,
  CheckCircle2,
  ChevronDown,
  Copy,
  Loader2,
  Paperclip,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import { memo, useEffect, useRef, useState } from "react";

import type {
  AssistantCitationItem,
  AssistantEvidenceReportEvent,
  AssistantSafetyNoticeEvent,
  AssistantToolStatusEvent,
} from "@/lib/types";

import { AssistantThinkingIndicator } from "@/components/motion/AssistantThinkingIndicator";
import {
  AssistantEvidenceCard,
  type PersistedEvidenceState,
} from "./AssistantEvidenceCard";
import { SafeMarkdown } from "./SafeMarkdown";

export interface AssistantChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  attachmentLabel?: string | null;
  isStreaming?: boolean;
  statusLabel?: string | null;
  safetyNotices?: AssistantSafetyNoticeEvent[];
  toolStatuses?: AssistantToolStatusEvent[];
  citations?: AssistantCitationItem[];
  evidenceReport?: AssistantEvidenceReportEvent | null;
  persistedEvidence?: PersistedEvidenceState | null;
  degradedMode?: boolean;
  outputTier?: 0 | 1 | 2 | null;
  suggestedFollowups?: string[];
  errorMessage?: string | null;
}

interface AssistantMessageItemProps {
  message: AssistantChatMessage;
  isLatestAssistant: boolean;
  disabled?: boolean;
  canRegenerate?: boolean;
  parentCaseId?: string;
  caseAccessToken?: string | null;
  onEvidencePersisted?: (messageId: string, state: PersistedEvidenceState) => void;
  onSelectFollowup?: (question: string) => void;
  onRetry?: () => void;
  onRegenerate?: (messageId: string) => void;
}

function formatCitationTag(sourceType: string): { tag: string; label: string; style: string } {
  const normalized = sourceType.toLowerCase();
  if (normalized === "case") {
    return {
      tag: "[CASE]",
      label: "Hồ sơ đang xem",
      style: "border-sky-500/35 bg-sky-500/10 text-sky-200",
    };
  }
  if (normalized === "tool") {
    return {
      tag: "[TOOL]",
      label: "Công cụ xác minh",
      style: "border-emerald-500/35 bg-emerald-500/10 text-emerald-200",
    };
  }
  return {
    tag: "[KB]",
    label: "Kho tri thức",
    style: "border-amber-500/35 bg-amber-500/10 text-amber-200",
  };
}

export const AssistantMessageItem = memo(function AssistantMessageItem({
  message,
  isLatestAssistant,
  disabled = false,
  canRegenerate = false,
  parentCaseId,
  caseAccessToken = null,
  onEvidencePersisted,
  onSelectFollowup,
  onRetry,
  onRegenerate,
}: AssistantMessageItemProps) {
  const [copiedReply, setCopiedReply] = useState(false);
  const [refsExpanded, setRefsExpanded] = useState(false);
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  if (message.role === "user") {
    return (
      <div className="flex justify-end">
        <div className="min-w-0 max-w-[88%] space-y-1.5 rounded-2xl rounded-br-sm border border-sky-500/35 bg-sky-500/15 px-3.5 py-2.5 text-xs leading-relaxed text-ink whitespace-pre-wrap wrap-anywhere">
          {message.attachmentLabel && (
            <div className="inline-flex max-w-full items-center gap-1 rounded-md border border-sky-400/40 bg-surface-deep/60 px-2 py-0.5 text-[10px] font-medium text-sky-200">
              <Paperclip className="h-3 w-3 shrink-0" aria-hidden="true" />
              <span className="truncate">{message.attachmentLabel}</span>
            </div>
          )}
          <div>{message.content}</div>
        </div>
      </div>
    );
  }

  const safetyNotices = message.safetyNotices ?? [];
  const toolStatuses = message.toolStatuses ?? [];
  const citations = message.citations ?? [];
  const suggestedFollowups = message.suggestedFollowups ?? [];
  const showFollowups =
    isLatestAssistant &&
    !message.isStreaming &&
    !message.errorMessage &&
    suggestedFollowups.length > 0 &&
    Boolean(onSelectFollowup);
  const showMessageActions = !message.isStreaming && message.content.trim().length > 0;
  const showRegenerate =
    isLatestAssistant &&
    showMessageActions &&
    !message.errorMessage &&
    canRegenerate &&
    Boolean(onRegenerate);

  async function handleCopyReply() {
    try {
      await navigator.clipboard.writeText(message.content);
      setCopiedReply(true);
      if (copyTimerRef.current !== null) window.clearTimeout(copyTimerRef.current);
      copyTimerRef.current = window.setTimeout(() => setCopiedReply(false), 1800);
    } catch {
      // Clipboard API unavailable in restricted context
    }
  }

  return (
    <div className="flex justify-start">
      <article
        aria-label="Phản hồi từ Trợ lý VeriShield"
        className="w-full min-w-0 space-y-2.5 rounded-2xl rounded-bl-sm border border-border-subtle bg-surface-subtle p-3.5 wrap-anywhere shadow-sm"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="inline-flex items-center gap-1.5 text-[11px] font-bold text-ink">
            <Shield className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
            <span>Trợ lý VeriShield</span>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {message.outputTier === 0 && !message.isStreaming && (
              <span className="inline-flex items-center gap-1 rounded-md border border-emerald-500/35 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-200">
                <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
                <span>Phản hồi xác định</span>
              </span>
            )}
            {message.degradedMode && (
              <span className="inline-flex items-center gap-1 rounded-md border border-amber-500/45 bg-amber-500/15 px-2 py-0.5 text-[10px] font-semibold text-amber-200">
                <BookMarked className="h-3 w-3" aria-hidden="true" />
                <span>Chế độ dự phòng từ Kho Tri thức cục bộ</span>
              </span>
            )}
            {showMessageActions && (
              <div className="inline-flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => void handleCopyReply()}
                  aria-label="Sao chép phản hồi của Trợ lý"
                  title="Sao chép phản hồi"
                  className="vs-pressable inline-flex min-h-[26px] cursor-pointer items-center gap-1 rounded-md border border-border-subtle bg-surface px-2 py-0.5 text-[10px] font-medium text-ink-muted hover:border-amber-400/60 hover:text-ink"
                >
                  {copiedReply ? (
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

                {showRegenerate && onRegenerate && (
                  <button
                    type="button"
                    disabled={disabled}
                    onClick={() => onRegenerate(message.id)}
                    aria-label="Tạo lại phản hồi"
                    title="Tạo lại phản hồi cho câu hỏi gần nhất"
                    className="vs-pressable inline-flex min-h-[26px] cursor-pointer items-center gap-1 rounded-md border border-border-subtle bg-surface px-2 py-0.5 text-[10px] font-medium text-ink-muted hover:border-sky-400/60 hover:text-ink disabled:cursor-not-allowed disabled:opacity-45"
                  >
                    <RefreshCw className="h-3 w-3" aria-hidden="true" />
                    <span>Tạo lại</span>
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

        {safetyNotices.length > 0 && (
          <div className="space-y-1.5">
            {safetyNotices.map((notice, idx) => (
              <div
                key={`${notice.code}-${idx}`}
                role="alert"
                className="flex items-start gap-2 rounded-xl border border-amber-400/70 bg-amber-500/15 px-3 py-2 text-[11px] leading-relaxed text-amber-100"
              >
                <AlertTriangle
                  className="mt-0.5 h-4 w-4 shrink-0 text-amber-300"
                  aria-hidden="true"
                />
                <span>{notice.message}</span>
              </div>
            ))}
          </div>
        )}

        {toolStatuses.length > 0 && (
          <div className="flex flex-wrap gap-1.5" aria-label="Trạng thái công cụ xác minh">
            {toolStatuses.map((ts, idx) => {
              const isRunning = ts.state === "running";
              const isBlocked = ts.state === "blocked";
              const chipStyle = isBlocked
                ? "border-rose-500/40 bg-rose-500/10 text-rose-200"
                : isRunning
                  ? "border-sky-500/40 bg-sky-500/10 text-sky-200"
                  : "border-emerald-500/35 bg-emerald-500/10 text-emerald-200";

              return (
                <span
                  key={`${ts.tool}-${idx}`}
                  className={`inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 text-[11px] font-medium ${chipStyle}`}
                >
                  {isRunning ? (
                    <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
                  ) : isBlocked ? (
                    <ShieldAlert className="h-3 w-3" aria-hidden="true" />
                  ) : (
                    <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
                  )}
                  <span>{ts.label}</span>
                </span>
              );
            })}
          </div>
        )}

        {message.isStreaming && !message.content && (
          <AssistantThinkingIndicator
            label={message.statusLabel ?? "Đang đối chiếu hồ sơ và kiểm tra độ an toàn..."}
          />
        )}

        {message.evidenceReport && parentCaseId && (
          <AssistantEvidenceCard
            evidence={message.evidenceReport}
            parentCaseId={parentCaseId}
            caseAccessToken={caseAccessToken}
            persisted={message.persistedEvidence ?? null}
            onPersisted={(state) => onEvidencePersisted?.(message.id, state)}
          />
        )}

        {message.content && (
          <div>
            <SafeMarkdown content={message.content} />
            {message.isStreaming && (
              <AssistantThinkingIndicator
                compact
                label={message.statusLabel ?? "Đang tiếp tục phản hồi..."}
              />
            )}
          </div>
        )}

        {message.errorMessage && (
          <div
            role="alert"
            className="space-y-2 rounded-xl border border-rose-500/45 bg-rose-500/15 p-3 text-xs leading-relaxed text-rose-100"
          >
            <div className="flex items-start gap-2">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-300" aria-hidden="true" />
              <span>{message.errorMessage}</span>
            </div>
            {onRetry && (
              <button
                type="button"
                disabled={disabled}
                onClick={onRetry}
                className="inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-lg border border-rose-400/55 bg-surface-subtle px-2.5 py-1 text-[11px] font-semibold text-rose-100 transition-colors hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Thử gửi lại</span>
              </button>
            )}
          </div>
        )}

        {citations.length > 0 && (
          <div className="space-y-1.5 border-t border-border-subtle/70 pt-2">
            <div className="flex flex-wrap items-center justify-between gap-1.5">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] font-semibold text-ink-muted">
                  Căn cứ ({citations.length}):
                </span>
                {citations.slice(0, refsExpanded ? citations.length : 3).map((item) => {
                  const meta = formatCitationTag(item.source_type);
                  return (
                    <span
                      key={item.id}
                      title={`${meta.label}: ${item.title}`}
                      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-medium ${meta.style}`}
                    >
                      <span className="font-mono font-bold">{meta.tag}</span>
                      <span className="max-w-[220px] truncate">{item.title}</span>
                    </span>
                  );
                })}
              </div>

              {!message.isStreaming && (
                <button
                  type="button"
                  aria-expanded={refsExpanded}
                  onClick={() => setRefsExpanded((prev) => !prev)}
                  className="inline-flex min-h-[24px] cursor-pointer items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium text-ink-muted transition-colors hover:bg-surface hover:text-ink-secondary"
                >
                  <span>{refsExpanded ? "Thu gọn" : "Chi tiết căn cứ"}</span>
                  <ChevronDown
                    className={`h-3 w-3 transition-transform ${refsExpanded ? "rotate-180" : ""}`}
                    aria-hidden="true"
                  />
                </button>
              )}
            </div>

            {refsExpanded && (
              <ul
                aria-label="Danh sách căn cứ tham chiếu đầy đủ"
                className="space-y-1 rounded-lg border border-border-subtle bg-surface-deep/75 p-2 text-[11px]"
              >
                {citations.map((item) => {
                  const meta = formatCitationTag(item.source_type);
                  return (
                    <li
                      key={`detail-${item.id}`}
                      className="flex flex-wrap items-start justify-between gap-2 rounded-md px-2 py-1 odd:bg-surface/45"
                    >
                      <div className="min-w-0 flex-1">
                        <span
                          className={`mr-1.5 inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[9.5px] font-bold ${meta.style}`}
                        >
                          {meta.tag}
                        </span>
                        <span className="text-ink-secondary">{item.title}</span>
                      </div>
                      <span className="shrink-0 font-mono text-[10px] text-ink-muted">
                        {meta.label}
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        )}

        {showFollowups && onSelectFollowup && (
          <div className="space-y-1.5 border-t border-border-subtle/70 pt-2.5">
            <p className="inline-flex items-center gap-1 text-[10px] font-semibold text-ink-muted">
              <Sparkles className="h-3 w-3 text-amber-400" aria-hidden="true" />
              <span>Gợi ý hỏi tiếp:</span>
            </p>
            <div className="flex flex-wrap gap-1.5">
              {suggestedFollowups.map((followup, idx) => (
                <button
                  key={`${followup}-${idx}`}
                  type="button"
                  disabled={disabled}
                  onClick={() => onSelectFollowup(followup)}
                  className="vs-pressable min-h-[34px] cursor-pointer rounded-lg border border-border-strong bg-surface px-2.5 py-1 text-left text-[11px] font-medium text-ink-secondary hover:border-amber-400/65 hover:text-ink disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {followup}
                </button>
              ))}
            </div>
          </div>
        )}
      </article>
    </div>
  );
});
