"use client";

import {
  AlertTriangle,
  FileAudio,
  FileWarning,
  Image as ImageIcon,
  Paperclip,
  Send,
  Shield,
  Square,
  Trash2,
  X,
} from "lucide-react";
import {
  type ChangeEvent,
  type KeyboardEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import { useScrollLock } from "@/components/motion/SmoothScrollProvider";
import {
  AssistantApiError,
  streamAssistantChat,
  streamAssistantEvidenceChat,
} from "@/lib/api";
import { MODE_COPY, VERDICT_COPY } from "@/lib/copy";
import type {
  AnalysisReport,
  AssistantCitationItem,
  AssistantHistoryTurn,
  AssistantQuickIntent,
  VerdictLevel,
} from "@/lib/types";

import type { PersistedEvidenceState } from "./AssistantEvidenceCard";
import {
  AssistantMessageItem,
  type AssistantChatMessage,
} from "./AssistantMessageItem";
import {
  AssistantQuickActions,
  type AssistantQuickAction,
  isMerchantOrReceiptContext,
} from "./AssistantQuickActions";

export interface AssistantDrawerProps {
  report: AnalysisReport;
  caseAccessToken: string | null;
  isOpen: boolean;
  onClose: () => void;
  initialPrompt?: string;
  initialIntent?: AssistantQuickIntent | null;
  initialPromptNonce?: number;
  onClearInitialPrompt?: () => void;
}

const MAX_MESSAGE_CHARS = 1500;
const MAX_HISTORY_TURNS = 12;
const MAX_HISTORY_ITEM_CHARS = 1200;
const MAX_HISTORY_TOTAL_CHARS = 6000;
const MAX_EVIDENCE_UPLOAD_BYTES = 10 * 1024 * 1024;

const ALLOWED_IMAGE_EXT_RE = /\.(?:jpe?g|png|webp|gif)$/i;
const ALLOWED_AUDIO_EXT_RE = /\.(?:wav|mp3|m4a|mp4|ogg|webm)$/i;

type EvidenceAttachmentKind = "image" | "audio";

interface PendingEvidenceAttachment {
  file: File;
  kind: EvidenceAttachmentKind;
  allowExternalMediaAi: boolean;
}

function detectEvidenceAttachmentKind(file: File): EvidenceAttachmentKind | null {
  const mime = (file.type || "").toLowerCase();
  if (mime.startsWith("image/") || ALLOWED_IMAGE_EXT_RE.test(file.name)) {
    return "image";
  }
  if (mime.startsWith("audio/") || ALLOWED_AUDIO_EXT_RE.test(file.name)) {
    return "audio";
  }
  return null;
}

function formatEvidenceFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

const MERCHANT_HONESTY_BANNER_TEXT =
  "Ảnh chụp biên lai không phải bằng chứng tiền đã vào tài khoản. Luôn kiểm tra số dư thực tế trên ứng dụng ngân hàng hoặc loa thông báo biến động số dư (Soundbox) trước khi giao hàng.";

const CLEAR_CONVERSATION_TOOLTIP =
  "Xóa hội thoại khỏi bộ nhớ trình duyệt hiện tại. Thao tác này không xóa hồ sơ phân tích đã lưu và không thu hồi nội dung đã gửi tới dịch vụ AI ở các lượt trước.";

const VERDICT_BADGE_STYLES: Record<VerdictLevel, string> = {
  SAFE: "border-emerald-500/45 bg-emerald-500/15 text-emerald-200",
  SUSPICIOUS: "border-amber-500/45 bg-amber-500/15 text-amber-200",
  HIGH_RISK: "border-orange-500/50 bg-orange-500/15 text-orange-200",
  CRITICAL_SCAM: "border-rose-500/55 bg-rose-500/18 text-rose-100",
};

function createMessageId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function truncateCaseId(caseId: string): string {
  const clean = caseId.trim();
  if (clean.length <= 14) return clean;
  return `${clean.slice(0, 10)}…${clean.slice(-4)}`;
}

/**
 * Build bounded alternating (user, assistant) history excluding failed, streaming,
 * empty, or orphaned user turns so retries never emit duplicate/consecutive user turns.
 */
function buildBoundedHistory(
  messages: AssistantChatMessage[],
  excludeIds?: ReadonlySet<string>,
): AssistantHistoryTurn[] {
  const filtered = excludeIds
    ? messages.filter((m) => !excludeIds.has(m.id))
    : messages;

  const pairs: Array<[AssistantHistoryTurn, AssistantHistoryTurn]> = [];
  for (let i = 0; i < filtered.length - 1; i += 1) {
    const u = filtered[i];
    const a = filtered[i + 1];
    if (
      u?.role === "user" &&
      a?.role === "assistant" &&
      !u.isStreaming &&
      !a.isStreaming &&
      !a.errorMessage &&
      u.content.trim().length > 0 &&
      a.content.trim().length > 0
    ) {
      pairs.push([
        { role: "user", content: u.content.trim().slice(0, MAX_HISTORY_ITEM_CHARS) },
        { role: "assistant", content: a.content.trim().slice(0, MAX_HISTORY_ITEM_CHARS) },
      ]);
      i += 1;
    }
  }

  const maxPairs = Math.floor(MAX_HISTORY_TURNS / 2);
  const recentPairs = pairs.slice(-maxPairs);
  const bounded: AssistantHistoryTurn[] = [];
  let totalChars = 0;

  for (let i = recentPairs.length - 1; i >= 0; i -= 1) {
    const pair = recentPairs[i];
    if (!pair) continue;
    const pairChars = pair[0].content.length + pair[1].content.length;
    if (totalChars + pairChars > MAX_HISTORY_TOTAL_CHARS) {
      break;
    }
    bounded.unshift(pair[0], pair[1]);
    totalChars += pairChars;
  }

  return bounded;
}

function inferQuickIntentFromPrompt(prompt: string): AssistantQuickIntent | null {
  const lower = prompt.toLowerCase();
  if (/lỡ chuyển|lộ otp|chuyển tiền rồi|cài.*apk|trình báo/.test(lower)) {
    return "incident_response";
  }
  if (/giải thích|vì sao|tại sao/.test(lower)) {
    return "explain_report";
  }
  if (/thủ đoạn|kịch bản lừa đảo|nhận biết/.test(lower)) {
    return "scam_education";
  }
  if (/kiểm chứng|xác minh|giao hàng|biên lai|tiền vào/.test(lower)) {
    return "verify_info";
  }
  return null;
}

function getFocusableElements(container: HTMLElement): HTMLElement[] {
  const selectors = [
    "button:not([disabled])",
    "textarea:not([disabled])",
    "input:not([disabled])",
    "a[href]",
    "[tabindex]:not([tabindex='-1'])",
  ].join(", ");
  return Array.from(container.querySelectorAll<HTMLElement>(selectors)).filter(
    (el) => el.offsetParent !== null,
  );
}

interface FailedTurnRecord {
  prompt: string;
  intent: AssistantQuickIntent | null;
  userMsgId: string;
  assistantMsgId: string;
  attachment?: PendingEvidenceAttachment | null;
}

export function AssistantDrawer({
  report,
  caseAccessToken,
  isOpen,
  onClose,
  initialPrompt,
  initialIntent = null,
  initialPromptNonce = 0,
  onClearInitialPrompt,
}: AssistantDrawerProps) {
  const [messages, setMessages] = useState<AssistantChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [detachedGeneralMode, setDetachedGeneralMode] = useState(false);
  const [retryCountdown, setRetryCountdown] = useState(0);
  const [lastFailedTurn, setLastFailedTurn] = useState<FailedTurnRecord | null>(null);
  const [attachedFile, setAttachedFile] = useState<File | null>(null);
  const [attachedKind, setAttachedKind] = useState<EvidenceAttachmentKind | null>(null);
  const [allowExternalMediaAi, setAllowExternalMediaAi] = useState(false);
  const [attachmentError, setAttachmentError] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const inFlightRef = useRef(false);
  const consumedPromptKeyRef = useRef<string | null>(null);
  const onCloseRef = useRef(onClose);
  const onClearInitialPromptRef = useRef(onClearInitialPrompt);
  const messagesRef = useRef<AssistantChatMessage[]>([]);
  const drawerRef = useRef<HTMLElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const lastCaseIdRef = useRef<string>(report.case_id);

  onCloseRef.current = onClose;
  onClearInitialPromptRef.current = onClearInitialPrompt;
  messagesRef.current = messages;

  const showMerchantBanner = isMerchantOrReceiptContext(report);
  const hasCaseToken = Boolean(caseAccessToken && caseAccessToken.trim());
  const needsSessionResolution = !detachedGeneralMode && (!hasCaseToken || sessionExpired);
  const canAttachEvidence = !detachedGeneralMode && hasCaseToken && !sessionExpired;

  const clearAttachment = useCallback(() => {
    setAttachedFile(null);
    setAttachedKind(null);
    setAllowExternalMediaAi(false);
    setAttachmentError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  }, []);

  // Abort any in-flight stream whenever the drawer closes so backend SSE slots release immediately
  useEffect(() => {
    if (!isOpen && (abortRef.current || inFlightRef.current)) {
      abortRef.current?.abort();
      abortRef.current = null;
      inFlightRef.current = false;
      setIsStreaming(false);
    }
  }, [isOpen]);

  useScrollLock(isOpen);

  // Reset conversation state cleanly when switching to a different analysis report
  useEffect(() => {
    if (lastCaseIdRef.current !== report.case_id) {
      lastCaseIdRef.current = report.case_id;
      abortRef.current?.abort();
      abortRef.current = null;
      inFlightRef.current = false;
      consumedPromptKeyRef.current = null;
      setMessages([]);
      setInput("");
      setIsStreaming(false);
      setSessionExpired(false);
      setDetachedGeneralMode(false);
      setRetryCountdown(0);
      setLastFailedTurn(null);
      clearAttachment();
    }
  }, [clearAttachment, report.case_id]);

  // Clear sessionExpired whenever a new non-empty caseAccessToken arrives (even replacing an expired one)
  useEffect(() => {
    if (caseAccessToken && caseAccessToken.trim()) {
      setSessionExpired(false);
    }
  }, [caseAccessToken]);

  // Abort active request on unmount
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
      abortRef.current = null;
      inFlightRef.current = false;
    };
  }, []);

  // Countdown timer for HTTP 429 Retry-After
  useEffect(() => {
    if (retryCountdown <= 0) return;
    const timer = window.setInterval(() => {
      setRetryCountdown((prev) => (prev <= 1 ? 0 : prev - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [retryCountdown]);

  // Auto-scroll to latest message/chunk
  useEffect(() => {
    if (!isOpen) return;
    messagesEndRef.current?.scrollIntoView({ behavior: "auto", block: "end" });
  }, [isOpen, messages]);

  // WCAG 2.2 dialog focus management, Tab trap, body scroll lock, and Escape close.
  // Depends strictly on [isOpen] using onCloseRef so parent re-renders never thrash focus.
  useEffect(() => {
    if (!isOpen) return;

    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const rafId = window.requestAnimationFrame(() => {
      if (textareaRef.current && !textareaRef.current.disabled) {
        textareaRef.current.focus();
      } else {
        closeButtonRef.current?.focus();
      }
    });

    function handleKeyDown(ev: globalThis.KeyboardEvent) {
      if (ev.key === "Escape") {
        ev.preventDefault();
        onCloseRef.current();
        return;
      }
      if (ev.key === "Tab" && drawerRef.current) {
        const focusables = getFocusableElements(drawerRef.current);
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const active = document.activeElement;
        if (ev.shiftKey && active === first && last) {
          ev.preventDefault();
          last.focus();
        } else if (!ev.shiftKey && active === last && first) {
          ev.preventDefault();
          first.focus();
        }
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.cancelAnimationFrame(rafId);
      window.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = prevOverflow;
      const opener = previousFocusRef.current;
      if (opener && opener.isConnected) {
        opener.focus();
      }
    };
  }, [isOpen]);

  const sendMessage = useCallback(
    async (
      rawPrompt: string,
      quickIntent: AssistantQuickIntent | null = null,
      options?: {
        forceGeneralMode?: boolean;
        replaceMessageIds?: readonly string[];
        attachmentOverride?: PendingEvidenceAttachment | null;
      },
    ) => {
      const trimmed = rawPrompt.trim().slice(0, MAX_MESSAGE_CHARS);
      const useGeneralMode = Boolean(options?.forceGeneralMode) || detachedGeneralMode;
      const pendingAttachment: PendingEvidenceAttachment | null = useGeneralMode
        ? null
        : options?.attachmentOverride !== undefined
          ? options.attachmentOverride
          : attachedFile && attachedKind
            ? {
                file: attachedFile,
                kind: attachedKind,
                allowExternalMediaAi,
              }
            : null;

      if ((!trimmed && !pendingAttachment) || inFlightRef.current || retryCountdown > 0) return;

      const effectiveCaseId = useGeneralMode ? null : report.case_id;
      const effectiveToken = useGeneralMode ? null : caseAccessToken;

      if (!useGeneralMode && (!effectiveToken || !effectiveToken.trim() || sessionExpired)) {
        setSessionExpired(true);
        if (trimmed) {
          setInput(trimmed);
        }
        return;
      }

      inFlightRef.current = true;
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      const replaceSet =
        options?.replaceMessageIds && options.replaceMessageIds.length > 0
          ? new Set(options.replaceMessageIds)
          : undefined;
      const history = buildBoundedHistory(messagesRef.current, replaceSet);
      const userMsgId = createMessageId("user");
      const assistantMsgId = createMessageId("assistant");
      const displayUserText =
        trimmed ||
        (pendingAttachment?.kind === "audio"
          ? "Phân tích tệp ghi âm bổ sung"
          : "Phân tích hình ảnh bổ sung");

      setLastFailedTurn(null);
      setInput("");
      if (options?.attachmentOverride === undefined) {
        clearAttachment();
      }
      setIsStreaming(true);
      setMessages((prev) => {
        const base = replaceSet ? prev.filter((item) => !replaceSet.has(item.id)) : prev;
        return [
          ...base,
          {
            id: userMsgId,
            role: "user",
            content: displayUserText,
            attachmentLabel: pendingAttachment ? pendingAttachment.file.name : null,
          },
          {
            id: assistantMsgId,
            role: "assistant",
            content: "",
            isStreaming: true,
            statusLabel: pendingAttachment
              ? pendingAttachment.allowExternalMediaAi
                ? "Đang phân tích bằng chứng bổ sung..."
                : "Đang phân tích bằng chứng bổ sung ở chế độ riêng tư cục bộ..."
              : "Đang đối chiếu hồ sơ và kho tri thức...",
            safetyNotices: [],
            toolStatuses: [],
            citations: [],
            suggestedFollowups: [],
          },
        ];
      });

      const updateAssistantMsg = (
        updater: (curr: AssistantChatMessage) => AssistantChatMessage,
      ) => {
        setMessages((prev) =>
          prev.map((item) => (item.id === assistantMsgId ? updater(item) : item)),
        );
      };

      let receivedAnyOutcome = false;

      const streamHandlers = {
        onStatus: (ev: { phase: string; label: string }) => {
          if (abortRef.current !== controller) return;
          updateAssistantMsg((curr) => ({ ...curr, statusLabel: ev.label }));
        },
        onToolStatus: (ev: { tool: string; state: string; label: string }) => {
          if (abortRef.current !== controller) return;
          updateAssistantMsg((curr) => {
            const existing = curr.toolStatuses ?? [];
            let matchIdx = -1;
            if (ev.state !== "running") {
              for (let i = existing.length - 1; i >= 0; i -= 1) {
                const entry = existing[i];
                if (entry && entry.tool === ev.tool && entry.state === "running") {
                  matchIdx = i;
                  break;
                }
              }
            }
            const nextTools =
              matchIdx >= 0
                ? existing.map((item, i) => (i === matchIdx ? ev : item))
                : [...existing, ev];
            return { ...curr, toolStatuses: nextTools };
          });
        },
        onSafetyNotice: (ev: { code: string; message: string }) => {
          if (abortRef.current !== controller) return;
          receivedAnyOutcome = true;
          updateAssistantMsg((curr) => {
            const existing = curr.safetyNotices ?? [];
            const alreadyExists = existing.some(
              (item) => item.code === ev.code && item.message === ev.message,
            );
            return alreadyExists
              ? curr
              : { ...curr, safetyNotices: [...existing, ev] };
          });
        },
        onDelta: (text: string) => {
          if (abortRef.current !== controller) return;
          receivedAnyOutcome = true;
          updateAssistantMsg((curr) => ({
            ...curr,
            content: `${curr.content}${text}`,
          }));
        },
        onCitation: (items: AssistantCitationItem[]) => {
          if (abortRef.current !== controller) return;
          updateAssistantMsg((curr) => {
            const seen = new Set((curr.citations ?? []).map((c) => c.id));
            const merged = [...(curr.citations ?? [])];
            for (const item of items) {
              if (!seen.has(item.id)) {
                seen.add(item.id);
                merged.push(item);
              }
            }
            return { ...curr, citations: merged };
          });
        },
        onEvidenceReport: (ev: NonNullable<AssistantChatMessage["evidenceReport"]>) => {
          if (abortRef.current !== controller) return;
          receivedAnyOutcome = true;
          updateAssistantMsg((curr) => ({ ...curr, evidenceReport: ev }));
        },
        onDone: (ev: {
          degraded_mode: boolean;
          output_tier: 0 | 1 | 2;
          suggested_followups: string[];
        }) => {
          if (abortRef.current !== controller) return;
          receivedAnyOutcome = true;
          updateAssistantMsg((curr) => ({
            ...curr,
            isStreaming: false,
            statusLabel: null,
            degradedMode: ev.degraded_mode,
            outputTier: ev.output_tier,
            suggestedFollowups: ev.suggested_followups,
          }));
        },
        onError: (ev: { code: string; message: string }) => {
          if (abortRef.current !== controller) return;
          receivedAnyOutcome = true;
          if (ev.code === "CASE_AUTH_FAILED") {
            setSessionExpired(true);
          }
          setLastFailedTurn({
            prompt: trimmed,
            intent: quickIntent,
            userMsgId,
            assistantMsgId,
            attachment: pendingAttachment,
          });
          updateAssistantMsg((curr) => ({
            ...curr,
            isStreaming: false,
            statusLabel: null,
            errorMessage: ev.message,
          }));
        },
      };

      try {
        if (pendingAttachment && effectiveCaseId) {
          const formData = new FormData();
          formData.append("case_id", effectiveCaseId);
          formData.append("message", trimmed);
          formData.append(
            "allow_external_media_ai",
            pendingAttachment.allowExternalMediaAi ? "true" : "false",
          );
          formData.append(
            pendingAttachment.kind === "audio" ? "audio" : "image",
            pendingAttachment.file,
          );
          await streamAssistantEvidenceChat(
            formData,
            effectiveToken,
            streamHandlers,
            controller.signal,
          );
        } else {
          await streamAssistantChat(
            {
              case_id: effectiveCaseId,
              message: trimmed,
              history,
              quick_intent: quickIntent,
            },
            effectiveToken,
            streamHandlers,
            controller.signal,
          );
        }

        if (abortRef.current === controller) {
          if (!receivedAnyOutcome) {
            setLastFailedTurn({
              prompt: trimmed,
              intent: quickIntent,
              userMsgId,
              assistantMsgId,
              attachment: pendingAttachment,
            });
            updateAssistantMsg((curr) => ({
              ...curr,
              isStreaming: false,
              statusLabel: null,
              errorMessage:
                "Kết nối phản hồi từ Trợ lý VeriShield kết thúc sớm trước khi nhận được nội dung. Vui lòng thử gửi lại.",
            }));
          } else {
            updateAssistantMsg((curr) => ({
              ...curr,
              isStreaming: false,
              statusLabel: null,
            }));
          }
        }
      } catch (err) {
        if ((err as Error).name === "AbortError") {
          setMessages((prev) =>
            prev
              .map((item) =>
                item.id === assistantMsgId
                  ? { ...item, isStreaming: false, statusLabel: null }
                  : item,
              )
              .filter(
                (item) =>
                  !(
                    item.id === assistantMsgId &&
                    !item.content.trim() &&
                    !item.evidenceReport &&
                    (item.safetyNotices?.length ?? 0) === 0
                  ),
              ),
          );
          return;
        }

        if (abortRef.current !== controller) return;

        let friendlyMessage =
          "Không thể kết nối tới Trợ lý VeriShield lúc này. Vui lòng thử gửi lại.";
        if (err instanceof AssistantApiError) {
          friendlyMessage = err.message;
          if (err.code === "CASE_AUTH_FAILED") {
            setSessionExpired(true);
          }
          if (err.retryAfterSeconds && err.retryAfterSeconds > 0) {
            setRetryCountdown(err.retryAfterSeconds);
          }
        } else if (err instanceof Error && err.message.trim()) {
          friendlyMessage = err.message;
        }

        setLastFailedTurn({
          prompt: trimmed,
          intent: quickIntent,
          userMsgId,
          assistantMsgId,
          attachment: pendingAttachment,
        });
        updateAssistantMsg((curr) => ({
          ...curr,
          isStreaming: false,
          statusLabel: null,
          errorMessage: friendlyMessage,
        }));
      } finally {
        if (abortRef.current === controller) {
          abortRef.current = null;
          inFlightRef.current = false;
          setIsStreaming(false);
        }
      }
    },
    [
      allowExternalMediaAi,
      attachedFile,
      attachedKind,
      caseAccessToken,
      clearAttachment,
      detachedGeneralMode,
      report.case_id,
      retryCountdown,
      sessionExpired,
    ],
  );

  // StrictMode-safe initialPrompt consumption: guards against double-send and preserves
  // prompt in composer if rate-limited or waiting for session resolution.
  useEffect(() => {
    if (!initialPrompt || !initialPrompt.trim()) {
      consumedPromptKeyRef.current = null;
      return;
    }
    if (!isOpen) return;

    const promptToSend = initialPrompt.trim();
    const promptKey = `${initialPromptNonce}:${promptToSend}`;
    if (consumedPromptKeyRef.current === promptKey) {
      return;
    }
    consumedPromptKeyRef.current = promptKey;

    if (needsSessionResolution || retryCountdown > 0 || inFlightRef.current) {
      setInput(promptToSend.slice(0, MAX_MESSAGE_CHARS));
      onClearInitialPromptRef.current?.();
      return;
    }

    onClearInitialPromptRef.current?.();
    void sendMessage(
      promptToSend,
      initialIntent ?? inferQuickIntentFromPrompt(promptToSend),
      { attachmentOverride: null },
    );
  }, [
    initialIntent,
    initialPrompt,
    initialPromptNonce,
    isOpen,
    needsSessionResolution,
    retryCountdown,
    sendMessage,
  ]);

  function handleClearConversation() {
    abortRef.current?.abort();
    abortRef.current = null;
    inFlightRef.current = false;
    setIsStreaming(false);
    setMessages([]);
    setLastFailedTurn(null);
    clearAttachment();
  }

  function handleAbortStream() {
    abortRef.current?.abort();
    abortRef.current = null;
    inFlightRef.current = false;
    setIsStreaming(false);
  }

  function handleQuickActionSelect(action: AssistantQuickAction) {
    if (needsSessionResolution || retryCountdown > 0) {
      setInput(action.prompt.slice(0, MAX_MESSAGE_CHARS));
      return;
    }
    void sendMessage(action.prompt, action.intent, { attachmentOverride: null });
  }

  function handleComposerKeyDown(ev: KeyboardEvent<HTMLTextAreaElement>) {
    if (ev.key === "Enter" && !ev.shiftKey && !ev.nativeEvent.isComposing) {
      ev.preventDefault();
      void sendMessage(input);
    }
  }

  function handleSwitchToGeneralMode() {
    setDetachedGeneralMode(true);
    setSessionExpired(false);
    setLastFailedTurn(null);
    clearAttachment();
  }

  function handleEvidencePersisted(messageId: string, persisted: PersistedEvidenceState) {
    setMessages((prev) =>
      prev.map((item) =>
        item.id === messageId ? { ...item, persistedEvidence: persisted } : item,
      ),
    );
  }

  function handleFileChange(ev: ChangeEvent<HTMLInputElement>) {
    const file = ev.target.files?.[0] ?? null;
    ev.target.value = "";
    if (!file) return;

    if (file.size <= 0) {
      setAttachmentError("Tệp đính kèm trống. Vui lòng chọn tệp hợp lệ.");
      return;
    }
    if (file.size > MAX_EVIDENCE_UPLOAD_BYTES) {
      setAttachmentError("Tệp đính kèm vượt quá dung lượng tối đa 10 MB.");
      return;
    }
    const kind = detectEvidenceAttachmentKind(file);
    if (!kind) {
      setAttachmentError(
        "Chỉ hỗ trợ 1 hình ảnh (JPG, PNG, WEBP, GIF) hoặc 1 tệp ghi âm (WAV, MP3, M4A, OGG, WEBM).",
      );
      return;
    }
    setAttachmentError(null);
    setAttachedFile(file);
    setAttachedKind(kind);
    setAllowExternalMediaAi(false);
  }

  if (!isOpen) {
    return null;
  }

  const verdictStyle = VERDICT_BADGE_STYLES[report.verdict];
  const latestAssistantId = [...messages]
    .reverse()
    .find((m) => m.role === "assistant")?.id;
  const charCount = input.length;
  const isSendDisabled =
    isStreaming ||
    retryCountdown > 0 ||
    (!input.trim() && !attachedFile) ||
    needsSessionResolution;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        aria-hidden="true"
        onClick={onClose}
        className="fixed inset-0 bg-slate-950/75 backdrop-blur-xs"
      />

      <aside
        ref={drawerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="assistant-drawer-title"
        className="relative z-10 flex h-full w-full flex-col border-l border-border-strong bg-surface shadow-2xl sm:w-[460px] lg:w-[500px]"
      >
        {/* Header */}
        <header className="flex items-start justify-between gap-3 border-b border-border-subtle px-4 py-3.5 sm:px-5">
          <div className="flex min-w-0 items-start gap-2.5">
            <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-amber-500/45 bg-amber-500/15">
              <Shield className="h-4 w-4 text-amber-300" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <h2
                id="assistant-drawer-title"
                className="truncate text-sm font-bold tracking-tight text-ink"
              >
                Trợ lý VeriShield
              </h2>
              <p className="text-[11px] text-ink-muted">
                {detachedGeneralMode
                  ? "Chế độ hỏi đáp chung về phòng chống lừa đảo"
                  : "Hỏi đáp an toàn theo ngữ cảnh hồ sơ hiện tại"}
              </p>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-1.5">
            <button
              type="button"
              onClick={handleClearConversation}
              disabled={messages.length === 0 && !isStreaming}
              title={CLEAR_CONVERSATION_TOOLTIP}
              aria-label="Xóa hội thoại"
              className="inline-flex min-h-[36px] cursor-pointer items-center gap-1.5 rounded-lg border border-border-strong bg-surface-subtle px-2.5 py-1.5 text-[11px] font-medium text-ink-secondary transition-colors hover:border-amber-400/60 hover:text-ink disabled:cursor-not-allowed disabled:opacity-45"
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">Xóa hội thoại</span>
            </button>

            <button
              ref={closeButtonRef}
              type="button"
              onClick={onClose}
              aria-label="Đóng Trợ lý VeriShield"
              className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-lg border border-border-strong bg-surface-subtle text-ink-secondary transition-colors hover:border-amber-400/60 hover:text-ink"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </header>

        {/* Case Context Summary Strip (masked metadata only, zero raw PII) */}
        <div className="border-b border-border-subtle bg-surface-subtle/85 px-4 py-2.5 sm:px-5">
          <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className={`inline-flex items-center rounded-md border px-2 py-0.5 font-bold ${verdictStyle}`}>
                {VERDICT_COPY[report.verdict].shortLabel}
              </span>
              <span className="tabular-num rounded-md border border-border-subtle bg-surface px-2 py-0.5 font-mono font-semibold text-ink">
                {report.risk_score}/100
              </span>
              <span className="rounded-md border border-border-subtle bg-surface px-2 py-0.5 text-ink-secondary">
                {MODE_COPY[report.mode].shortLabel}
              </span>
            </div>

            <span className="tabular-num font-mono text-[10px] text-ink-muted">
              {detachedGeneralMode ? "Hỏi đáp chung" : truncateCaseId(report.case_id)}
            </span>
          </div>
        </div>

        {/* Persistent, Non-Dismissible Merchant / Receipt Honesty Guardrail Banner */}
        {showMerchantBanner && (
          <div
            role="alert"
            data-testid="merchant-honesty-banner"
            className="border-b-2 border-amber-400/75 bg-amber-500/15 px-4 py-3 text-xs text-amber-100 sm:px-5"
          >
            <div className="flex items-start gap-2.5">
              <FileWarning
                className="mt-0.5 h-4 w-4 shrink-0 text-amber-300"
                aria-hidden="true"
              />
              <p className="text-[11px] font-medium leading-relaxed text-amber-100">
                {MERCHANT_HONESTY_BANNER_TEXT}
              </p>
            </div>
          </div>
        )}

        {/* Expired / Missing Case Session Prompt */}
        {needsSessionResolution && (
          <div
            role="alert"
            className="border-b border-amber-500/45 bg-surface-deep px-4 py-3 text-xs sm:px-5"
          >
            <div className="flex items-start gap-2.5">
              <AlertTriangle
                className="mt-0.5 h-4 w-4 shrink-0 text-amber-300"
                aria-hidden="true"
              />
              <div className="space-y-2">
                <p className="text-[11px] leading-relaxed text-amber-100">
                  Phiên truy cập hồ sơ hiện không khả dụng hoặc đã hết hạn. Vui lòng phân tích lại
                  tình huống để Trợ lý đối chiếu trực tiếp hồ sơ này, hoặc chuyển sang chế độ hỏi
                  đáp chung về phòng chống lừa đảo.
                </p>
                <button
                  type="button"
                  onClick={handleSwitchToGeneralMode}
                  className="inline-flex min-h-[34px] cursor-pointer items-center rounded-lg border border-amber-400/60 bg-amber-500/15 px-3 py-1 text-[11px] font-semibold text-amber-100 transition-colors hover:bg-amber-500/25"
                >
                  Chuyển sang hỏi đáp chung
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Scrollable Message Thread */}
        <div data-lenis-prevent className="flex-1 space-y-3.5 overflow-y-auto px-4 py-4 sm:px-5">
          {messages.length === 0 ? (
            <div className="space-y-4">
              <div className="rounded-2xl border border-border-subtle bg-surface-subtle p-4">
                <p className="text-xs font-semibold text-ink">
                  Xin chào, mình là Trợ lý VeriShield.
                </p>
                {detachedGeneralMode ? (
                  <p className="mt-1.5 text-xs leading-relaxed text-ink-secondary">
                    Mình đang ở <strong className="font-semibold text-ink">chế độ hỏi đáp chung</strong>{" "}
                    về phòng chống lừa đảo trực tuyến (không đối chiếu trực tiếp với hồ sơ đã hết
                    phiên). Bạn có thể hỏi về dấu hiệu nhận biết thủ đoạn, cách tự kiểm chứng qua
                    kênh chính thức hoặc quy trình xử lý khẩn cấp.
                  </p>
                ) : (
                  <p className="mt-1.5 text-xs leading-relaxed text-ink-secondary">
                    Mình đang theo dõi hồ sơ ở mức{" "}
                    <strong className="font-semibold text-ink">
                      {VERDICT_COPY[report.verdict].shortLabel.toLowerCase()}
                    </strong>{" "}
                    (<span className="tabular-num font-mono">{report.risk_score}/100</span>). Bạn cần
                    giải thích dấu hiệu rủi ro, hướng dẫn ứng phó khẩn cấp hay cách tự kiểm chứng qua
                    kênh chính thức?
                  </p>
                )}
              </div>

              <AssistantQuickActions
                report={report}
                disabled={isStreaming || retryCountdown > 0}
                onSelect={handleQuickActionSelect}
              />
            </div>
          ) : (
            messages.map((msg) => {
              const canRetryMessage =
                msg.id === latestAssistantId &&
                Boolean(msg.errorMessage) &&
                lastFailedTurn !== null &&
                lastFailedTurn.assistantMsgId === msg.id;

              return (
                <AssistantMessageItem
                  key={msg.id}
                  message={msg}
                  isLatestAssistant={msg.id === latestAssistantId}
                  disabled={isStreaming || retryCountdown > 0 || needsSessionResolution}
                  parentCaseId={report.case_id}
                  caseAccessToken={caseAccessToken}
                  onEvidencePersisted={handleEvidencePersisted}
                  onSelectFollowup={(q) =>
                    void sendMessage(q, inferQuickIntentFromPrompt(q), {
                      attachmentOverride: null,
                    })
                  }
                  onRetry={
                    canRetryMessage && lastFailedTurn
                      ? () =>
                          void sendMessage(lastFailedTurn.prompt, lastFailedTurn.intent, {
                            replaceMessageIds: [
                              lastFailedTurn.userMsgId,
                              lastFailedTurn.assistantMsgId,
                            ],
                            attachmentOverride: lastFailedTurn.attachment ?? null,
                          })
                      : undefined
                  }
                />
              );
            })
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Composer Footer */}
        <footer className="border-t border-border-subtle bg-surface-subtle/90 px-4 py-3 sm:px-5">
          {retryCountdown > 0 && (
            <p
              role="status"
              aria-live="polite"
              className="tabular-num mb-2 text-[11px] font-medium text-amber-200"
            >
              Đang tạm giới hạn tốc độ — vui lòng thử lại sau {retryCountdown} giây.
            </p>
          )}

          <form
            onSubmit={(ev) => {
              ev.preventDefault();
              void sendMessage(input);
            }}
            className="space-y-2"
          >
            {canAttachEvidence && (
              <input
                ref={fileInputRef}
                type="file"
                accept="image/jpeg,image/png,image/webp,image/gif,audio/wav,audio/mpeg,audio/mp4,audio/ogg,audio/webm"
                onChange={handleFileChange}
                className="sr-only"
                aria-label="Chọn ảnh hoặc tệp ghi âm bổ sung"
              />
            )}

            {attachmentError && (
              <p
                role="alert"
                className="rounded-lg border border-rose-500/45 bg-rose-500/15 px-2.5 py-1.5 text-[11px] text-rose-100"
              >
                {attachmentError}
              </p>
            )}

            {canAttachEvidence && attachedFile && (
              <div className="space-y-1.5 rounded-xl border border-border-strong bg-surface-deep px-3 py-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2 text-[11px] text-ink">
                    {attachedKind === "audio" ? (
                      <FileAudio className="h-3.5 w-3.5 shrink-0 text-sky-300" aria-hidden="true" />
                    ) : (
                      <ImageIcon className="h-3.5 w-3.5 shrink-0 text-amber-300" aria-hidden="true" />
                    )}
                    <span className="truncate font-medium">{attachedFile.name}</span>
                    <span className="tabular-num shrink-0 font-mono text-[10px] text-ink-muted">
                      {formatEvidenceFileSize(attachedFile.size)}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={clearAttachment}
                    disabled={isStreaming}
                    aria-label="Gỡ tệp đính kèm"
                    className="inline-flex h-6 w-6 shrink-0 cursor-pointer items-center justify-center rounded-md border border-border-subtle bg-surface-subtle text-ink-muted transition-colors hover:border-rose-400/50 hover:text-rose-200 disabled:opacity-50"
                  >
                    <X className="h-3 w-3" aria-hidden="true" />
                  </button>
                </div>

                <label
                  htmlFor="assistant-external-media-optin"
                  className="flex cursor-pointer items-start gap-2 text-[11px] leading-snug text-ink-secondary"
                >
                  <input
                    id="assistant-external-media-optin"
                    type="checkbox"
                    checked={allowExternalMediaAi}
                    disabled={isStreaming}
                    onChange={(ev) => setAllowExternalMediaAi(ev.target.checked)}
                    className="mt-0.5 h-3.5 w-3.5 shrink-0 rounded border-border-strong bg-surface accent-amber-500"
                  />
                  <span>
                    Cho phép gửi ảnh/ghi âm bổ sung tới AI bên ngoài (mặc định xử lý cục bộ)
                  </span>
                </label>
              </div>
            )}

            <div className="flex items-end gap-2">
              {canAttachEvidence && (
                <button
                  type="button"
                  disabled={isStreaming || retryCountdown > 0}
                  onClick={() => fileInputRef.current?.click()}
                  aria-label="Đính kèm ảnh hoặc tệp ghi âm bổ sung"
                  title="Đính kèm tối đa 1 ảnh hoặc 1 tệp ghi âm (≤ 10 MB) — mặc định xử lý cục bộ, không ghi DB"
                  className={`inline-flex h-[46px] w-[42px] shrink-0 cursor-pointer items-center justify-center rounded-xl border transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                    attachedFile
                      ? "border-amber-400/70 bg-amber-500/15 text-amber-200"
                      : "border-border-strong bg-surface-deep text-ink-secondary hover:border-amber-400/60 hover:text-ink"
                  }`}
                >
                  <Paperclip className="h-4 w-4" aria-hidden="true" />
                </button>
              )}

              <label htmlFor="assistant-composer-input" className="sr-only">
                Nhập câu hỏi cho Trợ lý VeriShield
              </label>
              <textarea
                id="assistant-composer-input"
                ref={textareaRef}
                rows={2}
                maxLength={MAX_MESSAGE_CHARS}
                value={input}
                onChange={(ev) => setInput(ev.target.value)}
                onKeyDown={handleComposerKeyDown}
                disabled={needsSessionResolution}
                placeholder={
                  needsSessionResolution
                    ? "Chuyển sang hỏi đáp chung hoặc phân tích lại để tiếp tục..."
                    : attachedFile
                      ? "Nhập thêm ghi chú cho bằng chứng đính kèm (tùy chọn)..."
                      : "Hỏi Trợ lý VeriShield về hồ sơ này... (Enter để gửi, Shift+Enter xuống dòng)"
                }
                className="min-h-[46px] max-h-32 flex-1 resize-y rounded-xl border border-border-strong bg-surface-deep px-3 py-2 text-xs leading-relaxed text-ink placeholder:text-ink-muted focus:border-amber-400 focus:outline-none disabled:cursor-not-allowed disabled:opacity-55"
              />

              {isStreaming ? (
                <button
                  type="button"
                  onClick={handleAbortStream}
                  aria-label="Dừng trả lời"
                  className="inline-flex h-[46px] shrink-0 cursor-pointer items-center gap-1.5 rounded-xl border border-rose-500/55 bg-rose-500/18 px-3.5 text-xs font-semibold text-rose-100 transition-colors hover:bg-rose-500/28"
                >
                  <Square className="h-3.5 w-3.5 fill-current" aria-hidden="true" />
                  <span>Dừng</span>
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={isSendDisabled}
                  aria-label="Gửi câu hỏi"
                  className="inline-flex h-[46px] shrink-0 cursor-pointer items-center gap-1.5 rounded-xl border border-amber-400/70 bg-amber-500 px-3.5 text-xs font-bold text-slate-950 transition-colors hover:bg-amber-400 disabled:cursor-not-allowed disabled:border-border-subtle disabled:bg-surface-elevated disabled:text-ink-muted"
                >
                  <Send className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Gửi</span>
                </button>
              )}
            </div>

            <div className="flex items-center justify-between gap-2 text-[10px] text-ink-muted">
              <span>Không nhập mã OTP, mật khẩu, số thẻ hoặc CCCD. Chỉ hỗ trợ tham khảo.</span>
              <span
                className={`tabular-num shrink-0 font-mono ${
                  charCount >= 1350 ? "font-semibold text-amber-300" : "text-ink-muted"
                }`}
              >
                {charCount}/{MAX_MESSAGE_CHARS}
              </span>
            </div>
          </form>
        </footer>
      </aside>
    </div>
  );
}
