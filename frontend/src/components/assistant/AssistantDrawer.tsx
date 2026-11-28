"use client";

import {
  ArrowDown,
  AlertTriangle,
  ExternalLink,
  FileAudio,
  FileWarning,
  Image as ImageIcon,
  Maximize2,
  Minimize2,
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
import { createPortal } from "react-dom";

import { useScrollLock } from "@/components/motion/SmoothScrollProvider";
import {
  AssistantApiError,
  streamAssistantChat,
  streamAssistantEvidenceChat,
} from "@/lib/api";
import { createConversationStore, expireInterruptedTurn, type ConversationRecord } from "@/lib/assistantConversation";
import { applyFollowupSelection, findRegenerableUserTurn, reconcileAssistantMessages } from "@/lib/assistantSession";
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
import { useAssistantPanel } from "./useAssistantPanel";
import { useAssistantScroll } from "./useAssistantScroll";

export interface AssistantDrawerProps {
  report: AnalysisReport;
  conversation: ConversationRecord;
  standalone?: boolean;
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
  "Xóa lịch sử trong các tab đang mở cùng hội thoại. Không xóa hồ sơ đã lưu hoặc thu hồi nội dung từng gửi tới dịch vụ AI.";

const HEADER_ACTION = "inline-flex size-9 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-border-strong bg-surface-deep text-ink-secondary hover:border-amber-400/60 hover:text-ink focus-visible:outline-2 focus-visible:outline-amber-400 disabled:cursor-not-allowed disabled:opacity-45";
const SYNC_NOTICE = "Hội thoại đang bận hoặc đang đồng bộ từ tab khác. Hãy thử lại sau.";

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
  conversation,
  standalone = false,
  isOpen,
  onClose,
  initialPrompt,
  initialIntent = null,
  initialPromptNonce = 0,
  onClearInitialPrompt,
}: AssistantDrawerProps) {
  const [store] = useState(() => createConversationStore(conversation));
  const [snapshot, setSnapshot] = useState(store.getSnapshot);
  const { messages, detached: detachedGeneralMode } = snapshot;
  const caseAccessToken = conversation.caseAccessToken;
  const [expanded, setExpanded] = useState(false);
  const [canPopOut, setCanPopOut] = useState(false);
  const [panelNotice, setPanelNotice] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [localStreaming, setLocalStreaming] = useState(false);
  const isStreaming = snapshot.streaming || localStreaming;
  const [sessionExpired, setSessionExpired] = useState(false);
  const [retryCountdown, setRetryCountdown] = useState(0);
  const [lastFailedTurn, setLastFailedTurn] = useState<FailedTurnRecord | null>(null);
  const [attachedFile, setAttachedFile] = useState<File | null>(null);
  const [attachedKind, setAttachedKind] = useState<EvidenceAttachmentKind | null>(null);
  const [allowExternalMediaAi, setAllowExternalMediaAi] = useState(false);
  const [attachmentError, setAttachmentError] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(false);
  const inFlightRef = useRef(false);
  const consumedPromptKeyRef = useRef<string | null>(null);
  const onCloseRef = useRef(onClose);
  const onClearInitialPromptRef = useRef(onClearInitialPrompt);
  const layerRef = useRef<HTMLDivElement>(null);
  const drawerRef = useRef<HTMLElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const scroll = useAssistantScroll(isOpen, messages);
  const panel = useAssistantPanel(drawerRef, isOpen && !standalone && !expanded, scroll.suspendForResize, scroll.resumeAfterResize);
  const full = standalone || expanded || panel.mobile;
  const modal = !standalone && full;
  const closeLabel = standalone ? "Đóng trang chat" : "Đóng khung chat";
  const modeLabel = expanded ? "Thu về khung bên phải" : "Mở rộng toàn màn hình";
  const setMessages = useCallback((update: (previous: AssistantChatMessage[]) => AssistantChatMessage[]) => {
    const current = store.getSnapshot();
    store.publish({ ...current, messages: update(current.messages) });
  }, [store]);

  onCloseRef.current = onClose;
  onClearInitialPromptRef.current = onClearInitialPrompt;

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

  useEffect(() => {
    const disconnect = store.connect(setSnapshot);
    setCanPopOut(store.canOpenStandalone());
    return disconnect;
  }, [store]);

  useScrollLock(isOpen && full);

  useEffect(() => {
    if (!conversation.expiresAt) return;
    const timeout = window.setTimeout(() => {
      setSessionExpired(true);
      setCanPopOut(false);
    }, Math.max(0, conversation.expiresAt - Date.now()));
    return () => window.clearTimeout(timeout);
  }, [conversation.expiresAt]);

  // Abort active request on unmount
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
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

  useEffect(() => {
    if (!isOpen) return;

    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const rafId = window.requestAnimationFrame(() => {
      if (textareaRef.current && !textareaRef.current.disabled) {
        textareaRef.current.focus();
      } else {
        closeButtonRef.current?.focus();
      }
    });

    return () => {
      window.cancelAnimationFrame(rafId);
      const opener = previousFocusRef.current;
      window.requestAnimationFrame(() => {
        if (document.getElementById("assistant-chat-panel")) return;
        if (opener && opener.isConnected && opener !== document.body && !opener.hidden) {
          opener.focus({ preventScroll: true });
        } else {
          document.getElementById("assistant-launcher")?.focus({ preventScroll: true });
        }
      });
    };
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen || !full) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const siblings = Array.from(document.body.children).filter(
      (node): node is HTMLElement => node instanceof HTMLElement && node !== layerRef.current && !node.inert,
    );
    for (const sibling of siblings) sibling.inert = true;
    if (!drawerRef.current?.contains(document.activeElement)) closeButtonRef.current?.focus();
    return () => {
      document.body.style.overflow = prevOverflow;
      for (const sibling of siblings) sibling.inert = false;
    };
  }, [full, isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    function handleKeyDown(ev: globalThis.KeyboardEvent) {
      if (ev.defaultPrevented) return;
      if (ev.key === "Escape" && (full || drawerRef.current?.contains(document.activeElement))) {
        ev.preventDefault();
        onCloseRef.current();
        return;
      }
      if (ev.key === "Tab" && modal && drawerRef.current) {
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
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [full, isOpen, modal]);

  const executeTurn = useCallback(
    async (
      rawPrompt: string,
      quickIntent: AssistantQuickIntent | null = null,
      options?: {
        replaceMessageIds?: readonly string[];
        attachmentOverride?: PendingEvidenceAttachment | null;
      },
    ) => {
      if (!mountedRef.current) return;
      const current = store.getSnapshot();
      const trimmed = rawPrompt.trim().slice(0, MAX_MESSAGE_CHARS);
      const useGeneralMode = current.detached;
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

      if (!trimmed && !pendingAttachment) return;

      const effectiveCaseId = useGeneralMode ? null : report.case_id;
      const effectiveToken = useGeneralMode ? null : caseAccessToken;

      if (!useGeneralMode && (!effectiveToken?.trim() || sessionExpired ||
        (conversation.expiresAt > 0 && Date.now() >= conversation.expiresAt))) {
        setSessionExpired(true);
        if (trimmed) {
          setInput(trimmed);
        }
        return;
      }

      const controller = new AbortController();
      abortRef.current = controller;

      const replaceSet =
        options?.replaceMessageIds && options.replaceMessageIds.length > 0
          ? new Set(options.replaceMessageIds)
          : undefined;
      const history = buildBoundedHistory(current.messages, replaceSet);
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
      setLocalStreaming(true);

      const currentBase = replaceSet
        ? current.messages.filter((item) => !replaceSet.has(item.id))
        : current.messages;
      const selectionState = applyFollowupSelection(
        currentBase,
        current.askedQuestions,
        displayUserText,
      );

      store.publish({
        ...current,
        streaming: true,
        askedQuestions: selectionState.askedQuestions,
        messages: [
          ...selectionState.messages,
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
        ],
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
          setMessages((prev) =>
            reconcileAssistantMessages(
              prev.map((item) =>
                item.id === assistantMsgId
                  ? {
                      ...item,
                      isStreaming: false,
                      statusLabel: null,
                      degradedMode: ev.degraded_mode,
                      outputTier: ev.output_tier,
                      suggestedFollowups: ev.suggested_followups,
                    }
                  : item,
              ),
              { askedQuestions: store.getSnapshot().askedQuestions },
            ),
          );
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

        if (abortRef.current === controller && !controller.signal.aborted) {
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
          setLocalStreaming(false);
          store.publish(expireInterruptedTurn(store.getSnapshot()));
        }
      }
    },
    [
      allowExternalMediaAi,
      attachedFile,
      attachedKind,
      caseAccessToken,
      clearAttachment,
      conversation.expiresAt,
      report.case_id,
      sessionExpired,
      setMessages,
      store,
    ],
  );

  const sendMessage = useCallback(async (...args: Parameters<typeof executeTurn>) => {
    if (inFlightRef.current || retryCountdown > 0) return;
    inFlightRef.current = true;
    setPanelNotice(null);
    const revision = store.getSnapshot().revision;
    let started = false;
    try {
      await store.exclusive(async () => {
        if (store.getSnapshot().revision !== revision) return;
        started = true;
        await executeTurn(...args);
      });
      if (!started && mountedRef.current) {
        setInput((draft) => draft || args[0].slice(0, MAX_MESSAGE_CHARS));
        setPanelNotice(SYNC_NOTICE);
      }
    } catch {
      if (mountedRef.current) {
        setLocalStreaming(false);
        abortRef.current = null;
        setInput((draft) => draft || args[0].slice(0, MAX_MESSAGE_CHARS));
        setPanelNotice(SYNC_NOTICE);
      }
    } finally {
      inFlightRef.current = false;
    }
  }, [executeTurn, retryCountdown, store]);

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
    changeConversation(() => {
      store.publish({ ...store.getSnapshot(), messages: [], askedQuestions: [] });
      setLastFailedTurn(null);
      setInput("");
      clearAttachment();
    });
  }

  function handleAbortStream() {
    abortRef.current?.abort();
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
    changeConversation(() => {
      store.publish({ ...store.getSnapshot(), detached: true, messages: [], askedQuestions: [] });
      setLastFailedTurn(null);
      clearAttachment();
    });
  }

  const changeConversation = useCallback((change: () => void) => {
    setPanelNotice(null);
    void store.exclusive(() => { if (mountedRef.current) change(); }).then((changed) => {
      if (!changed && mountedRef.current) setPanelNotice(SYNC_NOTICE);
    }).catch(() => { if (mountedRef.current) setPanelNotice(SYNC_NOTICE); });
  }, [store]);

  const handleEvidencePersisted = useCallback((messageId: string, persisted: PersistedEvidenceState) => {
    const update = () => setMessages((prev) =>
      prev.map((item) =>
        item.id === messageId ? { ...item, persistedEvidence: persisted } : item,
      ),
    );
    if (abortRef.current) update();
    else changeConversation(update);
  }, [changeConversation, setMessages]);

  const handleSelectFollowup = useCallback((q: string) => {
    void sendMessage(q, inferQuickIntentFromPrompt(q), {
      attachmentOverride: null,
    });
  }, [sendMessage]);

  const handleRegenerateMessage = useCallback((messageId: string) => {
    const target = findRegenerableUserTurn(store.getSnapshot().messages, messageId);
    if (!target) return;
    void sendMessage(target.prompt, inferQuickIntentFromPrompt(target.prompt), {
      replaceMessageIds: [target.userMsgId, target.assistantMsgId],
      attachmentOverride: null,
    });
  }, [sendMessage, store]);

  const handleRetryFailedTurn = useCallback(() => {
    if (!lastFailedTurn) return;
    void sendMessage(lastFailedTurn.prompt, lastFailedTurn.intent, {
      replaceMessageIds: [
        lastFailedTurn.userMsgId,
        lastFailedTurn.assistantMsgId,
      ],
      attachmentOverride: lastFailedTurn.attachment ?? null,
    });
  }, [lastFailedTurn, sendMessage]);

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

  return createPortal(
    <div ref={layerRef} className="assistant-shell" data-mode={standalone ? "standalone" : expanded ? "expanded" : "docked"}>
      <aside
        id="assistant-chat-panel"
        ref={drawerRef}
        role={standalone ? "main" : "dialog"}
        aria-modal={modal || undefined}
        aria-labelledby="assistant-drawer-title"
        style={{ "--assistant-width": `${panel.width}px` } as React.CSSProperties}
        className="assistant-panel relative flex h-full min-w-0 flex-col border-l border-border-strong bg-surface shadow-2xl"
      >
        {!full && <div {...panel.separator} className="assistant-resize" />}
        {/* Header */}
        <header className="assistant-gutter flex shrink-0 items-center justify-between gap-2 border-b border-border-subtle py-3">
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
            {!standalone && !panel.mobile && (
              <button type="button" className={HEADER_ACTION} title={modeLabel} aria-label={modeLabel}
                onClick={() => setExpanded((value) => !value)}>
                {expanded ? <Minimize2 size={16} aria-hidden="true" /> : <Maximize2 size={16} aria-hidden="true" />}
              </button>
            )}
            {!standalone && (
              <button type="button" className={HEADER_ACTION} disabled={!canPopOut || sessionExpired}
                title={canPopOut && !sessionExpired ? "Mở hội thoại trong tab mới" : "Cần phiên hồ sơ còn hạn và trình duyệt hỗ trợ đồng bộ tab"}
                aria-label="Mở hội thoại trong tab mới"
                onClick={() => setPanelNotice(store.openStandalone() ? null : "Không mở được tab chat. Hãy kiểm tra trình chặn cửa sổ bật lên.")}>
                <ExternalLink size={16} aria-hidden="true" />
              </button>
            )}
            <button
              type="button"
              onClick={handleClearConversation}
              disabled={messages.length === 0 || isStreaming}
              title={CLEAR_CONVERSATION_TOOLTIP}
              aria-label="Xóa hội thoại"
              className={HEADER_ACTION}
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
            </button>

            <button
              ref={closeButtonRef}
              type="button"
              onClick={onClose}
              aria-label={closeLabel}
              title={closeLabel}
              className={HEADER_ACTION}
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </header>

        {/* Case Context Summary Strip (masked metadata only, zero raw PII) */}
        <div className="assistant-gutter shrink-0 border-b border-border-subtle bg-surface-subtle/85 py-2.5">
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
            className="assistant-gutter shrink-0 border-b-2 border-amber-400/75 bg-amber-500/15 py-2.5 text-xs text-amber-100"
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
            className="assistant-gutter shrink-0 border-b border-amber-500/45 bg-surface-deep py-3 text-xs"
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
                  disabled={isStreaming}
                  className="inline-flex min-h-[34px] cursor-pointer items-center rounded-lg border border-amber-400/60 bg-amber-500/15 px-3 py-1 text-[11px] font-semibold text-amber-100 transition-colors hover:bg-amber-500/25"
                >
                  Chuyển sang hỏi đáp chung
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Scrollable Message Thread */}
        <div className="relative min-h-0 min-w-0 flex-1">
        <div ref={scroll.threadRef} onScroll={scroll.onScroll} data-lenis-prevent
          role="region" aria-label="Nội dung hội thoại" tabIndex={0}
          className="assistant-gutter assistant-thread h-full min-w-0 overflow-x-hidden overflow-y-auto py-4 outline-offset-[-2px] focus-visible:outline-2 focus-visible:outline-amber-400">
          <div className="min-w-0 space-y-3.5">
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
              const isLatest = msg.id === latestAssistantId;
              const canRetryMessage =
                isLatest &&
                Boolean(msg.errorMessage) &&
                lastFailedTurn !== null &&
                lastFailedTurn.assistantMsgId === msg.id;
              const canRegenerate =
                isLatest &&
                Boolean(findRegenerableUserTurn(messages, msg.id));

              return (
                <div key={msg.id} data-chat-message={msg.id} className="min-w-0">
                <AssistantMessageItem
                  message={msg}
                  isLatestAssistant={isLatest}
                  disabled={isStreaming || retryCountdown > 0 || needsSessionResolution}
                  canRegenerate={canRegenerate}
                  parentCaseId={report.case_id}
                  caseAccessToken={caseAccessToken}
                  onEvidencePersisted={handleEvidencePersisted}
                  onSelectFollowup={handleSelectFollowup}
                  onRetry={canRetryMessage ? handleRetryFailedTurn : undefined}
                  onRegenerate={canRegenerate ? handleRegenerateMessage : undefined}
                />
                </div>
              );
            })
          )}
          </div>
        </div>
        {scroll.showScrollToBottom && (
          <button type="button" title="Cuộn xuống cuối hội thoại"
            className="absolute bottom-3 left-1/2 flex -translate-x-1/2 cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-full border border-amber-400/60 bg-surface-elevated px-3 py-2 text-xs font-semibold text-amber-100 shadow-lg focus-visible:outline-2 focus-visible:outline-amber-400"
            onClick={() => {
              scroll.scrollToBottom();
              scroll.threadRef.current?.focus({ preventScroll: true });
            }}>
            <ArrowDown size={14} aria-hidden="true" /> Xuống cuối hội thoại
          </button>
        )}
        </div>

        {/* Composer Footer */}
        <footer className="assistant-gutter assistant-composer shrink-0 border-t border-border-subtle bg-surface-subtle/90 pt-3">
          {(panelNotice || (snapshot.streaming && !localStreaming)) && (
            <p role="status" className="mb-2 text-xs text-amber-200">
              {panelNotice ?? "Trợ lý đang trả lời ở một tab khác."}
            </p>
          )}
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
                className="min-h-[46px] min-w-0 flex-1 resize-none rounded-xl border border-border-strong bg-surface-deep px-3 py-2 text-xs leading-relaxed text-ink placeholder:text-ink-muted focus:border-amber-400 focus:outline-none disabled:cursor-not-allowed disabled:opacity-55"
              />

              {localStreaming ? (
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
    </div>,
    document.body,
  );
}
