import type { AssistantChatMessage } from "../components/assistant/AssistantMessageItem";
import { reconcileAssistantMessages } from "./assistantSession.ts";

const PREFIX = "verishield.chat.";
const HOME_KEY = `${PREFIX}home`;
const REVISION_PREFIX = `${PREFIX}revision.`;
const ID_PATTERN = /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i;

export interface ConversationSnapshot {
  revision: number;
  detached: boolean;
  streaming: boolean;
  messages: AssistantChatMessage[];
  askedQuestions: string[];
}

export interface ConversationRecord {
  id: string;
  channelId: string;
  caseId: string;
  caseAccessToken: string | null;
  expiresAt: number;
  snapshot: ConversationSnapshot;
}

export function getCaseTokenExpiry(caseId: string, token: string | null): number | null {
  if (!token) return null;
  try {
    const [payload, signature, ...extra] = token.split(".");
    if (!payload || !signature || extra.length) return null;
    const { cid, exp } = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    return cid === caseId && Number.isSafeInteger(exp) ? exp * 1000 : null;
  } catch {
    return null;
  }
}

export function createConversationRecord(caseId: string, caseAccessToken: string | null): ConversationRecord {
  return {
    id: crypto.randomUUID(),
    channelId: crypto.randomUUID(),
    caseId,
    caseAccessToken,
    expiresAt: getCaseTokenExpiry(caseId, caseAccessToken) ?? 0,
    snapshot: { revision: 0, detached: false, streaming: false, messages: [], askedQuestions: [] },
  };
}

export function readConversationRecord(raw: string | null, id: string, now = Date.now()): ConversationRecord | null {
  if (!raw || !ID_PATTERN.test(id)) return null;
  try {
    const record = JSON.parse(raw) as ConversationRecord;
    if (
      record.id !== id || !ID_PATTERN.test(record.channelId) ||
      typeof record.caseId !== "string" || typeof record.caseAccessToken !== "string" ||
      record.expiresAt <= now || getCaseTokenExpiry(record.caseId, record.caseAccessToken) !== record.expiresAt ||
      !Number.isSafeInteger(record.snapshot?.revision) || typeof record.snapshot.detached !== "boolean" ||
      typeof record.snapshot.streaming !== "boolean" || !Array.isArray(record.snapshot.messages) ||
      !Array.isArray(record.snapshot.askedQuestions)
    ) return null;
    return {
      ...record,
      snapshot: { ...record.snapshot, messages: reconcileAssistantMessages(record.snapshot.messages, record.snapshot) },
    };
  } catch {
    return null;
  }
}

export function expireInterruptedTurn(snapshot: ConversationSnapshot): ConversationSnapshot {
  return {
    ...snapshot,
    streaming: false,
    messages: snapshot.messages.map((message) => message.isStreaming ? {
      ...message,
      isStreaming: false,
      statusLabel: null,
      suggestedFollowups: [],
      errorMessage: "Lượt trả lời đã bị gián đoạn. Bạn có thể gửi lại câu hỏi nếu cần.",
    } : message),
  };
}

export function forgetConversation(id: string) {
  try { sessionStorage.removeItem(`${PREFIX}${id}`); } catch { return; }
}

export function loadConversation(id: string): ConversationRecord | null {
  if (!ID_PATTERN.test(id)) return null;
  try {
    const record = readConversationRecord(sessionStorage.getItem(`${PREFIX}${id}`), id);
    if (!record) forgetConversation(id);
    return record;
  } catch {
    return null;
  }
}

export function loadHomeConversation() {
  try {
    const saved = JSON.parse(sessionStorage.getItem(HOME_KEY) ?? "null") as { id: string; isOpen: boolean } | null;
    if (!saved) return null;
    const record = loadConversation(saved.id);
    return record ? { record, isOpen: saved.isOpen === true } : null;
  } catch {
    return null;
  }
}

export function saveHomeConversation(id: string | null, isOpen = false) {
  try {
    if (id) sessionStorage.setItem(HOME_KEY, JSON.stringify({ id, isOpen }));
    else sessionStorage.removeItem(HOME_KEY);
  } catch { return; }
}

function saveCheckpoint(record: ConversationRecord, storage = sessionStorage) {
  if (record.expiresAt > Date.now()) storage.setItem(`${PREFIX}${record.id}`, JSON.stringify(record));
}

type WireMessage = { type: "sync" } | { type: "snapshot"; snapshot: ConversationSnapshot };

export function createConversationStore(initial: ConversationRecord) {
  const syncKey = `${REVISION_PREFIX}${initial.id}`;
  const channelName = `${PREFIX}channel.${initial.channelId}`;
  let snapshot = initial.snapshot;
  let channel: BroadcastChannel | null = null;
  let listener: ((value: ConversationSnapshot) => void) | null = null;
  let localBusy = false;
  let supportsSync = false;

  function save() {
    try { saveCheckpoint({ ...initial, snapshot }); } catch { return; }
  }

  function post(message: WireMessage) {
    channel?.postMessage(message);
  }

  function publish(next: ConversationSnapshot) {
    const revision = snapshot.revision + 1;
    if (channel && initial.expiresAt > Date.now()) localStorage.setItem(syncKey, `${initial.expiresAt}:${revision}`);
    snapshot = { ...next, revision };
    save();
    post({ type: "snapshot", snapshot });
    listener?.(snapshot);
  }

  async function exclusive(action: () => void | Promise<void>): Promise<boolean> {
    if (!supportsSync) {
      if (localBusy) return false;
      localBusy = true;
      try {
        if (snapshot.streaming) publish(expireInterruptedTurn(snapshot));
        await action();
        return true;
      } finally { localBusy = false; }
    }
    return navigator.locks.request(syncKey, { ifAvailable: true }, async (lock) => {
      if (!lock) return false;
      const revision = Number(localStorage.getItem(syncKey)?.split(":")[1] ?? 0);
      if (initial.expiresAt > Date.now() && revision !== snapshot.revision) {
        post({ type: "sync" });
        return false;
      }
      if (snapshot.streaming) publish(expireInterruptedTurn(snapshot));
      await action();
      return true;
    });
  }

  function connect(onChange: (value: ConversationSnapshot) => void) {
    listener = onChange;
    try {
      for (const key of Object.keys(localStorage)) {
        if (key.startsWith(REVISION_PREFIX) && Number(localStorage.getItem(key)?.split(":")[0]) <= Date.now()) {
          localStorage.removeItem(key);
        }
      }
      supportsSync = initial.expiresAt > Date.now() && !!navigator.locks && typeof BroadcastChannel === "function";
      if (supportsSync) {
        channel = new BroadcastChannel(channelName);
        channel.onmessage = ({ data }: MessageEvent<WireMessage>) => {
          if (Date.now() >= initial.expiresAt) return;
          if (data.type === "sync") post({ type: "snapshot", snapshot });
          else if (data.type === "snapshot" && data.snapshot.revision > snapshot.revision) {
            snapshot = data.snapshot;
            save();
            listener?.(snapshot);
          }
        };
        post({ type: "sync" });
      }
    } catch { supportsSync = false; }

    function recover() {
      if (initial.expiresAt > 0 && initial.expiresAt <= Date.now()) {
        forgetConversation(initial.id);
        channel?.close();
        channel = null;
      }
      if (snapshot.streaming) void exclusive(() => undefined).catch(() => undefined);
    }

    save();
    recover();
    const timer = window.setInterval(recover, 1500);
    return () => {
      window.clearInterval(timer);
      channel?.close();
      channel = null;
      listener = null;
    };
  }

  function openStandalone(): boolean {
    if (!supportsSync || !channel || initial.expiresAt <= Date.now()) return false;
    const popup = window.open("", "_blank");
    if (!popup) return false;
    try {
      popup.opener = null;
      for (const key of Object.keys(popup.sessionStorage)) {
        if (key.startsWith(PREFIX)) popup.sessionStorage.removeItem(key);
      }
      saveCheckpoint({ ...initial, snapshot }, popup.sessionStorage);
      popup.location.replace(`/chat/${initial.id}`);
      return true;
    } catch {
      popup.close();
      return false;
    }
  }

  return {
    getSnapshot: () => snapshot,
    canOpenStandalone: () => supportsSync && !!channel && initial.expiresAt > Date.now(),
    connect, exclusive, openStandalone, publish,
  };
}
