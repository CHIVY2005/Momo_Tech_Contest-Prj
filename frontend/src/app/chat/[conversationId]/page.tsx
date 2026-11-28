"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { AssistantDrawer } from "@/components/assistant/AssistantDrawer";
import { fetchAssistantCase } from "@/lib/api";
import { forgetConversation, loadConversation, type ConversationRecord } from "@/lib/assistantConversation";
import type { AnalysisReport } from "@/lib/types";

export default function StandaloneChatPage() {
  const { conversationId } = useParams<{ conversationId: string }>();
  const router = useRouter();
  const [loaded, setLoaded] = useState<{ conversation: ConversationRecord; report: AnalysisReport } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    const conversation = loadConversation(conversationId);
    if (!conversation?.caseAccessToken) {
      setNotice("Hội thoại không khả dụng trong tab này hoặc đã hết hạn. Hãy mở lại từ khung chat của hồ sơ.");
      return;
    }
    const controller = new AbortController();
    setNotice(null);
    void fetchAssistantCase(conversation.caseId, conversation.caseAccessToken, controller.signal)
      .then((report) => {
        if (controller.signal.aborted) return;
        if (report) setLoaded({ conversation, report });
        else {
          forgetConversation(conversationId);
          setNotice("Phiên này không còn quyền truy cập hồ sơ. Hãy mở lại hội thoại từ hồ sơ hợp lệ.");
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) setNotice("Chưa kiểm tra được quyền truy cập hồ sơ. Hãy tải lại trang để thử lại.");
      });
    return () => controller.abort();
  }, [conversationId]);

  if (loaded?.conversation.id === conversationId) {
    return (
      <AssistantDrawer key={conversationId} {...loaded} isOpen standalone onClose={() => {
        window.close();
        router.replace("/");
      }} />
    );
  }

  return (
    <section className="mx-auto max-w-2xl space-y-3 rounded-2xl border border-border-subtle bg-surface p-5">
      <h1 className="text-lg font-bold">Trợ lý VeriShield</h1>
      <p className="text-sm text-ink-secondary" role="status">{notice ?? "Đang kiểm tra phiên hội thoại…"}</p>
      {notice && <Link href="/" className="text-sm font-semibold text-amber-300 underline">Về trang phân tích</Link>}
    </section>
  );
}
