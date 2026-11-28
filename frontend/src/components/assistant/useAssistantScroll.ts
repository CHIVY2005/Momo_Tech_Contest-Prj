import { useCallback, useLayoutEffect, useRef, useState } from "react";

const BOTTOM_THRESHOLD = 48;
const CONTAINMENT_MIN_MESSAGES = 20;

export function useAssistantScroll(isOpen: boolean, content: unknown) {
  const threadRef = useRef<HTMLDivElement>(null);
  const pinned = useRef(true);
  const suspended = useRef(false);
  const resumeFrame = useRef<number | null>(null);
  const releaseContainment = useRef<(() => void) | null>(null);
  const anchor = useRef<{ messageId: string; ratio: number } | null>(null);
  const [showScrollToBottom, setShowScrollToBottom] = useState(false);

  const onScroll = useCallback(() => {
    const thread = threadRef.current;
    if (!thread || suspended.current || !thread.clientHeight) return;
    const isPinned = thread.scrollHeight - thread.scrollTop - thread.clientHeight <= BOTTOM_THRESHOLD;
    if (pinned.current !== isPinned) setShowScrollToBottom(!isPinned);
    pinned.current = isPinned;
    if (pinned.current) {
      anchor.current = null;
      return;
    }
    const top = thread.getBoundingClientRect().top;
    const message = Array.from(thread.querySelectorAll<HTMLElement>("[data-chat-message]"))
      .find((item) => item.getBoundingClientRect().bottom > top);
    if (message?.dataset.chatMessage) {
      const rect = message.getBoundingClientRect();
      anchor.current = { messageId: message.dataset.chatMessage, ratio: (top - rect.top) / rect.height };
    }
  }, []);

  const scrollToBottom = useCallback(() => {
    const thread = threadRef.current;
    if (!thread || suspended.current) return;
    pinned.current = true;
    anchor.current = null;
    thread.scrollTop = thread.scrollHeight;
    setShowScrollToBottom(false);
  }, []);

  const restore = useCallback(() => {
    const thread = threadRef.current;
    if (!thread || suspended.current) return;
    if (pinned.current) {
      scrollToBottom();
      return;
    }
    const reading = anchor.current;
    const message = reading && thread.querySelector<HTMLElement>(`[data-chat-message="${CSS.escape(reading.messageId)}"]`);
    if (message && reading) {
      const rect = message.getBoundingClientRect();
      thread.scrollTop += rect.top - thread.getBoundingClientRect().top + reading.ratio * rect.height;
    } else {
      onScroll();
    }
  }, [onScroll, scrollToBottom]);

  const cancelResume = useCallback(() => {
    if (resumeFrame.current === null) return;
    cancelAnimationFrame(resumeFrame.current);
    resumeFrame.current = null;
  }, []);

  const suspendForResize = useCallback(() => {
    cancelResume();
    suspended.current = true;
    const thread = threadRef.current;
    if (!thread || !CSS.supports("content-visibility", "auto")) return;
    const messages = Array.from(thread.querySelectorAll<HTMLElement>("[data-chat-message]"));
    if (messages.length < CONTAINMENT_MIN_MESSAGES) return;
    const sizes = messages.map((message) => message.getBoundingClientRect().height);
    messages.forEach((message, index) => {
      message.style.containIntrinsicBlockSize = `auto ${sizes[index]}px`;
    });
    thread.dataset.resizeContainment = "true";
    releaseContainment.current = () => {
      delete thread.dataset.resizeContainment;
      for (const message of messages) message.style.removeProperty("contain-intrinsic-block-size");
    };
  }, [cancelResume]);

  const resumeAfterResize = useCallback((restorePosition: boolean) => {
    cancelResume();
    releaseContainment.current?.();
    releaseContainment.current = null;
    if (!restorePosition) {
      suspended.current = false;
      return;
    }
    resumeFrame.current = requestAnimationFrame(() => {
      resumeFrame.current = null;
      suspended.current = false;
      restore();
    });
  }, [cancelResume, restore]);

  useLayoutEffect(() => {
    if (!isOpen) return;
    return () => {
      cancelResume();
      suspended.current = false;
      releaseContainment.current?.();
      releaseContainment.current = null;
    };
  }, [cancelResume, isOpen]);

  useLayoutEffect(() => {
    if (isOpen) restore();
  }, [content, isOpen, restore]);

  useLayoutEffect(() => {
    if (!isOpen || !threadRef.current) return;
    const observer = new ResizeObserver(restore);
    observer.observe(threadRef.current);
    if (threadRef.current.firstElementChild) observer.observe(threadRef.current.firstElementChild);
    return () => observer.disconnect();
  }, [isOpen, restore]);

  return { threadRef, onScroll, scrollToBottom, showScrollToBottom, suspendForResize, resumeAfterResize };
}
