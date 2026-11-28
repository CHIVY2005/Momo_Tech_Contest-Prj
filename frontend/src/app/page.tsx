"use client";

import { AlertCircle, Radar, Send, Sparkles } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import { AssistantDrawer } from "@/components/assistant/AssistantDrawer";
import { HeroShieldScanner } from "@/components/motion/HeroShieldScanner";
import { useSmoothScroll } from "@/components/motion/SmoothScrollProvider";
import { DemoScenarioBar } from "@/components/workbench/DemoScenarioBar";
import { InputWorkbench, type WorkbenchFormState } from "@/components/workbench/InputWorkbench";
import { LiveTracePanel } from "@/components/workbench/LiveTracePanel";
import { InvestigationWorkspace } from "@/components/workspace/InvestigationWorkspace";
import { analyzeStream, fetchAssistantCase, fetchDemos, fetchHealth } from "@/lib/api";
import { createConversationRecord, forgetConversation, loadHomeConversation, saveHomeConversation, type ConversationRecord } from "@/lib/assistantConversation";
import { inferAnalyzeMode } from "@/lib/composerUtils";
import { BRAND_COPY } from "@/lib/copy";
import { ANCHOR_OFFSET_PX, shouldAutoScrollIntoView } from "@/lib/motion/scrollControl";
import type {
  AnalysisReport,
  AssistantQuickIntent,
  DemoScenario,
  SystemHealthResponse,
  TraceStep,
} from "@/lib/types";

const INITIAL_FORM: WorkbenchFormState = {
  text: "",
  inActiveCall: false,
  transferAmount: "",
  expectedMerchantAccount: "",
  imageFiles: [],
  audioFiles: [],
};

interface SubmittedSnapshot {
  report: AnalysisReport;
  caseAccessToken: string | null;
  imageFiles: File[];
  transferAmount: string;
  submittedText: string;
}

export default function HomePage() {
  const [demos, setDemos] = useState<DemoScenario[]>([]);
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);
  const [form, setForm] = useState<WorkbenchFormState>(INITIAL_FORM);
  const [activeDemo, setActiveDemo] = useState<DemoScenario | null>(null);
  const [traceSteps, setTraceSteps] = useState<TraceStep[]>([]);
  const [submittedSnapshot, setSubmittedSnapshot] = useState<SubmittedSnapshot | null>(null);
  const [submittedPreviewUrls, setSubmittedPreviewUrls] = useState<string[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isFormCollapsed, setIsFormCollapsed] = useState(false);
  const [isAssistantOpen, setIsAssistantOpen] = useState(false);
  const [conversation, setConversation] = useState<ConversationRecord | null>(null);
  const [assistantInitialPrompt, setAssistantInitialPrompt] = useState<string | undefined>(
    undefined,
  );
  const [assistantInitialIntent, setAssistantInitialIntent] =
    useState<AssistantQuickIntent | null>(null);
  const [assistantPromptNonce, setAssistantPromptNonce] = useState(0);
  const abortRef = useRef<AbortController | null>(null);
  const restoreRef = useRef<AbortController | null>(null);
  const resultRef = useRef<HTMLDivElement | null>(null);
  const scrolledCaseRef = useRef<string | null>(null);
  const { scrollToElement } = useSmoothScroll();

  useEffect(() => {
    void fetchDemos()
      .then(setDemos)
      .catch(() => setDemos([]));
    void fetchHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  const submittedImageFiles = submittedSnapshot?.imageFiles;

  useEffect(() => {
    const saved = loadHomeConversation();
    if (!saved?.record.caseAccessToken) return;
    const controller = new AbortController();
    restoreRef.current = controller;
    void fetchAssistantCase(saved.record.caseId, saved.record.caseAccessToken, controller.signal)
      .then((report) => {
        if (controller.signal.aborted) return;
        if (!report) {
          forgetConversation(saved.record.id);
          saveHomeConversation(null);
          return;
        }
        setSubmittedSnapshot({
          report,
          caseAccessToken: saved.record.caseAccessToken,
          imageFiles: [],
          transferAmount: "",
          submittedText: "",
        });
        setConversation(saved.record);
        setIsFormCollapsed(true);
        setIsAssistantOpen(saved.isOpen);
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, []);

  function resetAssistant() {
    restoreRef.current?.abort();
    saveHomeConversation(null);
    setConversation(null);
    setIsAssistantOpen(false);
    setAssistantInitialPrompt(undefined);
    setAssistantInitialIntent(null);
  }

  useEffect(() => {
    const files = submittedImageFiles ?? [];
    if (files.length === 0) {
      setSubmittedPreviewUrls([]);
      return;
    }
    const createdUrls = files.map((file) => URL.createObjectURL(file));
    setSubmittedPreviewUrls(createdUrls);
    return () => {
      for (const u of createdUrls) {
        URL.revokeObjectURL(u);
      }
    };
  }, [submittedImageFiles]);

  async function executeAnalysis(overrideDemo?: DemoScenario) {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setErrorMsg(null);
    setTraceSteps([]);
    setSubmittedSnapshot(null);
    resetAssistant();
    setIsAnalyzing(true);
    setIsFormCollapsed(true);

    const capturedImageFiles = !overrideDemo && !activeDemo ? [...form.imageFiles] : [];
    const capturedText = overrideDemo
      ? overrideDemo.url && !overrideDemo.text.includes(overrideDemo.url)
        ? `${overrideDemo.text}\n${overrideDemo.url}`.trim()
        : overrideDemo.text
      : form.text;
    const capturedAmount = overrideDemo
      ? overrideDemo.transfer_amount !== null && overrideDemo.transfer_amount !== undefined
        ? String(overrideDemo.transfer_amount)
        : ""
      : form.transferAmount;

    const fd = new FormData();
    if (overrideDemo) {
      fd.append("demo_id", overrideDemo.demo_id);
      fd.append("mode", overrideDemo.mode);
    } else if (activeDemo) {
      fd.append("demo_id", activeDemo.demo_id);
      fd.append("mode", activeDemo.mode);
    } else {
      const resolvedMode = inferAnalyzeMode({
        expectedMerchantAccount: form.expectedMerchantAccount,
        transferAmount: form.transferAmount,
        inActiveCall: form.inActiveCall,
      });
      fd.append("mode", resolvedMode);
      fd.append("text", form.text);
      fd.append("in_active_call", String(form.inActiveCall));
      if (form.expectedMerchantAccount.trim()) {
        fd.append("expected_merchant_account", form.expectedMerchantAccount.trim());
      }
      if (form.transferAmount.trim()) {
        fd.append("transfer_amount", form.transferAmount.trim());
      }
      for (const imgFile of form.imageFiles) {
        fd.append("images", imgFile);
      }
      for (const audFile of form.audioFiles) {
        fd.append("audios", audFile);
      }
    }

    let capturedToken: string | null = null;
    let capturedTokenCaseId: string | null = null;
    try {
      const finalReport = await analyzeStream(
        fd,
        {
          onTrace: (step) => {
            if (abortRef.current !== controller) return;
            setTraceSteps((prev) => {
              const filtered = prev.filter((p) => p.step_id !== step.step_id);
              return [...filtered, step];
            });
          },
          onResult: (res) => {
            if (abortRef.current !== controller) return;
            setSubmittedSnapshot({
              report: res,
              caseAccessToken: capturedTokenCaseId === res.case_id ? capturedToken : null,
              imageFiles: capturedImageFiles,
              transferAmount: capturedAmount,
              submittedText: capturedText,
            });
          },
          onSession: (session) => {
            if (abortRef.current !== controller) return;
            capturedToken = session.case_access_token;
            capturedTokenCaseId = session.case_id;
            setSubmittedSnapshot((prev) =>
              prev && prev.report.case_id === session.case_id
                ? { ...prev, caseAccessToken: session.case_access_token }
                : prev,
            );
          },
        },
        controller.signal,
      );
      if (abortRef.current === controller) {
        setSubmittedSnapshot({
          report: finalReport,
          caseAccessToken: capturedTokenCaseId === finalReport.case_id ? capturedToken : null,
          imageFiles: capturedImageFiles,
          transferAmount: capturedAmount,
          submittedText: capturedText,
        });
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError" && abortRef.current === controller) {
        setErrorMsg(
          err instanceof Error
            ? err.message
            : "Không thể kết nối tới máy chủ lúc này. Vui lòng thử lại sau.",
        );
        setIsFormCollapsed(false);
      }
    } finally {
      if (abortRef.current === controller) {
        setIsAnalyzing(false);
      }
    }
  }

  function handleSelectDemo(demo: DemoScenario) {
    setActiveDemo(demo);
    const demoText =
      demo.url && !demo.text.includes(demo.url)
        ? `${demo.text}\n${demo.url}`.trim()
        : demo.text;
    setForm({
      text: demoText,
      inActiveCall: demo.in_active_call,
      transferAmount: demo.transfer_amount ? String(demo.transfer_amount) : "",
      expectedMerchantAccount: demo.expected_merchant_account ?? "",
      imageFiles: [],
      audioFiles: [],
    });
    void executeAnalysis(demo);
  }

  function handleManualFormChange(next: WorkbenchFormState) {
    abortRef.current?.abort();
    abortRef.current = null;
    setIsAnalyzing(false);
    setActiveDemo(null);
    setSubmittedSnapshot(null);
    resetAssistant();
    setTraceSteps([]);
    setErrorMsg(null);
    setForm(next);
  }

  const handleOpenAssistant = useCallback(
    (initialPrompt?: string, initialIntent?: AssistantQuickIntent) => {
      if (initialPrompt) {
        setAssistantInitialPrompt(initialPrompt);
        setAssistantInitialIntent(initialIntent ?? null);
        setAssistantPromptNonce((prev) => prev + 1);
      } else {
        setAssistantInitialPrompt(undefined);
        setAssistantInitialIntent(null);
      }
      setIsAssistantOpen(true);
    },
    [],
  );

  const handleCloseAssistant = useCallback(() => {
    setIsAssistantOpen(false);
  }, []);

  const handleClearInitialPrompt = useCallback(() => {
    setAssistantInitialPrompt(undefined);
    setAssistantInitialIntent(null);
  }, []);

  const report = submittedSnapshot?.report ?? null;
  const caseAccessToken = submittedSnapshot?.caseAccessToken ?? null;
  const canCollapseForm = isAnalyzing || Boolean(report) || traceSteps.length > 0;
  const reportCaseId = report?.case_id ?? null;

  useEffect(() => {
    if (!isAssistantOpen || !reportCaseId || (!caseAccessToken && isAnalyzing)) return;
    if (conversation?.caseId === reportCaseId && conversation.caseAccessToken === caseAccessToken) return;
    setConversation(createConversationRecord(reportCaseId, caseAccessToken));
  }, [caseAccessToken, conversation, isAnalyzing, isAssistantOpen, reportCaseId]);

  useEffect(() => {
    if (conversation?.caseId === reportCaseId) saveHomeConversation(conversation.id, isAssistantOpen);
  }, [conversation, isAssistantOpen, reportCaseId]);

  // Publish non-sensitive active-case flag to Global Command Palette (zero PII)
  useEffect(() => {
    const maskedCaseId = reportCaseId
      ? reportCaseId.length > 14
        ? `${reportCaseId.slice(0, 10)}…${reportCaseId.slice(-4)}`
        : reportCaseId
      : null;
    window.dispatchEvent(
      new CustomEvent("verishield:active-case-changed", {
        detail: { hasActiveCase: Boolean(reportCaseId), maskedCaseId },
      }),
    );
    return () => {
      window.dispatchEvent(
        new CustomEvent("verishield:active-case-changed", {
          detail: { hasActiveCase: false, maskedCaseId: null },
        }),
      );
    };
  }, [reportCaseId]);

  // Listen to Global Command Palette actions on `/`
  useEffect(() => {
    function handleNewAnalysis() {
      abortRef.current?.abort();
      abortRef.current = null;
      setIsAnalyzing(false);
      setIsFormCollapsed(false);
      setActiveDemo(null);
      setSubmittedSnapshot(null);
      restoreRef.current?.abort();
      saveHomeConversation(null);
      setConversation(null);
      setIsAssistantOpen(false);
      setAssistantInitialPrompt(undefined);
      setAssistantInitialIntent(null);
      setTraceSteps([]);
      setErrorMsg(null);
      setForm(INITIAL_FORM);
      window.requestAnimationFrame(() => {
        const textarea = document.querySelector<HTMLTextAreaElement>("main textarea");
        textarea?.focus();
      });
    }
    function handleCommandOpenAssistant() {
      if (reportCaseId) {
        setIsAssistantOpen(true);
      }
    }
    window.addEventListener("verishield:new-analysis", handleNewAnalysis);
    window.addEventListener("verishield:open-assistant", handleCommandOpenAssistant);
    return () => {
      window.removeEventListener("verishield:new-analysis", handleNewAnalysis);
      window.removeEventListener("verishield:open-assistant", handleCommandOpenAssistant);
    };
  }, [reportCaseId]);

  // Bring the verdict into view once per case, only when it landed off-screen. Never moves focus.
  useEffect(() => {
    const el = resultRef.current;
    if (!reportCaseId || !el) return;
    const alreadyScrolledForCase = scrolledCaseRef.current === reportCaseId;
    scrolledCaseRef.current = reportCaseId;
    if (
      shouldAutoScrollIntoView({
        targetTop: el.getBoundingClientRect().top,
        viewportHeight: window.innerHeight,
        headerHeight: ANCHOR_OFFSET_PX,
        alreadyScrolledForCase,
      })
    ) {
      // Offset comes from the container's scroll-margin (honored by Lenis and native scrollIntoView).
      scrollToElement(el);
    }
  }, [reportCaseId, scrollToElement]);

  return (
    <div className="space-y-4">
      <section
        aria-labelledby="hero-heading"
        className="rounded-2xl border border-border-subtle bg-surface px-4 py-4 sm:px-6 sm:py-5"
      >
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
          <div className="flex min-w-0 max-w-2xl items-start gap-3.5">
            <HeroShieldScanner paused={isAnalyzing} />
            <div className="min-w-0">
              <h1
                id="hero-heading"
                className="text-xl font-bold tracking-tight text-ink sm:text-2xl"
              >
                {BRAND_COPY.heroHeading}
              </h1>
              {!canCollapseForm && (
                <p className="mt-1.5 text-sm leading-relaxed text-ink-secondary">
                  {BRAND_COPY.heroDescription}
                </p>
              )}
            </div>
          </div>

          <div className="flex shrink-0 flex-col items-start gap-2.5 sm:items-end">
            {health && (
              <div
                role="status"
                className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-300"
              >
                <span aria-hidden="true" className="h-2 w-2 rounded-full bg-emerald-400" />
                <span>Hệ thống đang hoạt động</span>
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2">
              {health?.telegram_bot_url ? (
                <a
                  href={health.telegram_bot_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex min-h-[38px] items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3 py-1.5 text-xs font-semibold text-sky-200 transition-colors hover:border-sky-400 hover:bg-sky-500/20"
                >
                  <Send className="h-3.5 w-3.5 text-sky-300" aria-hidden="true" />
                  <span>Kiểm tra qua Telegram</span>
                </a>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-xs text-ink-muted">
                  <Send className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
                  <span>Hỗ trợ kiểm tra qua Telegram</span>
                </span>
              )}
              <Link
                href="/radar"
                className="inline-flex min-h-[38px] items-center gap-1.5 rounded-lg border border-border-strong bg-surface-subtle px-3 py-1.5 text-xs font-semibold text-ink-secondary transition-colors hover:border-sky-400/60 hover:text-ink"
              >
                <Radar className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
                <span>Giám sát gian lận</span>
              </Link>
            </div>
          </div>
        </div>
      </section>

      <DemoScenarioBar
        demos={demos}
        activeDemoId={activeDemo?.demo_id ?? null}
        isAnalyzing={isAnalyzing}
        onSelectDemo={handleSelectDemo}
      />

      <InputWorkbench
        value={form}
        isAnalyzing={isAnalyzing}
        activeDemoTitle={activeDemo?.title_vi ?? null}
        collapsed={isFormCollapsed && canCollapseForm}
        canCollapse={canCollapseForm}
        onToggleCollapsed={() => setIsFormCollapsed((prev) => !prev)}
        onChange={handleManualFormChange}
        onSubmit={() => void executeAnalysis()}
        onClearDemo={() => {
          abortRef.current?.abort();
          abortRef.current = null;
          setIsAnalyzing(false);
          setIsFormCollapsed(false);
          setActiveDemo(null);
          setSubmittedSnapshot(null);
          resetAssistant();
          setTraceSteps([]);
          setErrorMsg(null);
          setForm(INITIAL_FORM);
        }}
      />

      {errorMsg && (
        <div
          role="alert"
          className="flex items-center gap-2.5 rounded-xl border border-rose-500/50 bg-rose-500/15 p-4 text-xs font-medium text-rose-100"
        >
          <AlertCircle className="h-4 w-4 shrink-0 text-rose-300" aria-hidden="true" />
          <span>{errorMsg}</span>
        </div>
      )}

      <LiveTracePanel
        steps={traceSteps}
        isAnalyzing={isAnalyzing}
        hasReport={Boolean(report)}
        hasError={Boolean(errorMsg)}
      />

      {report && (
        <div id="verdict-result" ref={resultRef} className="scroll-mt-[84px] space-y-5">
          <InvestigationWorkspace
            report={report}
            caseAccessToken={caseAccessToken}
            submittedText={submittedSnapshot?.submittedText ?? ""}
            transferAmountInput={submittedSnapshot?.transferAmount ?? ""}
            originalPreviewUrls={submittedPreviewUrls}
            onOpenAssistant={handleOpenAssistant}
          />

          <button
            id="assistant-launcher"
            type="button"
            hidden={isAssistantOpen}
            aria-hidden={isAssistantOpen}
            tabIndex={isAssistantOpen ? -1 : 0}
            onClick={() => handleOpenAssistant()}
            aria-label="Mở Trợ lý VeriShield"
            className={`fixed bottom-5 right-5 z-40 min-h-[44px] cursor-pointer items-center gap-2 rounded-full border border-amber-400/75 bg-surface-elevated/95 px-4 py-2.5 text-xs font-bold text-amber-100 shadow-2xl backdrop-blur-xs transition-colors hover:border-amber-300 hover:bg-amber-500/20 ${
              isAssistantOpen ? "hidden" : "inline-flex"
            }`}
          >
            <Sparkles className="h-4 w-4 text-amber-300" aria-hidden="true" />
            <span>Hỏi Trợ lý VeriShield</span>
          </button>

          {conversation?.caseId === report.case_id && <AssistantDrawer
            key={conversation.id}
            report={report}
            conversation={conversation}
            isOpen={isAssistantOpen}
            onClose={handleCloseAssistant}
            initialPrompt={assistantInitialPrompt}
            initialIntent={assistantInitialIntent}
            initialPromptNonce={assistantPromptNonce}
            onClearInitialPrompt={handleClearInitialPrompt}
          />}
        </div>
      )}
    </div>
  );
}
