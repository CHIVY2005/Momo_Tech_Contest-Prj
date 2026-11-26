"use client";

import { AlertCircle, Radar, Send } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { ActionCopilotPanel } from "@/components/copilot/ActionCopilotPanel";
import { EvidenceTabs } from "@/components/evidence/EvidenceTabs";
import { WalletPreTransferSim } from "@/components/wallet/WalletPreTransferSim";
import { DemoScenarioBar } from "@/components/workbench/DemoScenarioBar";
import { InputWorkbench, type WorkbenchFormState } from "@/components/workbench/InputWorkbench";
import { LiveTracePanel } from "@/components/workbench/LiveTracePanel";
import { VerdictDashboard } from "@/components/workbench/VerdictDashboard";
import { analyzeStream, fetchDemos, fetchHealth } from "@/lib/api";
import { inferAnalyzeMode } from "@/lib/composerUtils";
import { BRAND_COPY } from "@/lib/copy";
import type { AnalysisReport, DemoScenario, SystemHealthResponse, TraceStep } from "@/lib/types";

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
  imageFiles: File[];
  transferAmount: string;
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
  const abortRef = useRef<AbortController | null>(null);

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

  useEffect(() => {
    const files = submittedSnapshot?.imageFiles ?? [];
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
  }, [submittedSnapshot]);

  async function executeAnalysis(overrideDemo?: DemoScenario) {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setErrorMsg(null);
    setTraceSteps([]);
    setSubmittedSnapshot(null);
    setIsAnalyzing(true);
    setIsFormCollapsed(true);

    const capturedImageFiles = !overrideDemo && !activeDemo ? [...form.imageFiles] : [];
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
              imageFiles: capturedImageFiles,
              transferAmount: capturedAmount,
            });
          },
        },
        controller.signal,
      );
      if (abortRef.current === controller) {
        setSubmittedSnapshot({
          report: finalReport,
          imageFiles: capturedImageFiles,
          transferAmount: capturedAmount,
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
    setTraceSteps([]);
    setErrorMsg(null);
    setForm(next);
  }

  const report = submittedSnapshot?.report ?? null;
  const canCollapseForm = isAnalyzing || Boolean(report) || traceSteps.length > 0;

  return (
    <div className="space-y-4">
      <section
        aria-labelledby="hero-heading"
        className="rounded-2xl border border-border-subtle bg-surface px-4 py-4 sm:px-6 sm:py-5"
      >
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
          <div className="min-w-0 max-w-2xl">
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

      <LiveTracePanel steps={traceSteps} isAnalyzing={isAnalyzing} hasReport={Boolean(report)} />

      {report && (
        <div className="space-y-5">
          <VerdictDashboard report={report} />

          <WalletPreTransferSim
            report={report}
            transferAmountInput={submittedSnapshot?.transferAmount ?? ""}
          />

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
            <div className="xl:col-span-7">
              <EvidenceTabs
                report={report}
                originalPreviewUrl={submittedPreviewUrls[0] ?? null}
                originalPreviewUrls={submittedPreviewUrls}
              />
            </div>
            <div className="xl:col-span-5">
              <ActionCopilotPanel report={report} />

              {(report.iocs.bank_accounts.length > 0 ||
                report.iocs.domains.length > 0 ||
                report.iocs.phones.length > 0) && (
                <div className="mt-4 rounded-2xl border border-sky-500/35 bg-surface/95 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-bold text-sky-200">
                        Đã ghi nhận dấu hiệu đáng ngờ vào hệ thống giám sát
                      </p>
                      <p className="mt-0.5 text-[11px] text-ink-muted">
                        Đội ngũ vận hành có thể theo dõi và thêm cảnh báo chặn trên toàn hệ thống
                        với thông tin đã che giấu.
                      </p>
                    </div>
                    <Link
                      href="/radar"
                      className="inline-flex min-h-[40px] shrink-0 items-center gap-1.5 rounded-xl border border-sky-400/50 bg-sky-500/15 px-3 py-2 text-xs font-semibold text-sky-200 hover:bg-sky-500/25"
                    >
                      <Radar className="h-4 w-4" aria-hidden="true" />
                      <span>Mở giám sát gian lận</span>
                    </Link>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
