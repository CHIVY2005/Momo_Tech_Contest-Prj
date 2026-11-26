"use client";

import { AlertCircle, CheckCircle2, Radar, Send } from "lucide-react";
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
import type { AnalysisReport, DemoScenario, SystemHealthResponse, TraceStep } from "@/lib/types";

const INITIAL_FORM: WorkbenchFormState = {
  mode: "personal",
  text: "",
  url: "",
  inActiveCall: false,
  transferAmount: "",
  expectedMerchantAccount: "",
  imageFile: null,
  audioFile: null,
};

interface SubmittedSnapshot {
  report: AnalysisReport;
  imageFile: File | null;
  transferAmount: string;
}

export default function HomePage() {
  const [demos, setDemos] = useState<DemoScenario[]>([]);
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);
  const [form, setForm] = useState<WorkbenchFormState>(INITIAL_FORM);
  const [activeDemo, setActiveDemo] = useState<DemoScenario | null>(null);
  const [traceSteps, setTraceSteps] = useState<TraceStep[]>([]);
  const [submittedSnapshot, setSubmittedSnapshot] = useState<SubmittedSnapshot | null>(null);
  const [submittedPreviewUrl, setSubmittedPreviewUrl] = useState<string | null>(null);
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
    const file = submittedSnapshot?.imageFile ?? null;
    if (!file) {
      setSubmittedPreviewUrl(null);
      return;
    }
    const objUrl = URL.createObjectURL(file);
    setSubmittedPreviewUrl(objUrl);
    return () => URL.revokeObjectURL(objUrl);
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

    const capturedImageFile = !overrideDemo && !activeDemo ? form.imageFile : null;
    const capturedAmount = overrideDemo
      ? overrideDemo.transfer_amount !== null && overrideDemo.transfer_amount !== undefined
        ? String(overrideDemo.transfer_amount)
        : ""
      : form.mode !== "merchant"
        ? form.transferAmount
        : "";

    const fd = new FormData();
    if (overrideDemo) {
      fd.append("demo_id", overrideDemo.demo_id);
      fd.append("mode", overrideDemo.mode);
    } else if (activeDemo) {
      fd.append("demo_id", activeDemo.demo_id);
      fd.append("mode", form.mode);
    } else {
      fd.append("mode", form.mode);
      fd.append("text", form.text);
      if (form.url.trim()) fd.append("url", form.url.trim());
      fd.append("in_active_call", String(form.inActiveCall));
      if (form.mode === "merchant") {
        if (form.expectedMerchantAccount.trim()) {
          fd.append("expected_merchant_account", form.expectedMerchantAccount.trim());
        }
      } else if (form.transferAmount.trim()) {
        fd.append("transfer_amount", form.transferAmount.trim());
      }
      if (form.imageFile) fd.append("image", form.imageFile);
      if (form.audioFile) fd.append("audio", form.audioFile);
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
              imageFile: capturedImageFile,
              transferAmount: capturedAmount,
            });
          },
        },
        controller.signal,
      );
      if (abortRef.current === controller) {
        setSubmittedSnapshot({
          report: finalReport,
          imageFile: capturedImageFile,
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
    setForm({
      mode: demo.mode,
      text: demo.text,
      url: demo.url ?? "",
      inActiveCall: demo.in_active_call,
      transferAmount: demo.transfer_amount ? String(demo.transfer_amount) : "",
      expectedMerchantAccount: demo.expected_merchant_account ?? "",
      imageFile: null,
      audioFile: null,
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
    <div className="space-y-3.5">
      <section className="flex flex-col justify-between gap-2.5 rounded-2xl border border-border-subtle bg-gradient-to-r from-surface via-[#0f172a] to-[#131c31] px-4 py-3 sm:flex-row sm:items-center sm:px-5">
        <div className="min-w-0">
          {!canCollapseForm && (
            <div className="mb-1 inline-flex items-center gap-2 rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 text-[11px] font-semibold text-amber-300">
              <span>Kiểm tra tin nhắn, mã QR, biên lai và ngăn chặn lừa đảo trước khi chuyển tiền</span>
            </div>
          )}
          <h1 className="text-base font-bold tracking-tight text-ink sm:text-lg">
            Phân tích bằng chứng số và bảo vệ tài sản trước khi chuyển tiền
          </h1>
          {!canCollapseForm && (
            <p className="mt-1 max-w-3xl text-xs leading-relaxed text-ink-secondary">
              Kiểm tra nhanh tin nhắn nghi ngờ, đường dẫn lạ, mã VietQR, tính xác thực của hình ảnh
              biên lai và tệp ghi âm cuộc gọi để phát hiện sớm dấu hiệu bất thường.
            </p>
          )}
        </div>

        <div className="flex shrink-0 flex-col items-start gap-1 sm:items-end">
          {health && (
            <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="tabular-num inline-flex items-center gap-1 rounded-md border border-emerald-500/35 bg-emerald-500/10 px-2 py-0.5 text-emerald-300">
                <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Hệ thống sẵn sàng ({health.playbooks_count} kịch bản lừa đảo phổ biến)</span>
              </span>
            </div>
          )}
          <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
            <Send className="h-3 w-3 text-sky-400" aria-hidden="true" />
            {health?.telegram_bot_url ? (
              <a
                href={health.telegram_bot_url}
                target="_blank"
                rel="noopener noreferrer"
                className="font-semibold text-sky-300 underline hover:text-sky-200"
              >
                Kiểm tra qua Telegram
              </a>
            ) : (
              <span>Hỗ trợ kiểm tra qua Telegram</span>
            )}
            <span>·</span>
            <Link href="/radar" className="font-semibold text-sky-300 underline hover:text-sky-200">
              Trung tâm giám sát gian lận
            </Link>
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
              <EvidenceTabs report={report} originalPreviewUrl={submittedPreviewUrl} />
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
                        Đội ngũ vận hành có thể chặn nhanh dấu hiệu này trên toàn hệ thống mà không
                        lưu dữ liệu định danh cá nhân chưa qua xử lý.
                      </p>
                    </div>
                    <Link
                      href="/radar"
                      className="inline-flex min-h-[40px] shrink-0 items-center gap-1.5 rounded-xl border border-sky-400/50 bg-sky-500/15 px-3 py-2 text-xs font-semibold text-sky-200 hover:bg-sky-500/25"
                    >
                      <Radar className="h-4 w-4" aria-hidden="true" />
                      <span>Mở trung tâm giám sát</span>
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
