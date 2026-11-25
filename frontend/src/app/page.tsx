"use client";

import { AlertCircle, CheckCircle2, Cpu, Radar, Send } from "lucide-react";
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

export default function HomePage() {
  const [demos, setDemos] = useState<DemoScenario[]>([]);
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);
  const [form, setForm] = useState<WorkbenchFormState>(INITIAL_FORM);
  const [activeDemo, setActiveDemo] = useState<DemoScenario | null>(null);
  const [traceSteps, setTraceSteps] = useState<TraceStep[]>([]);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [localImagePreview, setLocalImagePreview] = useState<string | null>(null);
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
    if (!form.imageFile) {
      setLocalImagePreview(null);
      return;
    }
    const objUrl = URL.createObjectURL(form.imageFile);
    setLocalImagePreview(objUrl);
    return () => URL.revokeObjectURL(objUrl);
  }, [form.imageFile]);

  async function executeAnalysis(overrideDemo?: DemoScenario) {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setErrorMsg(null);
    setTraceSteps([]);
    setIsAnalyzing(true);

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
      if (form.transferAmount.trim()) fd.append("transfer_amount", form.transferAmount.trim());
      if (form.expectedMerchantAccount.trim()) {
        fd.append("expected_merchant_account", form.expectedMerchantAccount.trim());
      }
      if (form.imageFile) fd.append("image", form.imageFile);
      if (form.audioFile) fd.append("audio", form.audioFile);
    }

    try {
      const finalReport = await analyzeStream(
        fd,
        {
          onTrace: (step) => {
            setTraceSteps((prev) => {
              const filtered = prev.filter((p) => p.step_id !== step.step_id);
              return [...filtered, step];
            });
          },
          onResult: (res) => {
            setReport(res);
          },
        },
        controller.signal,
      );
      setReport(finalReport);
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setErrorMsg(err instanceof Error ? err.message : "Đã xảy ra lỗi khi kết nối máy chủ.");
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
    setActiveDemo(null);
    setForm(next);
  }

  return (
    <div className="space-y-6">
      <section className="flex flex-col justify-between gap-4 rounded-2xl border border-slate-800 bg-gradient-to-r from-[#111827] via-[#0f172a] to-[#131c31] p-5 sm:flex-row sm:items-center">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-0.5 text-xs font-semibold text-amber-300">
            <span>Bảo vệ từ Phút 01 (Tin nhắn / QR / Bill giả) tới Phút 89 (Trước Chuyển Tiền)</span>
          </div>
          <h1 className="mt-2 text-xl font-bold tracking-tight text-slate-50 sm:text-2xl">
            Không gian Điều tra Lừa đảo Đa phương thức &amp; Phòng vệ Giao dịch Số
          </h1>
          <p className="mt-1 max-w-3xl text-xs leading-relaxed text-slate-300 sm:text-sm">
            Phân tích kết hợp giải mã khung EMVCo VietQR, pháp y ảnh ELA 4 lớp, phân loại ngữ nghĩa{" "}
            <code className="font-[family-name:var(--font-mono)] text-sky-300">
              multilingual-e5-small INT8 ONNX
            </code>{" "}
            và suy luận đa phương thức cô lập an toàn.
          </p>
        </div>

        <div className="flex shrink-0 flex-col items-start gap-2 sm:items-end">
          {health && (
            <div className="flex flex-wrap items-center gap-2 text-[11px]">
              <span className="inline-flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-emerald-300">
                <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                <span>API Sẵn sàng ({health.playbooks_count} kịch bản VN)</span>
              </span>
              <span className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-900 px-2 py-1 font-[family-name:var(--font-mono)] text-slate-300">
                <Cpu className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
                <span>{health.onnx_classifier_loaded ? "ONNX Active" : "Hybrid KB Mode"}</span>
              </span>
            </div>
          )}
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Send className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
            <span>Hỗ trợ Bot Telegram 1-Chạm &amp;</span>
            <Link href="/radar" className="font-semibold text-sky-300 underline hover:text-sky-200">
              Khóa IOC Khép kín (/radar)
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
        onChange={handleManualFormChange}
        onSubmit={() => void executeAnalysis()}
        onClearDemo={() => {
          setActiveDemo(null);
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

      <LiveTracePanel steps={traceSteps} isAnalyzing={isAnalyzing} />

      {report && (
        <div className="space-y-6">
          <VerdictDashboard report={report} />

          <WalletPreTransferSim report={report} transferAmountInput={form.transferAmount} />

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            <div className="lg:col-span-7">
              <EvidenceTabs report={report} originalPreviewUrl={localImagePreview} />
            </div>
            <div className="lg:col-span-5">
              <ActionCopilotPanel report={report} />

              {(report.iocs.bank_accounts.length > 0 ||
                report.iocs.domains.length > 0 ||
                report.iocs.phones.length > 0) && (
                <div className="mt-4 rounded-2xl border border-sky-500/30 bg-[#111827]/95 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-bold text-sky-200">
                        Đã ghi nhận Thực thể Đáng ngờ vào Đồ thị Chiến dịch
                      </p>
                      <p className="mt-0.5 text-[11px] text-slate-400">
                        Chuyên viên Fraud Ops có thể khóa khẩn cấp IOC (ẩn danh hóa PII) trên toàn hệ thống.
                      </p>
                    </div>
                    <Link
                      href="/radar"
                      className="inline-flex shrink-0 items-center gap-1.5 rounded-xl border border-sky-400/50 bg-sky-500/15 px-3 py-2 text-xs font-semibold text-sky-200 hover:bg-sky-500/25"
                    >
                      <Radar className="h-4 w-4" aria-hidden="true" />
                      <span>Mở /radar</span>
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
