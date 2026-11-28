"use client";

import { BarChart3, ListChecks, Network, Radar } from "lucide-react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { type KeyboardEvent, useCallback, useEffect, useRef, useState } from "react";

import { ActionCopilotPanel } from "@/components/copilot/ActionCopilotPanel";
import { EvidenceTabs, type ExtendedEvidenceTabKey } from "@/components/evidence/EvidenceTabs";
import { useSmoothScroll } from "@/components/motion/SmoothScrollProvider";
import { WalletPreTransferSim } from "@/components/wallet/WalletPreTransferSim";
import { VerdictDashboard } from "@/components/workbench/VerdictDashboard";
import type { EvidenceTabKey } from "@/lib/explainableAi";
import type { AnalysisReport, AssistantQuickIntent } from "@/lib/types";

import { OfficialChannelsCard } from "./OfficialChannelsCard";

const ExplainableAiPanel = dynamic(
  () => import("@/components/xai/ExplainableAiPanel").then((mod) => mod.ExplainableAiPanel),
  {
    ssr: false,
    loading: () => (
      <div
        aria-busy="true"
        className="flex h-[320px] items-center justify-center rounded-2xl border border-border-subtle bg-surface/95 text-xs text-ink-muted"
      >
        Đang tải bảng Giải thích AI (Explainable AI)...
      </div>
    ),
  },
);

const FraudRelationshipGraph = dynamic(
  () => import("./FraudRelationshipGraph").then((mod) => mod.FraudRelationshipGraph),
  {
    ssr: false,
    loading: () => (
      <div
        aria-busy="true"
        className="flex h-[480px] items-center justify-center rounded-2xl border border-border-subtle bg-surface/95 text-xs text-ink-muted"
      >
        Đang tải sơ đồ mối liên hệ thực thể...
      </div>
    ),
  },
);

export type WorkspaceTabKey = "overview" | "xai" | "graph";

interface InvestigationWorkspaceProps {
  report: AnalysisReport;
  caseAccessToken: string | null;
  submittedText: string;
  transferAmountInput: string;
  originalPreviewUrls: string[];
  onOpenAssistant: (initialPrompt?: string, initialIntent?: AssistantQuickIntent) => void;
}

const WORKSPACE_TABS: ReadonlyArray<{
  id: WorkspaceTabKey;
  label: string;
  hint: string;
  Icon: typeof ListChecks;
}> = [
  {
    id: "overview",
    label: "Bằng chứng & Ứng phó",
    hint: "Bằng chứng chi tiết và hướng dẫn xử lý ngay",
    Icon: ListChecks,
  },
  {
    id: "xai",
    label: "Giải thích AI (XAI)",
    hint: "Tín hiệu phát hiện, biểu đồ E5 ONNX & dòng thời gian",
    Icon: BarChart3,
  },
  {
    id: "graph",
    label: "Sơ đồ liên kết",
    hint: "Mối quan hệ giữa URL, tên miền, STK, SĐT và dấu hiệu",
    Icon: Network,
  },
];

export function InvestigationWorkspace({
  report,
  caseAccessToken,
  submittedText,
  transferAmountInput,
  originalPreviewUrls,
  onOpenAssistant,
}: InvestigationWorkspaceProps) {
  const [workspaceTab, setWorkspaceTab] = useState<WorkspaceTabKey>("overview");
  const [evidenceTab, setEvidenceTab] = useState<ExtendedEvidenceTabKey>("all");
  const [highlightedSource, setHighlightedSource] = useState<string | null>(null);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const workspaceRef = useRef<HTMLDivElement | null>(null);
  const { scrollToElement } = useSmoothScroll();

  useEffect(() => {
    setWorkspaceTab("overview");
    setEvidenceTab("all");
    setHighlightedSource(null);
  }, [report.case_id]);

  // Listen for Global Command Palette tab switch events
  useEffect(() => {
    function handleSwitchTab(ev: Event) {
      const detail = (ev as CustomEvent<{ tab?: WorkspaceTabKey }>).detail;
      if (detail?.tab && (detail.tab === "overview" || detail.tab === "xai" || detail.tab === "graph")) {
        setWorkspaceTab(detail.tab);
        if (workspaceRef.current) {
          scrollToElement(workspaceRef.current);
        }
      }
    }
    window.addEventListener("verishield:workspace-tab", handleSwitchTab);
    return () => window.removeEventListener("verishield:workspace-tab", handleSwitchTab);
  }, [scrollToElement]);

  const handleNavigateToEvidence = useCallback(
    (tab: EvidenceTabKey, source?: string) => {
      setWorkspaceTab("overview");
      setEvidenceTab(tab);
      setHighlightedSource(source ?? null);
      window.requestAnimationFrame(() => {
        const panel = document.getElementById("evidence-viewer-panel");
        if (panel) {
          scrollToElement(panel);
        }
      });
    },
    [scrollToElement],
  );

  const handleOpenXai = useCallback(() => {
    setWorkspaceTab("xai");
    window.requestAnimationFrame(() => {
      if (workspaceRef.current) {
        scrollToElement(workspaceRef.current);
      }
    });
  }, [scrollToElement]);

  function handleTabKeyDown(ev: KeyboardEvent<HTMLButtonElement>, idx: number) {
    let nextIdx = idx;
    if (ev.key === "ArrowRight") nextIdx = (idx + 1) % WORKSPACE_TABS.length;
    else if (ev.key === "ArrowLeft") nextIdx = (idx - 1 + WORKSPACE_TABS.length) % WORKSPACE_TABS.length;
    else if (ev.key === "Home") nextIdx = 0;
    else if (ev.key === "End") nextIdx = WORKSPACE_TABS.length - 1;
    else return;
    ev.preventDefault();
    const target = WORKSPACE_TABS[nextIdx];
    if (target) {
      setWorkspaceTab(target.id);
      tabRefs.current[nextIdx]?.focus();
    }
  }

  return (
    <div className="space-y-5">
      {/* Tier 1 (Immediate Decision): Everyday users see verdict & pre-transfer guard immediately */}
      <VerdictDashboard
        report={report}
        onOpenAssistant={onOpenAssistant}
        onInspectSignal={handleNavigateToEvidence}
        onOpenXai={handleOpenXai}
      />

      <WalletPreTransferSim report={report} transferAmountInput={transferAmountInput} />

      {/* Tier 2 (Progressive Disclosure Investigation Workspace) */}
      <div ref={workspaceRef} className="scroll-mt-[84px] space-y-4">
        <div
          role="tablist"
          aria-label="Không gian điều tra hồ sơ"
          className="flex flex-wrap items-center gap-2 rounded-2xl border border-border-subtle bg-surface/95 p-2 shadow-md"
        >
          {WORKSPACE_TABS.map(({ id, label, hint, Icon }, idx) => {
            const active = workspaceTab === id;
            return (
              <button
                key={id}
                ref={(el) => {
                  tabRefs.current[idx] = el;
                }}
                id={`ws-tab-${id}`}
                type="button"
                role="tab"
                tabIndex={active ? 0 : -1}
                aria-selected={active}
                aria-controls={`ws-panel-${id}`}
                title={hint}
                onClick={() => setWorkspaceTab(id)}
                onKeyDown={(ev) => handleTabKeyDown(ev, idx)}
                className={`vs-pressable inline-flex min-h-[40px] flex-1 cursor-pointer items-center justify-center gap-2 rounded-xl border px-3.5 py-2 text-xs font-bold sm:flex-none ${
                  active
                    ? "border-amber-400/80 bg-amber-500/15 text-amber-100 shadow-sm"
                    : "border-transparent bg-surface-subtle/70 text-ink-secondary hover:border-border-strong hover:text-ink"
                }`}
              >
                <Icon
                  className={`h-4 w-4 shrink-0 ${active ? "text-amber-300" : "text-sky-400"}`}
                  aria-hidden="true"
                />
                <span>{label}</span>
              </button>
            );
          })}
        </div>

        <div
          id={`ws-panel-${workspaceTab}`}
          role="tabpanel"
          aria-labelledby={`ws-tab-${workspaceTab}`}
        >
          {workspaceTab === "overview" && (
            <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
              <div className="xl:col-span-7">
                <EvidenceTabs
                  report={report}
                  originalPreviewUrl={originalPreviewUrls[0] ?? null}
                  originalPreviewUrls={originalPreviewUrls}
                  submittedText={submittedText}
                  activeTab={evidenceTab}
                  onTabChange={setEvidenceTab}
                  highlightedSource={highlightedSource}
                  onClearHighlightedSource={() => setHighlightedSource(null)}
                />
              </div>

              <div className="space-y-4 xl:col-span-5">
                <ActionCopilotPanel report={report} caseAccessToken={caseAccessToken} />

                <OfficialChannelsCard />

                {(report.iocs.bank_accounts.length > 0 ||
                  report.iocs.domains.length > 0 ||
                  report.iocs.phones.length > 0) && (
                  <div className="rounded-2xl border border-sky-500/35 bg-surface/95 p-4">
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
          )}

          {workspaceTab === "xai" && (
            <ExplainableAiPanel
              report={report}
              onNavigateToEvidence={handleNavigateToEvidence}
            />
          )}

          {workspaceTab === "graph" && (
            <FraudRelationshipGraph
              report={report}
              submittedText={submittedText}
              onNavigateToEvidence={handleNavigateToEvidence}
            />
          )}
        </div>
      </div>
    </div>
  );
}
