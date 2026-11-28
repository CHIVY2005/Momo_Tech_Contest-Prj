"use client";

import {
  AlertCircle,
  CheckCircle2,
  FlaskConical,
  Info,
  PlusCircle,
  RefreshCw,
} from "lucide-react";
import dynamic from "next/dynamic";
import { useCallback, useEffect, useRef, useState } from "react";

import { AnimatedNumber } from "@/components/motion/AnimatedNumber";
import { SpotlightGroup } from "@/components/motion/SpotlightGroup";
import { ApiPlaygroundCard } from "@/components/radar/ApiPlaygroundCard";
import { BlockRuleManager } from "@/components/radar/BlockRuleManager";
import { CampaignDetailDrawer } from "@/components/radar/CampaignDetailDrawer";
import { CampaignQueue } from "@/components/radar/CampaignQueue";
import { IocGraphSvg } from "@/components/radar/IocGraphSvg";
import {
  RuleActionModal,
  type RuleModalState,
  type TargetIocOption,
} from "@/components/radar/RuleActionModal";
import {
  createBlockRule,
  fetchRadarGraph,
  resetBlockRules,
  revokeBlockRule,
} from "@/lib/api";
import { resolveRadarMotionScope } from "@/lib/motion/cyberMotion";
import { formatMaskedIoc, formatNodeDisplayLabel, getNextRuleExpiryDelayMs } from "@/lib/radarLayout";

const RadarSweepVisual = dynamic(
  () => import("@/components/radar/RadarSweepVisual").then((mod) => mod.RadarSweepVisual),
  {
    ssr: false,
    loading: () => (
      <div
        aria-hidden="true"
        className="h-12 w-12 shrink-0 rounded-xl border border-border-strong/85 bg-surface-deep"
      />
    ),
  },
);
import type {
  BlockRule,
  EmergingCampaign,
  IocType,
  RadarGraphResponse,
  RadarNode,
} from "@/lib/types";

export default function RadarPage() {
  const [graph, setGraph] = useState<RadarGraphResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isMutating, setIsMutating] = useState(false);
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [detailCampaignId, setDetailCampaignId] = useState<string | null>(null);
  const [ruleModal, setRuleModal] = useState<RuleModalState | null>(null);
  const [simulationOpen, setSimulationOpen] = useState(false);

  const graphReqIdRef = useRef(0);
  const retryTimerRef = useRef<number | null>(null);
  const mountedRef = useRef(true);
  const graphAbortRef = useRef<AbortController | null>(null);

  const clearRetryTimer = useCallback(() => {
    if (retryTimerRef.current !== null) {
      window.clearTimeout(retryTimerRef.current);
      retryTimerRef.current = null;
    }
  }, []);

  const loadGraph = useCallback(async (): Promise<boolean> => {
    clearRetryTimer();
    graphAbortRef.current?.abort();
    const controller = new AbortController();
    graphAbortRef.current = controller;
    const reqId = ++graphReqIdRef.current;
    setIsRefreshing(true);
    try {
      const data = await fetchRadarGraph(controller.signal);
      if (!mountedRef.current || controller.signal.aborted || reqId !== graphReqIdRef.current) {
        return false;
      }
      setGraph(data);
      setNowMs(Date.now());
      return true;
    } catch (e) {
      if (!mountedRef.current || controller.signal.aborted || reqId !== graphReqIdRef.current) {
        return false;
      }
      setBanner({
        kind: "err",
        text: e instanceof Error ? e.message : "Không thể tải dữ liệu giám sát lúc này.",
      });
      retryTimerRef.current = window.setTimeout(() => {
        if (mountedRef.current && reqId === graphReqIdRef.current) {
          void loadGraph();
        }
      }, 5000);
      return false;
    } finally {
      if (mountedRef.current && reqId === graphReqIdRef.current) {
        setIsLoading(false);
        setIsRefreshing(false);
      }
    }
  }, [clearRetryTimer]);

  useEffect(() => {
    mountedRef.current = true;
    void loadGraph();
    return () => {
      mountedRef.current = false;
      graphReqIdRef.current += 1;
      graphAbortRef.current?.abort();
      clearRetryTimer();
    };
  }, [loadGraph, clearRetryTimer]);

  useEffect(() => {
    const activeCount = graph?.active_block_rules.length ?? 0;
    if (activeCount === 0) return;
    const tick = window.setInterval(() => setNowMs(Date.now()), 5000);
    return () => window.clearInterval(tick);
  }, [graph?.active_block_rules.length]);

  useEffect(() => {
    const activeRules = graph?.active_block_rules ?? [];
    const delayMs = getNextRuleExpiryDelayMs(activeRules, Date.now());
    if (delayMs === null) {
      return;
    }
    const timer = window.setTimeout(() => {
      void loadGraph();
    }, delayMs);
    return () => window.clearTimeout(timer);
  }, [graph, loadGraph]);

  function openCampaignBlockModal(campaign: EmergingCampaign) {
    const nodeMap = new Map((graph?.nodes ?? []).map((n) => [n.node_id, n]));
    const linkedIds = new Set<string>([campaign.primary_ioc_hash]);
    for (const edge of graph?.edges ?? []) {
      if (edge.source === campaign.campaign_id && edge.target !== campaign.campaign_id) {
        linkedIds.add(edge.target);
      } else if (edge.target === campaign.campaign_id && edge.source !== campaign.campaign_id) {
        linkedIds.add(edge.source);
      }
    }

    const targets: TargetIocOption[] = [];
    for (const id of linkedIds) {
      const node = nodeMap.get(id);
      if (node && node.kind !== "campaign" && !node.blocked) {
        targets.push({
          iocType: node.kind as IocType,
          iocHash: node.node_id,
          maskedLabel: formatNodeDisplayLabel(node),
        });
      }
    }
    if (targets.length === 0) {
      targets.push({
        iocType: campaign.primary_ioc_type,
        iocHash: campaign.primary_ioc_hash,
        maskedLabel: campaign.primary_ioc_masked,
      });
    }

    const initialHash =
      targets.find((t) => t.iocHash === campaign.primary_ioc_hash)?.iocHash ??
      targets[0]?.iocHash ??
      campaign.primary_ioc_hash;

    setRuleModal({
      kind: "create_targeted",
      title: campaign.title_vi,
      targets,
      initialHash,
      defaultReason: campaign.recommended_action,
    });
  }

  const openNodeBlockModal = useCallback((node: RadarNode) => {
    if (node.kind === "campaign") return;
    const label = formatNodeDisplayLabel(node);
    setRuleModal({
      kind: "create_targeted",
      title: "Đối tượng được chọn trên mạng lưới",
      targets: [
        {
          iocType: node.kind as IocType,
          iocHash: node.node_id,
          maskedLabel: label,
        },
      ],
      initialHash: node.node_id,
      defaultReason: `Áp dụng quy tắc chặn tạm thời cho dấu hiệu ${label}`,
    });
  }, []);

  async function handleCreateRule(payload: {
    iocType: IocType;
    rawValue?: string;
    iocHash?: string;
    reason: string;
    ttlMinutes: number;
    analystPin: string;
  }): Promise<string | null> {
    setIsMutating(true);
    setBanner(null);
    try {
      const rule = await createBlockRule({
        ioc_type: payload.iocType,
        value: payload.rawValue,
        ioc_hash: payload.iocHash,
        reason: payload.reason,
        ttl_minutes: payload.ttlMinutes,
        analyst_pin: payload.analystPin,
      });
      const refreshed = await loadGraph();
      const displayTarget = formatMaskedIoc(rule.masked_value, rule.rule_id);
      setBanner({
        kind: refreshed ? "ok" : "err",
        text: refreshed
          ? `Đã áp dụng quy tắc chặn cho ${displayTarget} (hiệu lực ${payload.ttlMinutes} phút).`
          : `Đã tạo quy tắc cho ${displayTarget} nhưng chưa đồng bộ được sơ đồ (đang tự thử lại).`,
      });
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : "Không thể áp dụng quy tắc chặn lúc này.";
    } finally {
      setIsMutating(false);
    }
  }

  async function handleRevokeRule(ruleId: string, analystPin: string): Promise<string | null> {
    setIsMutating(true);
    setBanner(null);
    try {
      await revokeBlockRule(ruleId, analystPin);
      const refreshed = await loadGraph();
      setBanner({
        kind: refreshed ? "ok" : "err",
        text: refreshed
          ? "Đã thu hồi quy tắc chặn và đồng bộ trạng thái mạng lưới."
          : "Đã thu hồi quy tắc nhưng chưa đồng bộ được sơ đồ.",
      });
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : "Không thể thu hồi quy tắc chặn lúc này.";
    } finally {
      setIsMutating(false);
    }
  }

  async function handleResetDemoRules(analystPin: string): Promise<string | null> {
    setIsMutating(true);
    setBanner(null);
    try {
      const res = await resetBlockRules(analystPin);
      const refreshed = await loadGraph();
      setBanner({
        kind: refreshed ? "ok" : "err",
        text: refreshed
          ? `Đã khôi phục dữ liệu mẫu (đã thu hồi ${res.cleared_rules} quy tắc tạm thời).`
          : `Đã thu hồi ${res.cleared_rules} quy tắc nhưng chưa đồng bộ được sơ đồ.`,
      });
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : "Không thể khôi phục dữ liệu mẫu lúc này.";
    } finally {
      setIsMutating(false);
    }
  }

  const detailCampaign = detailCampaignId
    ? (graph?.campaigns.find((c) => c.campaign_id === detailCampaignId) ?? null)
    : null;

  const totalCases = graph?.stats.total_cases ?? 0;
  const totalCampaigns = graph?.stats.emerging_campaigns ?? graph?.campaigns.length ?? 0;
  const demoCampaigns = graph?.stats.demo_campaigns ?? 0;
  const realCampaigns = graph?.stats.real_campaigns ?? Math.max(0, totalCampaigns - demoCampaigns);
  const totalIocs = graph?.stats.tracked_iocs ?? 0;
  const demoIocs = graph?.stats.demo_iocs ?? 0;
  const realIocs = graph?.stats.real_iocs ?? Math.max(0, totalIocs - demoIocs);
  const activeBlocks = graph?.active_block_rules.length ?? 0;
  const hasDemoData =
    graph?.data_scope === "demo_only" ||
    graph?.data_scope === "mixed_with_demo" ||
    demoCampaigns > 0 ||
    demoIocs > 0;
  const radarMotionScope = resolveRadarMotionScope(graph?.data_scope, hasDemoData);

  return (
    <div className="space-y-4 sm:space-y-5">
      {/* Clean Security Operations Header */}
      <section className="flex flex-col justify-between gap-3 rounded-2xl border border-border-subtle bg-gradient-to-r from-surface via-[#0f172a] to-[#0c1f2e] px-4 py-4 sm:flex-row sm:items-center sm:px-5">
        <div className="flex items-start gap-3">
          <RadarSweepVisual scope={radarMotionScope} isRefreshing={isRefreshing} />
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-lg font-bold text-ink sm:text-xl">Giám sát gian lận</h1>
              {graph && (
                <span
                  role="status"
                  className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10.5px] font-semibold ${
                    hasDemoData
                      ? "border-sky-500/40 bg-sky-500/12 text-sky-200"
                      : "border-emerald-500/40 bg-emerald-500/12 text-emerald-200"
                  }`}
                >
                  <span
                    aria-hidden="true"
                    className={`h-1.5 w-1.5 rounded-full ${hasDemoData ? "bg-sky-400" : "bg-emerald-400"}`}
                  />
                  <span>
                    {graph.data_scope === "live"
                      ? "Dữ liệu vận hành thực tế"
                      : graph.data_scope === "mixed_with_demo"
                        ? "Thực tế + Mẫu minh họa"
                        : "Môi trường dữ liệu mẫu"}
                  </span>
                </span>
              )}
            </div>
            <p className="mt-1 max-w-2xl text-xs leading-relaxed text-ink-secondary">
              Theo dõi các chiến dịch lừa đảo, phân tích mối liên hệ và quản lý quy tắc chặn tạm thời.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={isRefreshing}
            onClick={() => void loadGraph()}
            className="inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-xl border border-border-strong bg-surface-subtle px-3 py-2 text-xs font-semibold text-ink transition-colors hover:border-sky-400 disabled:opacity-60"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 text-sky-400 ${isRefreshing ? "animate-spin" : ""}`}
              aria-hidden="true"
            />
            <span>Làm mới</span>
          </button>

          <button
            type="button"
            onClick={() => setSimulationOpen(true)}
            className="inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-xl border border-sky-500/45 bg-sky-500/12 px-3 py-2 text-xs font-semibold text-sky-200 transition-colors hover:bg-sky-500/20"
          >
            <FlaskConical className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
            <span>Mô phỏng giao dịch</span>
          </button>

          <button
            type="button"
            disabled={isMutating}
            onClick={() => setRuleModal({ kind: "create_manual" })}
            className="inline-flex min-h-[38px] cursor-pointer items-center gap-1.5 rounded-xl bg-amber-500 px-3.5 py-2 text-xs font-bold text-slate-950 transition-colors hover:bg-amber-400 disabled:opacity-60"
          >
            <PlusCircle className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Thêm quy tắc</span>
          </button>
        </div>
      </section>

      {/* 4 Standardized KPI Cards with transparent real vs. demo scope */}
      {isLoading && !graph ? (
        <div
          aria-label="Đang tải thống kê giám sát"
          className="grid grid-cols-2 gap-3 sm:grid-cols-4"
        >
          {[0, 1, 2, 3].map((idx) => (
            <div
              key={idx}
              className="h-24 animate-pulse rounded-xl border border-border-subtle bg-surface p-3.5"
            />
          ))}
        </div>
      ) : graph ? (
        <div className="space-y-2.5">
          <SpotlightGroup className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="vs-spotlight vs-spotlight-cyan rounded-xl border border-border-subtle bg-surface p-3.5">
              <p className="text-xs font-medium text-ink-muted">Hồ sơ đã phân tích</p>
              <p className="tabular-num mt-1 font-mono text-2xl font-bold text-ink">
                <AnimatedNumber value={totalCases} />
              </p>
              <p className="mt-1 text-[11px] text-ink-muted">
                Từ kiểm tra thực tế (không tính mô phỏng)
              </p>
            </div>

            <div className="vs-spotlight vs-spotlight-cyan rounded-xl border border-border-subtle bg-surface p-3.5">
              <p className="text-xs font-medium text-ink-muted">Chiến dịch nghi vấn</p>
              <p className="tabular-num mt-1 font-mono text-2xl font-bold text-rose-400">
                <AnimatedNumber value={totalCampaigns} />
              </p>
              <p className="tabular-num mt-1 text-[11px] text-ink-muted">
                {demoCampaigns > 0
                  ? `${realCampaigns} thực tế · ${demoCampaigns} mẫu minh họa`
                  : "Tổng hợp từ hồ sơ thực tế"}
              </p>
            </div>

            <div className="vs-spotlight vs-spotlight-cyan rounded-xl border border-border-subtle bg-surface p-3.5">
              <p className="text-xs font-medium text-ink-muted">Dấu hiệu nghi vấn</p>
              <p className="tabular-num mt-1 font-mono text-2xl font-bold text-sky-300">
                <AnimatedNumber value={totalIocs} />
              </p>
              <p className="tabular-num mt-1 text-[11px] text-ink-muted">
                {demoIocs > 0
                  ? `${realIocs} thực tế · ${demoIocs} mẫu minh họa`
                  : "Ghi nhận từ phiên phân tích thực tế"}
              </p>
            </div>

            <div className="vs-spotlight vs-spotlight-cyan rounded-xl border border-border-subtle bg-surface p-3.5">
              <p className="text-xs font-medium text-ink-muted">Quy tắc đang áp dụng</p>
              <p className="tabular-num mt-1 font-mono text-2xl font-bold text-amber-300">
                <AnimatedNumber value={activeBlocks} />
              </p>
              <p className="mt-1 text-[11px] text-ink-muted">
                Đang hiệu lực (tự hết hạn theo TTL)
              </p>
            </div>
          </SpotlightGroup>

          {hasDemoData && (
            <div className="flex items-start gap-2 rounded-xl border border-sky-500/30 bg-sky-500/8 px-3.5 py-2 text-[11px] text-sky-100">
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sky-400" aria-hidden="true" />
              <p>
                Phạm vi dữ liệu hiện tại bao gồm <strong>dữ liệu mẫu minh họa</strong> (được gắn
                nhãn riêng) nhằm phục vụ kiểm thử vận hành; hiệu ứng quét radar và luồng liên kết
                trên sơ đồ chỉ minh họa cấu trúc mạng lưới, không phải cảnh báo khẩn cấp thực tế,
                và các phiên chạy trong <strong>Mô phỏng giao dịch</strong> không làm tăng thống kê
                thực tế.
              </p>
            </div>
          )}
        </div>
      ) : null}

      {/* Operation feedback banner */}
      {banner && (
        <div
          role={banner.kind === "err" ? "alert" : "status"}
          className={`flex items-center justify-between gap-2.5 rounded-xl border p-3.5 text-xs font-medium ${
            banner.kind === "err"
              ? "border-rose-500/50 bg-rose-500/15 text-rose-100"
              : "border-emerald-500/50 bg-emerald-500/15 text-emerald-100"
          }`}
        >
          <div className="flex items-center gap-2.5">
            {banner.kind === "err" ? (
              <AlertCircle className="h-4 w-4 shrink-0 text-rose-300" aria-hidden="true" />
            ) : (
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-300" aria-hidden="true" />
            )}
            <span>{banner.text}</span>
          </div>
          {banner.kind === "err" && !graph && (
            <button
              type="button"
              onClick={() => void loadGraph()}
              className="shrink-0 cursor-pointer rounded-lg border border-rose-400/50 bg-rose-500/20 px-2.5 py-1 text-[11px] font-semibold text-rose-100 hover:bg-rose-500/30"
            >
              Thử lại
            </button>
          )}
        </div>
      )}

      {/* Primary Workspace: Threat Network + Campaigns to Review */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:items-start">
        <div className="xl:col-span-7">
          {isLoading && !graph ? (
            <div className="h-[460px] animate-pulse rounded-2xl border border-border-subtle bg-surface" />
          ) : graph ? (
            <IocGraphSvg
              nodes={graph.nodes}
              edges={graph.edges}
              selectedNodeId={selectedNodeId}
              allowLiveAlertPulse={radarMotionScope.allowLiveAlertPulse}
              onSelectNode={setSelectedNodeId}
              onRequestBlockNode={openNodeBlockModal}
            />
          ) : null}
        </div>

        <div className="xl:col-span-5">
          {isLoading && !graph ? (
            <div className="h-[460px] animate-pulse rounded-2xl border border-border-subtle bg-surface" />
          ) : (
            <CampaignQueue
              campaigns={graph?.campaigns ?? []}
              selectedCampaignId={selectedNodeId}
              isLocked={isMutating}
              onInspectCampaign={(camp) => {
                setSelectedNodeId(camp.campaign_id);
                setDetailCampaignId(camp.campaign_id);
              }}
              onRequestBlockCampaign={(camp) => {
                setSelectedNodeId(camp.campaign_id);
                openCampaignBlockModal(camp);
              }}
            />
          )}
        </div>
      </div>

      {/* Full-width Active Block Rules Table + Audit Log */}
      <BlockRuleManager
        rules={graph?.active_block_rules ?? []}
        auditLogs={graph?.recent_audit_logs ?? []}
        nowMs={nowMs}
        isBusy={isMutating}
        onOpenCreateModal={() => setRuleModal({ kind: "create_manual" })}
        onRequestRevokeRule={(rule: BlockRule) => setRuleModal({ kind: "revoke", rule })}
      />

      {/* Campaign Evidence & IOC Detail Drawer */}
      <CampaignDetailDrawer
        campaign={detailCampaign}
        nodes={graph?.nodes ?? []}
        edges={graph?.edges ?? []}
        onClose={() => setDetailCampaignId(null)}
        onRequestBlockTarget={(target) => {
          setRuleModal({
            kind: "create_targeted",
            title: detailCampaign?.title_vi ?? "Chiến dịch nghi vấn",
            targets: [
              {
                iocType: target.iocType,
                iocHash: target.iocHash,
                maskedLabel: target.maskedLabel,
              },
            ],
            initialHash: target.iocHash,
            defaultReason: target.defaultReason,
          });
        }}
      />

      {/* Privileged Action Confirmation Modal (Create / Revoke / Reset Demo) */}
      <RuleActionModal
        modal={ruleModal}
        isBusy={isMutating}
        onClose={() => setRuleModal(null)}
        onCreateRule={handleCreateRule}
        onRevokeRule={handleRevokeRule}
        onResetDemoRules={handleResetDemoRules}
      />

      {/* On-Demand Transaction Simulation Drawer (non-polluting + isolated demo reset) */}
      <ApiPlaygroundCard
        open={simulationOpen}
        activeRuleCount={activeBlocks}
        showDemoControls={hasDemoData || graph?.app_env !== "production"}
        onClose={() => setSimulationOpen(false)}
        onRequestResetDemo={() =>
          setRuleModal({ kind: "reset_demo", activeCount: activeBlocks })
        }
      />
    </div>
  );
}
