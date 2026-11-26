"use client";

import { AlertCircle, ArrowLeft, CheckCircle2, RefreshCw, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import { ApiPlaygroundCard } from "@/components/radar/ApiPlaygroundCard";
import { BlockRuleManager } from "@/components/radar/BlockRuleManager";
import { CampaignQueue } from "@/components/radar/CampaignQueue";
import { IocGraphSvg } from "@/components/radar/IocGraphSvg";
import {
  createBlockRule,
  fetchRadarGraph,
  resetBlockRules,
  revokeBlockRule,
  validateAnalystPinInput,
} from "@/lib/api";
import { getNextRuleExpiryDelayMs } from "@/lib/radarLayout";
import type { EmergingCampaign, IocType, RadarGraphResponse } from "@/lib/types";

const DEFAULT_DEMO_PIN =
  process.env.NEXT_PUBLIC_APP_ENV === "demo"
    ? (process.env.NEXT_PUBLIC_DEMO_ANALYST_PIN ?? "2026")
    : (process.env.NEXT_PUBLIC_DEMO_ANALYST_PIN ?? "");

export default function RadarPage() {
  const [graph, setGraph] = useState<RadarGraphResponse | null>(null);
  const [analystPin, setAnalystPin] = useState(DEFAULT_DEMO_PIN);
  const [busyCampaignId, setBusyCampaignId] = useState<string | null>(null);
  const [isMutating, setIsMutating] = useState(false);
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
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
        text: e instanceof Error ? e.message : "Không thể tải dữ liệu đồ thị Fraud Ops.",
      });
      retryTimerRef.current = window.setTimeout(() => {
        if (mountedRef.current && reqId === graphReqIdRef.current) {
          void loadGraph();
        }
      }, 5000);
      return false;
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

  const anyWriteBusy = isMutating || busyCampaignId !== null;

  async function handleBlockCampaign(camp: EmergingCampaign) {
    if (anyWriteBusy) return;
    const pinErr = validateAnalystPinInput(analystPin);
    if (pinErr) {
      setBanner({ kind: "err", text: pinErr });
      return;
    }
    setBusyCampaignId(camp.campaign_id);
    setBanner(null);
    try {
      const rule = await createBlockRule({
        ioc_type: camp.primary_ioc_type,
        ioc_hash: camp.primary_ioc_hash,
        reason: camp.recommended_action,
        analyst_pin: analystPin,
      });
      const refreshed = await loadGraph();
      setBanner({
        kind: refreshed ? "ok" : "err",
        text: refreshed
          ? `Đã kích hoạt lệnh chặn khẩn cấp cho ${rule.masked_value}! Hãy thử bấm kiểm định ở API Playground bên dưới.`
          : `Đã khóa ${rule.masked_value} trên máy chủ nhưng làm mới đồ thị tạm thời thất bại (tự động thử lại sau 5s).`,
      });
    } catch (e) {
      setBanner({
        kind: "err",
        text: e instanceof Error ? e.message : "Không thể ban hành quy tắc chặn.",
      });
    } finally {
      setBusyCampaignId(null);
    }
  }

  async function handleManualBlock(
    iocType: IocType,
    rawValue: string,
    reason: string,
  ): Promise<boolean> {
    if (anyWriteBusy) return false;
    const pinErr = validateAnalystPinInput(analystPin);
    if (pinErr) {
      setBanner({ kind: "err", text: pinErr });
      return false;
    }
    setIsMutating(true);
    setBanner(null);
    try {
      const rule = await createBlockRule({
        ioc_type: iocType,
        value: rawValue,
        reason,
        analyst_pin: analystPin,
      });
      const refreshed = await loadGraph();
      setBanner({
        kind: refreshed ? "ok" : "err",
        text: refreshed
          ? `Đã mã hóa SHA-256 & khóa thực thể ${rule.masked_value} (TTL 30 phút).`
          : `Đã khóa ${rule.masked_value} trên máy chủ nhưng làm mới đồ thị tạm thời thất bại (tự động thử lại sau 5s).`,
      });
      return true;
    } catch (e) {
      setBanner({
        kind: "err",
        text: e instanceof Error ? e.message : "Lệnh chặn bị từ chối.",
      });
      return false;
    } finally {
      setIsMutating(false);
    }
  }

  async function handleRevokeRule(ruleId: string) {
    if (anyWriteBusy) return;
    const pinErr = validateAnalystPinInput(analystPin);
    if (pinErr) {
      setBanner({ kind: "err", text: pinErr });
      return;
    }
    setIsMutating(true);
    setBanner(null);
    try {
      await revokeBlockRule(ruleId, analystPin);
      const refreshed = await loadGraph();
      setBanner({
        kind: refreshed ? "ok" : "err",
        text: refreshed
          ? "Đã thu hồi lệnh chặn tạm thời khỏi danh sách kích hoạt."
          : "Đã thu hồi lệnh chặn trên máy chủ nhưng làm mới đồ thị tạm thời thất bại.",
      });
    } catch (e) {
      setBanner({
        kind: "err",
        text: e instanceof Error ? e.message : "Không thể thu hồi quy tắc chặn.",
      });
    } finally {
      setIsMutating(false);
    }
  }

  async function handleReset() {
    if (anyWriteBusy) return;
    const pinErr = validateAnalystPinInput(analystPin);
    if (pinErr) {
      setBanner({ kind: "err", text: pinErr });
      return;
    }
    setIsMutating(true);
    setBanner(null);
    try {
      const res = await resetBlockRules(analystPin);
      const refreshed = await loadGraph();
      setBanner({
        kind: refreshed ? "ok" : "err",
        text: refreshed
          ? `Đã khôi phục trạng thái Demo sạch (gỡ ${res.cleared_rules} lệnh chặn tạm thời).`
          : `Đã gỡ ${res.cleared_rules} lệnh chặn nhưng làm mới đồ thị tạm thời thất bại (tự động thử lại sau 5s).`,
      });
    } catch (e) {
      setBanner({
        kind: "err",
        text: e instanceof Error ? e.message : "Không thể reset danh sách chặn.",
      });
    } finally {
      setIsMutating(false);
    }
  }

  return (
    <div className="space-y-4 sm:space-y-5">
      <section className="flex flex-col justify-between gap-3 rounded-2xl border border-border-subtle bg-gradient-to-r from-surface via-[#0f172a] to-[#0c1f2e] px-4 py-3.5 sm:flex-row sm:items-center sm:px-5 sm:py-4">
        <div>
          <div className="inline-flex items-center gap-1.5 rounded-full border border-sky-500/40 bg-sky-500/10 px-2.5 py-0.5 text-[11px] font-semibold text-sky-300">
            <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Closed-Loop Fintech Fraud Operations Workspace</span>
          </div>
          <h1 className="mt-1.5 text-lg font-bold text-ink sm:text-xl">
            Trung tâm Điều hành Chống Gian lận Khép kín (/radar)
          </h1>
          <p className="mt-1 max-w-3xl text-xs leading-relaxed text-ink-secondary">
            Biến cảnh báo từ người dùng cuối thành lá chắn toàn hệ sinh thái trong 1 cú nhấp chuột —
            mọi SĐT và STK đều được băm SHA-256 &amp; che dấu PII ngay từ tầng lưu trữ.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void loadGraph()}
            className="inline-flex min-h-[40px] cursor-pointer items-center gap-1.5 rounded-xl border border-border-strong bg-surface-subtle px-3.5 py-2 text-xs font-semibold text-ink hover:border-sky-400"
          >
            <RefreshCw className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
            <span>Làm mới Đồ thị</span>
          </button>
          <Link
            href="/"
            className="inline-flex min-h-[40px] items-center gap-1.5 rounded-xl border border-amber-500/40 bg-amber-500/15 px-3.5 py-2 text-xs font-semibold text-amber-200 hover:bg-amber-500/25"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Về Workbench &amp; Ví 30s</span>
          </Link>
        </div>
      </section>

      {graph && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-xl border border-border-subtle bg-surface p-3.5">
            <p className="text-xs text-ink-muted">Tổng Hồ sơ Đã Thẩm định</p>
            <p className="tabular-num mt-1 font-mono text-2xl font-bold text-ink">
              {graph.stats.total_cases ?? 0}
            </p>
          </div>
          <div className="rounded-xl border border-border-subtle bg-surface p-3.5">
            <p className="text-xs text-ink-muted">Chiến dịch Lừa đảo Bùng phát</p>
            <p className="tabular-num mt-1 font-mono text-2xl font-bold text-rose-400">
              {graph.stats.emerging_campaigns ?? graph.campaigns.length}
            </p>
          </div>
          <div className="rounded-xl border border-border-subtle bg-surface p-3.5">
            <p className="text-xs text-ink-muted">Thực thể IOC Đã Ghi nhận</p>
            <p className="tabular-num mt-1 font-mono text-2xl font-bold text-sky-300">
              {graph.stats.tracked_iocs ?? graph.nodes.length}
            </p>
          </div>
          <div className="rounded-xl border border-border-subtle bg-surface p-3.5">
            <p className="text-xs text-ink-muted">Quy tắc Chặn Đang Bật</p>
            <p className="tabular-num mt-1 font-mono text-2xl font-bold text-amber-300">
              {graph.active_block_rules.length}
            </p>
          </div>
        </div>
      )}

      {banner && (
        <div
          role={banner.kind === "err" ? "alert" : "status"}
          className={`flex items-center gap-2.5 rounded-xl border p-3.5 text-xs font-medium ${
            banner.kind === "err"
              ? "border-rose-500/50 bg-rose-500/15 text-rose-100"
              : "border-emerald-500/50 bg-emerald-500/15 text-emerald-100"
          }`}
        >
          {banner.kind === "err" ? (
            <AlertCircle className="h-4 w-4 shrink-0 text-rose-300" aria-hidden="true" />
          ) : (
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-300" aria-hidden="true" />
          )}
          <span>{banner.text}</span>
        </div>
      )}

      {/* Scene 4 Side-by-Side: clicking 1-Click Block turns graph nodes crimson in the exact same frame */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:items-start">
        <div className="xl:col-span-7">
          {graph && <IocGraphSvg nodes={graph.nodes} edges={graph.edges} />}
        </div>
        <div className="xl:col-span-5">
          <CampaignQueue
            campaigns={graph?.campaigns ?? []}
            busyCampaignId={busyCampaignId}
            isLocked={anyWriteBusy}
            onBlockCampaign={(camp) => void handleBlockCampaign(camp)}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:items-start">
        <div className="xl:col-span-6">
          <BlockRuleManager
            rules={graph?.active_block_rules ?? []}
            analystPin={analystPin}
            nowMs={nowMs}
            isBusy={anyWriteBusy}
            onPinChange={setAnalystPin}
            onCreateManualRule={handleManualBlock}
            onRevokeRule={(ruleId) => void handleRevokeRule(ruleId)}
            onResetRules={() => void handleReset()}
          />
        </div>
        <div className="xl:col-span-6">
          <ApiPlaygroundCard />
        </div>
      </div>
    </div>
  );
}
