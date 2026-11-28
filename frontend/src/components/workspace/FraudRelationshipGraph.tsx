"use client";

import {
  ArrowRight,
  ArrowUpRight,
  Check,
  Copy,
  Info,
  ListTree,
  Map as MapIcon,
  Network,
} from "lucide-react";
import dynamic from "next/dynamic";
import { useEffect, useMemo, useState } from "react";

import {
  buildCaseRelationshipGraph,
  type CaseEntityKind,
  ENTITY_KIND_LABELS,
  VERIFICATION_STATE_META,
} from "@/lib/caseGraph";
import { mapEvidenceSourceToTab, type EvidenceTabKey } from "@/lib/explainableAi";
import type { AnalysisReport } from "@/lib/types";

const FraudRelationshipFlowCanvas = dynamic(
  () =>
    import("./FraudRelationshipFlowCanvas").then((mod) => mod.FraudRelationshipFlowCanvas),
  {
    ssr: false,
    loading: () => (
      <div
        aria-hidden="true"
        className="flex h-[430px] w-full items-center justify-center rounded-xl border border-border-subtle bg-surface-deep text-xs text-ink-muted sm:h-[470px]"
      >
        Đang khởi tạo sơ đồ liên kết thực thể...
      </div>
    ),
  },
);

interface FraudRelationshipGraphProps {
  report: AnalysisReport;
  submittedText?: string;
  onNavigateToEvidence: (tab: EvidenceTabKey, source?: string) => void;
}

const VERIFICATION_BADGE_STYLE = {
  verified_evidence: "border-emerald-500/45 bg-emerald-500/15 text-emerald-200",
  extracted_info: "border-sky-500/40 bg-sky-500/15 text-sky-200",
  suspected_relation: "border-amber-500/45 bg-amber-500/15 text-amber-200",
  unverified_info: "border-slate-500/45 bg-slate-500/15 text-slate-300",
} as const;

export function FraudRelationshipGraph({
  report,
  submittedText = "",
  onNavigateToEvidence,
}: FraudRelationshipGraphProps) {
  const fullGraph = useMemo(
    () => buildCaseRelationshipGraph(report, submittedText),
    [report, submittedText],
  );

  const [kindFilter, setKindFilter] = useState<"all" | CaseEntityKind>("all");
  const [viewMode, setViewMode] = useState<"graph" | "list">("graph");
  const [showMiniMap, setShowMiniMap] = useState(true);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [layoutNonce, setLayoutNonce] = useState(0);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Mobile-friendly default: switch to accessible structured list on small screens (< 768px)
  useEffect(() => {
    if (typeof window !== "undefined" && window.innerWidth < 768) {
      setViewMode("list");
      setShowMiniMap(false);
    }
  }, []);

  useEffect(() => {
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
    setKindFilter("all");
  }, [report.case_id]);

  const presentKinds = useMemo(() => {
    const counts = new Map<CaseEntityKind, number>();
    for (const node of fullGraph.nodes) {
      counts.set(node.kind, (counts.get(node.kind) ?? 0) + 1);
    }
    return Array.from(counts.entries());
  }, [fullGraph.nodes]);

  const filteredGraph = useMemo(() => {
    if (kindFilter === "all") return fullGraph;
    const directIds = new Set(
      fullGraph.nodes
        .filter((n) => n.kind === kindFilter || n.kind === "case" || n.kind === "verdict")
        .map((n) => n.id),
    );
    const keepIds = new Set(directIds);
    for (const edge of fullGraph.edges) {
      if (directIds.has(edge.source) && fullGraph.nodes.some((n) => n.id === edge.target && n.kind === kindFilter)) {
        keepIds.add(edge.source);
        keepIds.add(edge.target);
      }
      if (directIds.has(edge.target) && fullGraph.nodes.some((n) => n.id === edge.source && n.kind === kindFilter)) {
        keepIds.add(edge.source);
        keepIds.add(edge.target);
      }
    }
    return {
      nodes: fullGraph.nodes.filter((n) => keepIds.has(n.id)),
      edges: fullGraph.edges.filter((e) => keepIds.has(e.source) && keepIds.has(e.target)),
    };
  }, [fullGraph, kindFilter]);

  const nodeMap = useMemo(
    () => new Map(fullGraph.nodes.map((n) => [n.id, n])),
    [fullGraph.nodes],
  );
  const selectedNode = selectedNodeId ? (nodeMap.get(selectedNodeId) ?? null) : null;
  const selectedEdge = selectedEdgeId
    ? (fullGraph.edges.find((e) => e.id === selectedEdgeId) ?? null)
    : null;

  const relatedEdgesForNode = useMemo(() => {
    if (!selectedNode) return [];
    return fullGraph.edges.filter(
      (e) => e.source === selectedNode.id || e.target === selectedNode.id,
    );
  }, [fullGraph.edges, selectedNode]);

  const matchingEvidence = useMemo(() => {
    if (!selectedNode?.evidenceSource) return [];
    return report.evidence.filter((ev) => ev.source === selectedNode.evidenceSource);
  }, [report.evidence, selectedNode]);

  async function handleCopyIndicator(id: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedId(id);
      window.setTimeout(() => setCopiedId((curr) => (curr === id ? null : curr)), 1800);
    } catch {
      // Clipboard unavailable
    }
  }

  return (
    <section
      aria-labelledby="case-graph-heading"
      className="space-y-4 rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-lg sm:p-5"
    >
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border-subtle pb-3.5">
        <div>
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-sky-400" aria-hidden="true" />
            <h3 id="case-graph-heading" className="text-sm font-bold text-ink">
              Sơ đồ mối liên hệ thực thể trong hồ sơ
            </h3>
          </div>
          <p className="mt-1 text-xs leading-relaxed text-ink-muted">
            Trực quan hóa chỉ những thực thể và liên kết có bằng chứng trích xuất từ hồ sơ hiện tại.
            Kéo thả nút, cuộn để thu phóng hoặc nhấp vào nút/cạnh để kiểm tra trạng thái xác minh.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {viewMode === "graph" && (
            <button
              type="button"
              aria-pressed={showMiniMap}
              onClick={() => setShowMiniMap((prev) => !prev)}
              className={`hidden min-h-[34px] cursor-pointer items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[11px] font-medium transition-colors sm:inline-flex ${
                showMiniMap
                  ? "border-sky-400/60 bg-sky-500/15 text-sky-200"
                  : "border-border-strong bg-surface-subtle text-ink-secondary hover:text-ink"
              }`}
            >
              <MapIcon className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Bản đồ thu nhỏ</span>
            </button>
          )}

          <div
            role="group"
            aria-label="Chế độ xem mối liên hệ thực thể"
            className="inline-flex rounded-lg border border-border-strong bg-surface-deep p-0.5 text-[11px]"
          >
            <button
              type="button"
              aria-pressed={viewMode === "graph"}
              onClick={() => setViewMode("graph")}
              className={`inline-flex min-h-[32px] cursor-pointer items-center gap-1.5 rounded-md px-2.5 py-1 font-semibold transition-colors ${
                viewMode === "graph"
                  ? "bg-sky-500/20 text-sky-200"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              <Network className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Sơ đồ</span>
            </button>
            <button
              type="button"
              aria-pressed={viewMode === "list"}
              onClick={() => setViewMode("list")}
              className={`inline-flex min-h-[32px] cursor-pointer items-center gap-1.5 rounded-md px-2.5 py-1 font-semibold transition-colors ${
                viewMode === "list"
                  ? "bg-sky-500/20 text-sky-200"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              <ListTree className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Danh sách</span>
            </button>
          </div>
        </div>
      </div>

      {/* Entity Type Filter Bar + Verification State Legend */}
      <div className="space-y-2.5">
        <div role="group" aria-label="Lọc theo loại thực thể" className="flex flex-wrap gap-1.5 text-[11px]">
          <button
            type="button"
            aria-pressed={kindFilter === "all"}
            onClick={() => setKindFilter("all")}
            className={`tabular-num min-h-[32px] cursor-pointer rounded-lg border px-2.5 py-1 font-semibold transition-colors ${
              kindFilter === "all"
                ? "border-amber-400 bg-amber-500/15 text-amber-200"
                : "border-border-subtle bg-surface-subtle text-ink-secondary hover:border-border-strong"
            }`}
          >
            Tất cả ({fullGraph.nodes.length})
          </button>
          {presentKinds.map(([kind, count]) => {
            const active = kindFilter === kind;
            return (
              <button
                key={kind}
                type="button"
                aria-pressed={active}
                onClick={() => setKindFilter(active ? "all" : kind)}
                className={`tabular-num min-h-[32px] cursor-pointer rounded-lg border px-2.5 py-1 font-medium transition-colors ${
                  active
                    ? "border-sky-400 bg-sky-500/15 text-sky-100"
                    : "border-border-subtle bg-surface-subtle text-ink-secondary hover:border-border-strong"
                }`}
              >
                {ENTITY_KIND_LABELS[kind]} ({count})
              </button>
            );
          })}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-[10.5px]">
          {(
            Object.entries(VERIFICATION_STATE_META) as Array<
              [keyof typeof VERIFICATION_STATE_META, (typeof VERIFICATION_STATE_META)["verified_evidence"]]
            >
          ).map(([stateKey, meta]) => (
            <span
              key={stateKey}
              title={meta.description}
              className={`inline-flex items-center rounded-md border px-2 py-0.5 font-medium ${VERIFICATION_BADGE_STYLE[stateKey]}`}
            >
              {meta.label}
            </span>
          ))}
        </div>
      </div>

      {/* Main Split: Canvas or Mobile List + Entity / Edge Detail Inspector */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="xl:col-span-8">
          {viewMode === "graph" ? (
            <FraudRelationshipFlowCanvas
              graphNodes={filteredGraph.nodes}
              graphEdges={filteredGraph.edges}
              selectedNodeId={selectedNodeId}
              selectedEdgeId={selectedEdgeId}
              showMiniMap={showMiniMap}
              layoutNonce={layoutNonce}
              onSelectNode={setSelectedNodeId}
              onSelectEdge={setSelectedEdgeId}
              onResetLayout={() => setLayoutNonce((n) => n + 1)}
            />
          ) : (
            <div className="space-y-2 rounded-xl border border-border-subtle bg-surface-deep p-3">
              {filteredGraph.nodes.map((node) => {
                const isSelected = selectedNodeId === node.id;
                const verMeta = VERIFICATION_STATE_META[node.verificationState];
                return (
                  <button
                    key={node.id}
                    type="button"
                    aria-pressed={isSelected}
                    onClick={() => {
                      setSelectedEdgeId(null);
                      setSelectedNodeId(isSelected ? null : node.id);
                    }}
                    className={`flex w-full cursor-pointer flex-col gap-1 rounded-xl border p-3 text-left transition-colors ${
                      isSelected
                        ? "border-amber-400 bg-amber-500/10"
                        : "border-border-subtle bg-surface hover:border-border-strong"
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-[10.5px] font-semibold text-ink-muted">
                        {ENTITY_KIND_LABELS[node.kind]}
                      </span>
                      <span
                        className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${
                          VERIFICATION_BADGE_STYLE[node.verificationState]
                        }`}
                      >
                        {verMeta.label}
                      </span>
                    </div>
                    <p className="font-mono text-xs font-bold text-ink">{node.label}</p>
                    <p className="text-[11px] text-ink-muted">{node.subtitle}</p>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Entity & Edge Detail Inspector */}
        <aside
          aria-label="Chi tiết thực thể hoặc liên kết đã chọn"
          className="flex flex-col justify-between gap-3 rounded-xl border border-border-subtle bg-surface-subtle p-4 xl:col-span-4"
        >
          {selectedNode ? (
            <div className="space-y-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-1.5">
                <span className="rounded bg-surface-elevated px-2 py-0.5 text-[10px] font-semibold text-ink-secondary">
                  {ENTITY_KIND_LABELS[selectedNode.kind]}
                </span>
                <span
                  className={`rounded border px-2 py-0.5 text-[10px] font-semibold ${
                    VERIFICATION_BADGE_STYLE[selectedNode.verificationState]
                  }`}
                >
                  {VERIFICATION_STATE_META[selectedNode.verificationState].label}
                </span>
              </div>

              <div>
                <p className="break-all font-mono text-sm font-bold text-ink">
                  {selectedNode.label}
                </p>
                <p className="mt-0.5 text-[11px] text-ink-muted">{selectedNode.subtitle}</p>
              </div>

              <p className="rounded-lg border border-border-subtle bg-surface p-2.5 text-[11px] leading-relaxed text-ink-secondary">
                {selectedNode.detail}
              </p>

              <p className="text-[10.5px] leading-relaxed text-ink-muted">
                {VERIFICATION_STATE_META[selectedNode.verificationState].description}
              </p>

              {selectedNode.copyValue && (
                <button
                  type="button"
                  onClick={() =>
                    void handleCopyIndicator(selectedNode.id, selectedNode.copyValue!)
                  }
                  className="vs-pressable inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-lg border border-border-strong bg-surface px-3 py-1.5 text-[11px] font-semibold text-ink-secondary hover:border-amber-400 hover:text-ink"
                >
                  {copiedId === selectedNode.id ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                      <span className="text-emerald-300">Đã sao chép chỉ báo</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>Sao chép chỉ báo an toàn</span>
                    </>
                  )}
                </button>
              )}

              {relatedEdgesForNode.length > 0 && (
                <div className="space-y-1.5 border-t border-border-subtle/70 pt-2.5">
                  <p className="text-[11px] font-semibold text-ink-secondary">
                    Liên kết trực tiếp ({relatedEdgesForNode.length})
                  </p>
                  <ul className="space-y-1.5">
                    {relatedEdgesForNode.map((edge) => {
                      const otherId =
                        edge.source === selectedNode.id ? edge.target : edge.source;
                      const otherNode = nodeMap.get(otherId);
                      if (!otherNode) return null;
                      return (
                        <li key={edge.id}>
                          <button
                            type="button"
                            onClick={() => {
                              setSelectedEdgeId(null);
                              setSelectedNodeId(otherNode.id);
                            }}
                            className="flex w-full cursor-pointer items-center justify-between gap-2 rounded-lg border border-border-subtle bg-surface px-2.5 py-1.5 text-left text-[11px] transition-colors hover:border-sky-400/65"
                          >
                            <span className="min-w-0 truncate font-mono text-ink">
                              {otherNode.label}
                            </span>
                            <span className="shrink-0 text-[10px] text-amber-300">
                              {edge.label}
                            </span>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}

              {selectedNode.evidenceSource && (
                <div className="space-y-1.5 border-t border-border-subtle/70 pt-2.5">
                  {matchingEvidence.length > 0 && (
                    <p className="text-[11px] text-ink-muted">
                      Gắn với <strong className="text-ink">{matchingEvidence.length}</strong> mục
                      bằng chứng kỹ thuật.
                    </p>
                  )}
                  <button
                    type="button"
                    onClick={() =>
                      onNavigateToEvidence(
                        mapEvidenceSourceToTab(selectedNode.evidenceSource!),
                        selectedNode.evidenceSource,
                      )
                    }
                    className="inline-flex min-h-[34px] w-full cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-amber-500/50 bg-amber-500/15 px-3 py-1.5 text-[11px] font-semibold text-amber-200 transition-colors hover:bg-amber-500/25"
                  >
                    <span>Mở bằng chứng liên quan</span>
                    <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </div>
              )}
            </div>
          ) : selectedEdge ? (
            <div className="space-y-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-1.5">
                <span className="rounded bg-surface-elevated px-2 py-0.5 text-[10px] font-semibold text-ink-secondary">
                  Mối liên hệ (Cạnh)
                </span>
                <span
                  className={`rounded border px-2 py-0.5 text-[10px] font-semibold ${
                    VERIFICATION_BADGE_STYLE[selectedEdge.verificationState]
                  }`}
                >
                  {VERIFICATION_STATE_META[selectedEdge.verificationState].label}
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-border-subtle bg-surface p-2.5 font-mono text-[11px] text-ink">
                <span>{nodeMap.get(selectedEdge.source)?.label ?? selectedEdge.source}</span>
                <ArrowRight className="h-3.5 w-3.5 shrink-0 text-amber-400" aria-hidden="true" />
                <span>{nodeMap.get(selectedEdge.target)?.label ?? selectedEdge.target}</span>
              </div>

              <p className="font-semibold text-amber-200">Quan hệ: {selectedEdge.label}</p>
              <p className="text-[11px] leading-relaxed text-ink-secondary">
                {selectedEdge.detail}
              </p>
            </div>
          ) : (
            <div className="space-y-2.5 text-xs">
              <p className="font-semibold text-ink">Bảng kiểm tra chi tiết</p>
              <p className="text-[11px] leading-relaxed text-ink-muted">
                Nhấp vào bất kỳ thực thể hoặc đường nối nào trên sơ đồ để xem nguồn bằng chứng, mức
                độ xác minh và nhảy nhanh sang mục bằng chứng chi tiết.
              </p>
              <dl className="grid grid-cols-2 gap-2 pt-1 text-[11px]">
                <div className="rounded-lg border border-border-subtle bg-surface p-2.5">
                  <dt className="text-ink-muted">Tổng thực thể</dt>
                  <dd className="tabular-num mt-0.5 font-mono text-base font-bold text-ink">
                    {fullGraph.nodes.length}
                  </dd>
                </div>
                <div className="rounded-lg border border-border-subtle bg-surface p-2.5">
                  <dt className="text-ink-muted">Mối liên hệ</dt>
                  <dd className="tabular-num mt-0.5 font-mono text-base font-bold text-sky-300">
                    {fullGraph.edges.length}
                  </dd>
                </div>
              </dl>
            </div>
          )}

          <div className="flex items-start gap-2 rounded-lg border border-border-subtle bg-surface-deep/80 p-2.5 text-[10.5px] leading-relaxed text-ink-muted">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sky-400" aria-hidden="true" />
            <p>
              Số điện thoại, số tài khoản và email được che giấu tự động. Việc thực thể xuất hiện
              trên sơ đồ không cấu thành kết luận pháp lý về danh tính chủ tài khoản.
            </p>
          </div>
        </aside>
      </div>
    </section>
  );
}
