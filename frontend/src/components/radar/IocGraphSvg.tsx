"use client";

import {
  Ban,
  Maximize2,
  Minimize2,
  Network,
  RotateCcw,
  ShieldAlert,
  Table2,
  X,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import {
  type PointerEvent,
  type WheelEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
  useTransition,
} from "react";

import { RADAR_KIND_COPY, VERDICT_COPY } from "@/lib/copy";
import { computeRadarLayout, formatNodeDisplayLabel } from "@/lib/radarLayout";
import type { RadarEdge, RadarNode } from "@/lib/types";

interface IocGraphSvgProps {
  nodes: RadarNode[];
  edges: RadarEdge[];
  selectedNodeId?: string | null;
  onSelectNode?: (nodeId: string | null) => void;
  onRequestBlockNode?: (node: RadarNode) => void;
}

type NodeKindFilter = "all" | RadarNode["kind"];

const CANVAS_W = 860;
const CANVAS_H = 480;
const MIN_ZOOM = 0.65;
const MAX_ZOOM = 2.4;

const KIND_META: Record<
  RadarNode["kind"],
  {
    fill: string;
    stroke: string;
    textFill: string;
    labelVi: string;
    shortVi: string;
    shapeLabel: string;
  }
> = {
  campaign: {
    fill: "#f59e0b",
    stroke: "#fde68a",
    textFill: "#090e1a",
    labelVi: RADAR_KIND_COPY.campaign.label,
    shortVi: RADAR_KIND_COPY.campaign.shortLabel,
    shapeLabel: RADAR_KIND_COPY.campaign.shapeLabel,
  },
  bank_account: {
    fill: "#0ea5e9",
    stroke: "#bae6fd",
    textFill: "#090e1a",
    labelVi: RADAR_KIND_COPY.bank_account.label,
    shortVi: RADAR_KIND_COPY.bank_account.shortLabel,
    shapeLabel: RADAR_KIND_COPY.bank_account.shapeLabel,
  },
  domain: {
    fill: "#f97316",
    stroke: "#fed7aa",
    textFill: "#090e1a",
    labelVi: RADAR_KIND_COPY.domain.label,
    shortVi: RADAR_KIND_COPY.domain.shortLabel,
    shapeLabel: RADAR_KIND_COPY.domain.shapeLabel,
  },
  phone: {
    fill: "#9333ea",
    stroke: "#e9d5ff",
    textFill: "#ffffff",
    labelVi: RADAR_KIND_COPY.phone.label,
    shortVi: RADAR_KIND_COPY.phone.shortLabel,
    shapeLabel: RADAR_KIND_COPY.phone.shapeLabel,
  },
};

function hexagonPoints(cx: number, cy: number, r: number): string {
  const pts: string[] = [];
  for (let i = 0; i < 6; i += 1) {
    const angle = (Math.PI / 3) * i - Math.PI / 6;
    pts.push(`${(cx + r * Math.cos(angle)).toFixed(1)},${(cy + r * Math.sin(angle)).toFixed(1)}`);
  }
  return pts.join(" ");
}

function diamondPoints(cx: number, cy: number, r: number): string {
  return `${cx},${cy - r} ${cx + r},${cy} ${cx},${cy + r} ${cx - r},${cy}`;
}

function truncateLabel(text: string, maxChars: number): string {
  return text.length > maxChars ? `${text.slice(0, maxChars - 1)}…` : text;
}

export function IocGraphSvg({
  nodes,
  edges,
  selectedNodeId,
  onSelectNode,
  onRequestBlockNode,
}: IocGraphSvgProps) {
  const [internalSelectedId, setInternalSelectedId] = useState<string | null>(null);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [kindFilter, setKindFilter] = useState<NodeKindFilter>("all");
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const dragOriginRef = useRef<{ x: number; y: number; panX: number; panY: number } | null>(null);
  const [, startTransition] = useTransition();

  const activeSelectedId = selectedNodeId !== undefined ? selectedNodeId : internalSelectedId;

  function selectNode(nextId: string | null) {
    setInternalSelectedId(nextId);
    onSelectNode?.(nextId);
  }

  useEffect(() => {
    function handleKey(ev: KeyboardEvent) {
      if (ev.key === "Escape") {
        if (isFullscreen) {
          setIsFullscreen(false);
        } else if (activeSelectedId) {
          selectNode(null);
        }
      }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isFullscreen, activeSelectedId]);

  const positioned = useMemo(
    () => computeRadarLayout(nodes, CANVAS_W, CANVAS_H, edges),
    [nodes, edges],
  );
  const nodeMap = useMemo(() => new Map(positioned.map((n) => [n.node_id, n])), [positioned]);

  const neighborIdsByNode = useMemo(() => {
    const adj = new Map<string, Set<string>>();
    for (const edge of edges) {
      const sSet = adj.get(edge.source) ?? new Set<string>();
      sSet.add(edge.target);
      adj.set(edge.source, sSet);
      const tSet = adj.get(edge.target) ?? new Set<string>();
      tSet.add(edge.source);
      adj.set(edge.target, tSet);
    }
    return adj;
  }, [edges]);

  const matchingFilterIds = useMemo(() => {
    if (kindFilter === "all") {
      return new Set(positioned.map((n) => n.node_id));
    }
    const direct = new Set(positioned.filter((n) => n.kind === kindFilter).map((n) => n.node_id));
    const withNeighbors = new Set(direct);
    for (const id of direct) {
      const neighbors = neighborIdsByNode.get(id);
      if (neighbors) {
        for (const nb of neighbors) withNeighbors.add(nb);
      }
    }
    return withNeighbors;
  }, [positioned, kindFilter, neighborIdsByNode]);

  const selectedNode = activeSelectedId ? (nodeMap.get(activeSelectedId) ?? null) : null;
  const hoveredNode = hoveredId ? (nodeMap.get(hoveredId) ?? null) : null;
  const tooltipNode = hoveredNode ?? selectedNode;

  const focusedIds = useMemo(() => {
    if (!selectedNode) return null;
    const set = new Set<string>([selectedNode.node_id]);
    const neighbors = neighborIdsByNode.get(selectedNode.node_id);
    if (neighbors) {
      for (const nb of neighbors) set.add(nb);
    }
    return set;
  }, [selectedNode, neighborIdsByNode]);

  const filteredTableNodes = useMemo(
    () => (kindFilter === "all" ? positioned : positioned.filter((n) => n.kind === kindFilter)),
    [positioned, kindFilter],
  );

  function handleSelectFilter(next: NodeKindFilter) {
    startTransition(() => {
      setKindFilter(next);
    });
  }

  function adjustZoom(delta: number) {
    setZoom((prev) => Number(Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, prev + delta)).toFixed(2)));
  }

  function resetViewport() {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }

  function handleWheel(ev: WheelEvent<SVGSVGElement>) {
    if (!ev.ctrlKey && !ev.metaKey && Math.abs(ev.deltaY) < 4) return;
    ev.preventDefault();
    const step = ev.deltaY > 0 ? -0.15 : 0.15;
    adjustZoom(step);
  }

  function handlePointerDown(ev: PointerEvent<SVGSVGElement>) {
    if ((ev.target as Element).closest("[data-radar-node='true']")) return;
    setIsDragging(true);
    dragOriginRef.current = { x: ev.clientX, y: ev.clientY, panX: pan.x, panY: pan.y };
    ev.currentTarget.setPointerCapture(ev.pointerId);
  }

  function handlePointerMove(ev: PointerEvent<SVGSVGElement>) {
    if (!isDragging || !dragOriginRef.current) return;
    const dx = (ev.clientX - dragOriginRef.current.x) / zoom;
    const dy = (ev.clientY - dragOriginRef.current.y) / zoom;
    setPan({ x: dragOriginRef.current.panX + dx, y: dragOriginRef.current.panY + dy });
  }

  function handlePointerUp(ev: PointerEvent<SVGSVGElement>) {
    if (!isDragging) return;
    const origin = dragOriginRef.current;
    setIsDragging(false);
    dragOriginRef.current = null;
    try {
      ev.currentTarget.releasePointerCapture(ev.pointerId);
    } catch {
      // Ignore if capture already released
    }
    if (origin && Math.hypot(ev.clientX - origin.x, ev.clientY - origin.y) < 4) {
      selectNode(null);
    }
  }

  const selectedNeighbors = useMemo(() => {
    if (!selectedNode) return [];
    return Array.from(neighborIdsByNode.get(selectedNode.node_id) ?? [])
      .map((id) => nodeMap.get(id))
      .filter((n): n is NonNullable<typeof n> => Boolean(n));
  }, [selectedNode, neighborIdsByNode, nodeMap]);

  const clusterAnchors = useMemo(
    () => positioned.filter((n) => n.kind === "campaign"),
    [positioned],
  );

  const transformAttr = `translate(${(CANVAS_W / 2 + pan.x * zoom).toFixed(1)}, ${(
    CANVAS_H / 2 +
    pan.y * zoom
  ).toFixed(1)}) scale(${zoom.toFixed(2)}) translate(${(-CANVAS_W / 2).toFixed(1)}, ${(
    -CANVAS_H / 2
  ).toFixed(1)})`;

  const containerClass = isFullscreen
    ? "fixed inset-3 z-50 flex flex-col overflow-hidden rounded-2xl border border-border-strong bg-surface p-4 shadow-2xl sm:inset-6 sm:p-5"
    : "rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-lg sm:p-5";

  return (
    <>
      {isFullscreen && (
        <div
          aria-hidden="true"
          onClick={() => setIsFullscreen(false)}
          className="fixed inset-0 z-40 bg-slate-950/80 backdrop-blur-xs"
        />
      )}

      <section aria-labelledby="ioc-graph-heading" className={containerClass}>
        <div className="mb-3 flex flex-wrap items-start justify-between gap-2.5">
          <div className="flex items-start gap-2">
            <Network className="mt-0.5 h-5 w-5 shrink-0 text-sky-400" aria-hidden="true" />
            <div>
              <h2 id="ioc-graph-heading" className="text-sm font-bold text-ink">
                Mạng lưới liên kết
              </h2>
              <p className="text-xs text-ink-muted">
                Các dấu hiệu nghi vấn được gom theo cụm chiến dịch. Nhấp vào từng nút để xem chi tiết
                liên kết.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {viewMode === "graph" && (
              <div
                role="group"
                aria-label="Điều khiển khung nhìn sơ đồ"
                className="inline-flex items-center rounded-lg border border-border-strong bg-surface-deep p-0.5 text-[11px]"
              >
                <button
                  type="button"
                  onClick={() => adjustZoom(-0.2)}
                  aria-label="Thu nhỏ sơ đồ"
                  title="Thu nhỏ"
                  className="inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-md text-ink-secondary hover:bg-surface-subtle hover:text-ink"
                >
                  <ZoomOut className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
                <span className="tabular-num min-w-[44px] text-center font-mono text-[11px] text-ink-secondary">
                  {Math.round(zoom * 100)}%
                </span>
                <button
                  type="button"
                  onClick={() => adjustZoom(0.2)}
                  aria-label="Phóng to sơ đồ"
                  title="Phóng to"
                  className="inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-md text-ink-secondary hover:bg-surface-subtle hover:text-ink"
                >
                  <ZoomIn className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
                <button
                  type="button"
                  onClick={resetViewport}
                  aria-label="Đưa sơ đồ vừa khung nhìn"
                  title="Vừa khung"
                  className="inline-flex h-8 cursor-pointer items-center gap-1 rounded-md px-2 text-ink-secondary hover:bg-surface-subtle hover:text-ink"
                >
                  <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                  <span className="hidden sm:inline">Vừa khung</span>
                </button>
                <button
                  type="button"
                  onClick={() => setIsFullscreen((prev) => !prev)}
                  aria-label={isFullscreen ? "Thoát toàn màn hình" : "Mở toàn màn hình"}
                  title={isFullscreen ? "Thu nhỏ" : "Toàn màn hình"}
                  className="inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-md text-ink-secondary hover:bg-surface-subtle hover:text-ink"
                >
                  {isFullscreen ? (
                    <Minimize2 className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <Maximize2 className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                </button>
              </div>
            )}

            <div
              role="group"
              aria-label="Chế độ hiển thị mạng lưới liên kết"
              className="inline-flex shrink-0 rounded-lg border border-border-strong bg-surface-deep p-0.5 text-[11px]"
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
                aria-pressed={viewMode === "table"}
                onClick={() => setViewMode("table")}
                className={`inline-flex min-h-[32px] cursor-pointer items-center gap-1.5 rounded-md px-2.5 py-1 font-semibold transition-colors ${
                  viewMode === "table"
                    ? "bg-sky-500/20 text-sky-200"
                    : "text-ink-muted hover:text-ink"
                }`}
              >
                <Table2 className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Bảng dữ liệu</span>
              </button>
            </div>
          </div>
        </div>

        {/* Entity kind filters + active focus chip */}
        <div
          role="group"
          aria-label="Lọc theo loại đối tượng"
          className="mb-3 flex flex-wrap items-center justify-between gap-2 text-[11px]"
        >
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              aria-pressed={kindFilter === "all"}
              onClick={() => handleSelectFilter("all")}
              className={`tabular-num min-h-[32px] cursor-pointer rounded-lg border px-2.5 py-1 font-semibold transition-colors ${
                kindFilter === "all"
                  ? "border-sky-400 bg-sky-500/20 text-sky-100"
                  : "border-border-subtle bg-surface-subtle text-ink-secondary hover:border-border-strong"
              }`}
            >
              Tất cả ({positioned.length})
            </button>

            {(
              Object.entries(KIND_META) as Array<
                [RadarNode["kind"], (typeof KIND_META)[RadarNode["kind"]]]
              >
            ).map(([kind, cfg]) => {
              const count = positioned.filter((n) => n.kind === kind).length;
              const active = kindFilter === kind;
              return (
                <button
                  key={kind}
                  type="button"
                  aria-pressed={active}
                  onClick={() => handleSelectFilter(active ? "all" : kind)}
                  className={`tabular-num inline-flex min-h-[32px] cursor-pointer items-center gap-1.5 rounded-lg border px-2.5 py-1 font-medium transition-colors ${
                    active
                      ? "border-amber-400 bg-amber-500/15 text-ink"
                      : "border-border-subtle bg-surface-subtle text-ink-secondary hover:border-border-strong"
                  }`}
                >
                  <span
                    aria-hidden="true"
                    className={`inline-block h-2.5 w-2.5 shrink-0 ${
                      kind === "bank_account"
                        ? "rounded-full"
                        : kind === "domain"
                          ? "rotate-45 rounded-[1px]"
                          : kind === "phone"
                            ? "rounded-[2px]"
                            : "rounded-sm"
                    }`}
                    style={{ backgroundColor: cfg.fill }}
                  />
                  <span>
                    {cfg.shortVi} ({count})
                  </span>
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-2 text-[11px] text-ink-muted">
            <span className="inline-flex items-center gap-1">
              <span
                aria-hidden="true"
                className="inline-block h-2.5 w-2.5 rounded-full border border-dashed border-rose-400 bg-rose-700"
              />
              <span>Đang áp dụng chặn</span>
            </span>
            {selectedNode && (
              <button
                type="button"
                onClick={() => selectNode(null)}
                className="inline-flex min-h-[28px] cursor-pointer items-center gap-1 rounded-md border border-border-strong bg-surface-subtle px-2 py-0.5 text-[11px] font-medium text-ink-secondary hover:text-ink"
              >
                <X className="h-3 w-3" aria-hidden="true" />
                <span>Bỏ chọn</span>
              </button>
            )}
          </div>
        </div>

        {viewMode === "graph" ? (
          <div
            className={`relative overflow-hidden rounded-xl border border-border-subtle bg-surface-deep ${
              isFullscreen ? "min-h-0 flex-1 flex flex-col" : ""
            }`}
          >
            {/* Non-overlapping metric tooltip bar above canvas */}
            <div
              role="status"
              aria-live="polite"
              className="flex min-h-[34px] flex-wrap items-center justify-between gap-2 border-b border-border-subtle/70 bg-surface-subtle/70 px-3 py-1.5 text-[11px]"
            >
              {tooltipNode ? (
                <div className="flex flex-wrap items-center gap-1.5">
                  <strong className="font-mono text-ink">
                    {formatNodeDisplayLabel(tooltipNode)}
                  </strong>
                  <span className="text-ink-muted">·</span>
                  <span className="tabular-num text-ink-secondary">
                    {tooltipNode.kind === "campaign"
                      ? `Số trong nút (${tooltipNode.hit_count}): hồ sơ thuộc chiến dịch`
                      : `Số trong nút (${tooltipNode.hit_count}): lượt ghi nhận dấu hiệu`}
                  </span>
                  {tooltipNode.blocked && (
                    <span className="rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-bold text-rose-200">
                      Đang bị chặn
                    </span>
                  )}
                </div>
              ) : (
                <span className="text-ink-muted">
                  Di chuột hoặc chọn một nút để xem ý nghĩa số liệu và liên kết trực tiếp.
                </span>
              )}
              <span className="hidden text-[10px] text-ink-muted sm:inline">
                Kéo nền để di chuyển · Cuộn chuột để thu phóng
              </span>
            </div>

            {positioned.length === 0 ? (
              <div className="flex h-64 items-center justify-center p-6 text-center text-xs text-ink-muted">
                Chưa có chiến dịch hoặc dấu hiệu nghi vấn nào được ghi nhận.
              </div>
            ) : (
              <svg
                viewBox={`0 0 ${CANVAS_W} ${CANVAS_H}`}
                role="group"
                aria-label="Sơ đồ mạng lưới liên kết chiến dịch và dấu hiệu nghi vấn"
                onWheel={handleWheel}
                onPointerDown={handlePointerDown}
                onPointerMove={handlePointerMove}
                onPointerUp={handlePointerUp}
                onPointerLeave={handlePointerUp}
                className={`w-full select-none ${
                  isFullscreen ? "h-full" : "h-auto max-h-[460px]"
                } ${isDragging ? "cursor-grabbing" : "cursor-grab"}`}
              >
                <title>Mạng lưới liên kết chiến dịch và dấu hiệu nghi vấn</title>
                <defs>
                  <pattern
                    id="radar-dot-grid"
                    width="24"
                    height="24"
                    patternUnits="userSpaceOnUse"
                  >
                    <circle cx="1.5" cy="1.5" r="1" fill="#1e293b" opacity="0.7" />
                  </pattern>
                </defs>
                <rect width={CANVAS_W} height={CANVAS_H} fill="url(#radar-dot-grid)" />

                <g transform={transformAttr}>
                  {/* Subtle cluster halos around each campaign hub */}
                  {clusterAnchors.map((hub) => {
                    const dimmed =
                      !matchingFilterIds.has(hub.node_id) ||
                      (focusedIds !== null && !focusedIds.has(hub.node_id));
                    return (
                      <circle
                        key={`halo-${hub.node_id}`}
                        cx={hub.x}
                        cy={hub.y}
                        r={126}
                        fill={hub.blocked ? "#991b1b" : "#0ea5e9"}
                        fillOpacity={dimmed ? 0.015 : 0.045}
                        stroke={hub.blocked ? "#ef4444" : "#334155"}
                        strokeOpacity={dimmed ? 0.08 : 0.28}
                        strokeDasharray="4 6"
                      />
                    );
                  })}

                  {/* Edges */}
                  {edges.map((edge, idx) => {
                    const src = nodeMap.get(edge.source);
                    const dst = nodeMap.get(edge.target);
                    if (!src || !dst) return null;
                    const passesFilter =
                      matchingFilterIds.has(src.node_id) && matchingFilterIds.has(dst.node_id);
                    const isDirectEdge =
                      selectedNode !== null &&
                      (selectedNode.node_id === edge.source || selectedNode.node_id === edge.target);
                    const dimmedByFocus = focusedIds !== null && !isDirectEdge;
                    const isBlockedEdge = src.blocked || dst.blocked;

                    return (
                      <line
                        key={`${edge.source}-${edge.target}-${idx}`}
                        x1={src.x}
                        y1={src.y}
                        x2={dst.x}
                        y2={dst.y}
                        stroke={
                          isDirectEdge
                            ? isBlockedEdge
                              ? "#f87171"
                              : "#38bdf8"
                            : isBlockedEdge
                              ? "#ef4444"
                              : "#475569"
                        }
                        strokeWidth={isDirectEdge ? 2.6 : 1.4}
                        strokeOpacity={!passesFilter || dimmedByFocus ? 0.14 : 0.85}
                        strokeDasharray={isBlockedEdge ? "5 4" : undefined}
                      />
                    );
                  })}

                  {/* Nodes */}
                  {positioned.map((node) => {
                    const style = KIND_META[node.kind];
                    const isCampaign = node.kind === "campaign";
                    const radius = isCampaign ? 22 : 16;
                    const isActive = selectedNode?.node_id === node.node_id;
                    const isRelated = focusedIds === null || focusedIds.has(node.node_id);
                    const isDimmed = !matchingFilterIds.has(node.node_id) || !isRelated;
                    const displayLabel = formatNodeDisplayLabel(node);
                    const shortLabel = truncateLabel(displayLabel, isCampaign ? 24 : 18);
                    const pillWidth = Math.min(170, Math.max(66, shortLabel.length * 6.4 + 14));
                    const nodeFill = node.blocked ? "#991b1b" : style.fill;
                    const countFill = node.blocked ? "#ffffff" : style.textFill;
                    const nodeStroke = isActive
                      ? "#ffffff"
                      : node.blocked
                        ? "#fca5a5"
                        : style.stroke;
                    const strokeWidth = isActive ? 3 : 1.7;

                    return (
                      <g
                        key={node.node_id}
                        data-radar-node="true"
                        role="button"
                        tabIndex={0}
                        aria-pressed={isActive}
                        aria-label={`${style.labelVi} (${style.shapeLabel}): ${displayLabel} (${
                          node.hit_count
                        } ${isCampaign ? "hồ sơ" : "lượt ghi nhận"}${
                          node.blocked ? ", đang bị chặn" : ""
                        })`}
                        onClick={(ev) => {
                          ev.stopPropagation();
                          selectNode(isActive ? null : node.node_id);
                        }}
                        onMouseEnter={() => setHoveredId(node.node_id)}
                        onMouseLeave={() => setHoveredId((prev) => (prev === node.node_id ? null : prev))}
                        onFocus={() => setHoveredId(node.node_id)}
                        onBlur={() => setHoveredId((prev) => (prev === node.node_id ? null : prev))}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            selectNode(isActive ? null : node.node_id);
                          }
                        }}
                        opacity={isDimmed ? 0.18 : 1}
                        className="cursor-pointer transition-opacity duration-150 focus:outline-none"
                      >
                        {node.blocked && (
                          <circle
                            cx={node.x}
                            cy={node.y}
                            r={radius + 7}
                            fill="none"
                            stroke="#ef4444"
                            strokeWidth={2.2}
                            strokeDasharray="4 3"
                          />
                        )}

                        {node.kind === "campaign" ? (
                          <polygon
                            points={hexagonPoints(node.x, node.y, radius)}
                            fill={nodeFill}
                            stroke={nodeStroke}
                            strokeWidth={strokeWidth}
                          />
                        ) : node.kind === "domain" ? (
                          <polygon
                            points={diamondPoints(node.x, node.y, radius + 2)}
                            fill={nodeFill}
                            stroke={nodeStroke}
                            strokeWidth={strokeWidth}
                          />
                        ) : node.kind === "phone" ? (
                          <rect
                            x={node.x - 15}
                            y={node.y - 15}
                            width={30}
                            height={30}
                            rx={6}
                            fill={nodeFill}
                            stroke={nodeStroke}
                            strokeWidth={strokeWidth}
                          />
                        ) : (
                          <circle
                            cx={node.x}
                            cy={node.y}
                            r={radius}
                            fill={nodeFill}
                            stroke={nodeStroke}
                            strokeWidth={strokeWidth}
                          />
                        )}

                        <text
                          x={node.x}
                          y={node.y + 4}
                          textAnchor="middle"
                          fill={countFill}
                          fontSize="11"
                          fontWeight="700"
                        >
                          {node.hit_count}
                        </text>

                        {node.blocked && (
                          <g transform={`translate(${node.x + radius - 2}, ${node.y - radius - 4})`}>
                            <rect
                              x={-2}
                              y={-8}
                              width={36}
                              height={14}
                              rx={4}
                              fill="#7f1d1d"
                              stroke="#f87171"
                              strokeWidth={0.9}
                            />
                            <text
                              x={16}
                              y={2}
                              textAnchor="middle"
                              fill="#fee2e2"
                              fontSize="8.5"
                              fontWeight="700"
                            >
                              CHẶN
                            </text>
                          </g>
                        )}

                        {/* Pill-backed label for zero edge clash and crisp readability */}
                        <rect
                          x={node.x - pillWidth / 2}
                          y={node.y + radius + 5}
                          width={pillWidth}
                          height={19}
                          rx={5}
                          fill="#090e1a"
                          fillOpacity={0.86}
                          stroke={isActive ? "#38bdf8" : node.blocked ? "#991b1b" : "#1e293b"}
                          strokeWidth={isActive ? 1.2 : 0.8}
                        />
                        <text
                          x={node.x}
                          y={node.y + radius + 17.5}
                          textAnchor="middle"
                          fill={node.blocked ? "#fecaca" : "#e2e8f0"}
                          fontSize="10.5"
                          fontWeight={isActive ? "700" : "500"}
                        >
                          {shortLabel}
                        </text>
                      </g>
                    );
                  })}
                </g>
              </svg>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-border-subtle bg-surface-deep">
            <table className="w-full min-w-[540px] border-collapse text-left text-xs">
              <caption className="sr-only">
                Bảng dữ liệu chiến dịch và dấu hiệu nghi vấn đã che giấu thông tin cá nhân
              </caption>
              <thead>
                <tr className="border-b border-border-subtle bg-surface-subtle text-[11px] font-semibold text-ink-secondary">
                  <th scope="col" className="px-3 py-2.5">
                    Đối tượng
                  </th>
                  <th scope="col" className="px-3 py-2.5">
                    Phân loại
                  </th>
                  <th scope="col" className="px-3 py-2.5 text-right">
                    Số lượt / hồ sơ
                  </th>
                  <th scope="col" className="px-3 py-2.5">
                    Liên kết trực tiếp
                  </th>
                  <th scope="col" className="px-3 py-2.5">
                    Trạng thái
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/60">
                {filteredTableNodes.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-3 py-6 text-center text-ink-muted">
                      Không có đối tượng nào khớp với bộ lọc hiện tại.
                    </td>
                  </tr>
                ) : (
                  filteredTableNodes.map((node) => {
                    const cfg = KIND_META[node.kind];
                    const neighbors = Array.from(neighborIdsByNode.get(node.node_id) ?? [])
                      .map((id) => nodeMap.get(id))
                      .filter((nb): nb is NonNullable<typeof nb> => Boolean(nb))
                      .map((nb) => formatNodeDisplayLabel(nb));
                    const isActive = selectedNode?.node_id === node.node_id;

                    return (
                      <tr
                        key={node.node_id}
                        onClick={() => selectNode(node.node_id)}
                        className={`cursor-pointer transition-colors ${
                          isActive ? "bg-sky-500/12" : "hover:bg-surface-subtle/70"
                        }`}
                      >
                        <td className="tabular-num px-3 py-2.5 font-mono font-semibold text-ink">
                          {formatNodeDisplayLabel(node)}
                        </td>
                        <td className="px-3 py-2.5 text-ink-secondary">
                          <span className="inline-flex items-center gap-1.5">
                            <span
                              className="inline-block h-2 w-2 rounded-full"
                              style={{ backgroundColor: cfg.fill }}
                              aria-hidden="true"
                            />
                            <span>{cfg.shortVi}</span>
                          </span>
                        </td>
                        <td className="tabular-num px-3 py-2.5 text-right font-mono text-ink">
                          {node.hit_count}
                        </td>
                        <td className="px-3 py-2.5 text-[11px] text-ink-muted">
                          {neighbors.length > 0 ? neighbors.slice(0, 3).join(", ") : "Đơn lẻ"}
                          {neighbors.length > 3 ? ` (+${neighbors.length - 3})` : ""}
                        </td>
                        <td className="px-3 py-2.5">
                          <span
                            className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                              node.blocked
                                ? "bg-rose-500/20 text-rose-200"
                                : "bg-amber-500/15 text-amber-200"
                            }`}
                          >
                            {node.blocked ? "Đang chặn" : VERDICT_COPY[node.risk_level].shortLabel}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Selected Node Detail Inspector */}
        <div className="mt-3 rounded-xl border border-border-subtle bg-surface-subtle px-3.5 py-3 text-xs">
          {selectedNode ? (
            <div className="space-y-2">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-surface-elevated px-2 py-0.5 text-[10px] font-semibold text-ink-secondary">
                      {KIND_META[selectedNode.kind].labelVi}
                    </span>
                    {selectedNode.is_demo && (
                      <span className="rounded border border-sky-500/35 bg-sky-500/10 px-1.5 py-0.5 text-[10px] font-medium text-sky-300">
                        Dữ liệu mẫu
                      </span>
                    )}
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                        selectedNode.blocked
                          ? "bg-rose-500/20 text-rose-200"
                          : "bg-amber-500/15 text-amber-200"
                      }`}
                    >
                      {selectedNode.blocked
                        ? "Đang áp dụng quy tắc chặn"
                        : VERDICT_COPY[selectedNode.risk_level].shortLabel}
                    </span>
                  </div>

                  <p className="mt-1 font-mono text-sm font-bold text-ink">
                    {formatNodeDisplayLabel(selectedNode)}
                  </p>
                  <p className="tabular-num mt-0.5 text-[11px] text-ink-muted">
                    {selectedNode.kind === "campaign"
                      ? `${selectedNode.hit_count} hồ sơ liên quan · ${selectedNeighbors.length} dấu hiệu gắn kết`
                      : `${selectedNode.hit_count} lượt ghi nhận · ${selectedNeighbors.length} liên kết trực tiếp`}
                  </p>
                </div>

                {selectedNode.kind !== "campaign" && !selectedNode.blocked && onRequestBlockNode && (
                  <button
                    type="button"
                    onClick={() => onRequestBlockNode(selectedNode)}
                    className="inline-flex min-h-[34px] shrink-0 cursor-pointer items-center gap-1.5 rounded-lg border border-rose-500/45 bg-rose-500/15 px-3 py-1.5 text-[11px] font-semibold text-rose-200 transition-colors hover:bg-rose-500/25"
                  >
                    <Ban className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Áp dụng quy tắc chặn</span>
                  </button>
                )}
              </div>

              {selectedNeighbors.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 border-t border-border-subtle/70 pt-2">
                  <span className="text-[11px] text-ink-muted">Liên kết trực tiếp:</span>
                  {selectedNeighbors.map((nb) => (
                    <button
                      key={nb.node_id}
                      type="button"
                      onClick={() => selectNode(nb.node_id)}
                      className={`inline-flex cursor-pointer items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] transition-colors ${
                        nb.blocked
                          ? "border-rose-500/45 bg-rose-500/12 text-rose-200 hover:bg-rose-500/20"
                          : "border-border-strong bg-surface text-ink-secondary hover:border-sky-400 hover:text-ink"
                      }`}
                    >
                      {nb.blocked && <ShieldAlert className="h-3 w-3 text-rose-400" aria-hidden="true" />}
                      <span className="font-mono">{formatNodeDisplayLabel(nb)}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <p className="text-[11px] text-ink-muted">
              Chọn một nút trên sơ đồ hoặc một hàng trong bảng để xem tên đầy đủ, số lượt ghi nhận và
              các thực thể liên quan.
            </p>
          )}
        </div>
      </section>
    </>
  );
}
