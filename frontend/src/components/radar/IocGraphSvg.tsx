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
  forwardRef,
  memo,
  type FocusEvent,
  type PointerEvent,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  useTransition,
} from "react";

import { RADAR_KIND_COPY, VERDICT_COPY } from "@/lib/copy";
import {
  buildGraphTopologyKey,
  clampFloatingTooltip,
  computeFitViewport,
  computeOptimalGraphExtent,
  computeRadarLayout,
  formatNodeDisplayLabel,
  type GraphViewport,
  type PositionedRadarNode,
  zoomViewportAroundPoint,
} from "@/lib/radarLayout";
import type { RadarEdge, RadarNode } from "@/lib/types";

interface IocGraphSvgProps {
  nodes: RadarNode[];
  edges: RadarEdge[];
  selectedNodeId?: string | null;
  onSelectNode?: (nodeId: string | null) => void;
  onRequestBlockNode?: (node: RadarNode) => void;
}

type NodeKindFilter = "all" | RadarNode["kind"];

const VIEW_W = 860;
const VIEW_H = 480;
const MIN_ZOOM = 0.2;
const MAX_ZOOM = 2.8;
const BUTTON_ZOOM_DURATION_MS = 180;
const FIT_ANIMATION_DURATION_MS = 220;
const TOOLTIP_EST_W = 264;
const TOOLTIP_EST_H = 74;

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

const KIND_ENTRIES = Object.entries(KIND_META) as Array<
  [RadarNode["kind"], (typeof KIND_META)[RadarNode["kind"]]]
>;

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

function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function easeOutCubic(t: number): number {
  return 1 - (1 - t) ** 3;
}

function formatMatrix(vp: GraphViewport): string {
  return `matrix(${vp.scale.toFixed(4)} 0 0 ${vp.scale.toFixed(4)} ${vp.x.toFixed(2)} ${vp.y.toFixed(2)})`;
}

/**
 * Compute uniform `preserveAspectRatio="xMidYMid meet"` mapping between CSS client pixels
 * and SVG viewBox coordinates so drag tracking is strictly 1:1 at every viewport & DPR.
 */
function getSvgViewportMetrics(rect: DOMRect) {
  const scaleToCss = Math.min(rect.width / VIEW_W, rect.height / VIEW_H) || 1;
  const renderedW = VIEW_W * scaleToCss;
  const renderedH = VIEW_H * scaleToCss;
  const offsetX = (rect.width - renderedW) / 2;
  const offsetY = (rect.height - renderedH) / 2;
  return { scaleToCss, offsetX, offsetY };
}

interface FloatingTooltipState {
  node: PositionedRadarNode;
  left: number;
  top: number;
}

interface FloatingTooltipHandle {
  show: (next: FloatingTooltipState) => void;
  hide: () => void;
}

/**
 * Isolated floating tooltip overlay (pointer-events-none, position: absolute).
 * Holds its own local state via imperative handle so hovering nodes triggers ZERO
 * React re-renders on IocGraphSvg or the SVG scene layer and ZERO layout shift.
 */
const FloatingNodeTooltip = memo(
  forwardRef<FloatingTooltipHandle>(function FloatingNodeTooltip(_props, ref) {
    const [tooltip, setTooltip] = useState<FloatingTooltipState | null>(null);

    useImperativeHandle(
      ref,
      () => ({
        show(next: FloatingTooltipState) {
          setTooltip((prev) => {
            if (
              prev &&
              prev.node.node_id === next.node.node_id &&
              prev.left === next.left &&
              prev.top === next.top
            ) {
              return prev;
            }
            return next;
          });
        },
        hide() {
          setTooltip((prev) => (prev ? null : prev));
        },
      }),
      [],
    );

    if (!tooltip) return null;
    const { node, left, top } = tooltip;
    const isCampaign = node.kind === "campaign";
    const meta = KIND_META[node.kind];

    return (
      <div
        role="tooltip"
        aria-live="off"
        style={{
          transform: `translate3d(${left}px, ${top}px, 0)`,
          maxWidth: `${TOOLTIP_EST_W}px`,
          contain: "layout style",
        }}
        className="pointer-events-none absolute top-0 left-0 z-20 rounded-lg border border-border-strong/90 bg-slate-950/95 px-2.5 py-2 text-[11px] shadow-xl will-change-transform"
      >
        <div className="flex items-center gap-1.5">
          <span
            aria-hidden="true"
            className="inline-block h-2 w-2 shrink-0 rounded-full"
            style={{ backgroundColor: node.blocked ? "#ef4444" : meta.fill }}
          />
          <span className="truncate font-mono font-semibold text-ink">
            {formatNodeDisplayLabel(node)}
          </span>
        </div>
        <p className="tabular-num mt-1 text-[10.5px] leading-snug text-ink-secondary">
          {isCampaign
            ? `Số trong nút (${node.hit_count}): hồ sơ thuộc chiến dịch`
            : `Số trong nút (${node.hit_count}): lượt ghi nhận dấu hiệu`}
        </p>
        {node.blocked && (
          <span className="mt-1 inline-block rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-bold text-rose-200">
            Đang áp dụng chặn
          </span>
        )}
      </div>
    );
  }),
);

interface GraphSceneLayerProps {
  positioned: PositionedRadarNode[];
  edges: RadarEdge[];
  nodeMap: Map<string, PositionedRadarNode>;
  matchingFilterIds: Set<string>;
  focusedIds: Set<string> | null;
  selectedNodeId: string | null;
  onToggleSelect: (nodeId: string) => void;
}

/**
 * Memoized static SVG scene layer (halos, edges, nodes, labels).
 * Completely insulated from pan, zoom, and hover tooltip updates!
 */
const GraphSceneLayer = memo(function GraphSceneLayer({
  positioned,
  edges,
  nodeMap,
  matchingFilterIds,
  focusedIds,
  selectedNodeId,
  onToggleSelect,
}: GraphSceneLayerProps) {
  const isDense = positioned.length > 80;

  // Render campaign hubs AFTER IOCs so hubs stay cleanly clickable on dense graphs
  const orderedNodes = useMemo(() => {
    const iocs: PositionedRadarNode[] = [];
    const hubs: PositionedRadarNode[] = [];
    for (const n of positioned) {
      if (n.kind === "campaign") hubs.push(n);
      else iocs.push(n);
    }
    return [...iocs, ...hubs];
  }, [positioned]);

  const clusterAnchors = useMemo(
    () => positioned.filter((n) => n.kind === "campaign"),
    [positioned],
  );

  return (
    <>
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
            r={isDense ? 156 : 126}
            fill={hub.blocked ? "#991b1b" : "#0ea5e9"}
            fillOpacity={dimmed ? 0.015 : 0.045}
            stroke={hub.blocked ? "#ef4444" : "#334155"}
            strokeOpacity={dimmed ? 0.08 : 0.26}
            strokeDasharray="4 6"
            className="pointer-events-none"
          />
        );
      })}

      {/* Edges */}
      {edges.map((edge) => {
        const src = nodeMap.get(edge.source);
        const dst = nodeMap.get(edge.target);
        if (!src || !dst) return null;
        const passesFilter =
          matchingFilterIds.has(src.node_id) && matchingFilterIds.has(dst.node_id);
        const isDirectEdge =
          selectedNodeId !== null &&
          (selectedNodeId === edge.source || selectedNodeId === edge.target);
        const dimmedByFocus = focusedIds !== null && !isDirectEdge;
        const isBlockedEdge = src.blocked || dst.blocked;

        return (
          <line
            key={`${edge.source}__${edge.target}__${edge.relation}`}
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
            strokeWidth={isDirectEdge ? 2.6 : isDense ? 1.1 : 1.4}
            strokeOpacity={!passesFilter || dimmedByFocus ? 0.12 : isDense ? 0.65 : 0.85}
            strokeDasharray={isBlockedEdge ? "5 4" : undefined}
            className="radar-edge pointer-events-none"
          />
        );
      })}

      {/* Nodes */}
      {orderedNodes.map((node) => {
        const style = KIND_META[node.kind];
        const isCampaign = node.kind === "campaign";
        const radius = isCampaign ? 22 : 16;
        const isActive = selectedNodeId === node.node_id;
        const isRelated = focusedIds === null || focusedIds.has(node.node_id);
        const isDimmed = !matchingFilterIds.has(node.node_id) || !isRelated;
        const displayLabel = formatNodeDisplayLabel(node);
        const shortLabel = truncateLabel(displayLabel, isCampaign ? 24 : 18);
        const showPillBg = !isDense || isCampaign || isActive || node.blocked;
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
            data-node-id={node.node_id}
            role="button"
            tabIndex={0}
            aria-pressed={isActive}
            aria-label={`${style.labelVi} (${style.shapeLabel}): ${displayLabel} (${
              node.hit_count
            } ${isCampaign ? "hồ sơ" : "lượt ghi nhận"}${node.blocked ? ", đang bị chặn" : ""})`}
            onClick={(ev) => {
              ev.stopPropagation();
              onToggleSelect(node.node_id);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onToggleSelect(node.node_id);
              }
            }}
            opacity={isDimmed ? 0.18 : 1}
            className="radar-node cursor-pointer focus:outline-none"
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
                className="radar-node-shape"
              />
            ) : node.kind === "domain" ? (
              <polygon
                points={diamondPoints(node.x, node.y, radius + 2)}
                fill={nodeFill}
                stroke={nodeStroke}
                strokeWidth={strokeWidth}
                className="radar-node-shape"
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
                className="radar-node-shape"
              />
            ) : (
              <circle
                cx={node.x}
                cy={node.y}
                r={radius}
                fill={nodeFill}
                stroke={nodeStroke}
                strokeWidth={strokeWidth}
                className="radar-node-shape"
              />
            )}

            <text
              x={node.x}
              y={node.y + 4}
              textAnchor="middle"
              fill={countFill}
              fontSize="11"
              fontWeight="700"
              className="pointer-events-none"
            >
              {node.hit_count}
            </text>

            {node.blocked && (
              <g
                transform={`translate(${node.x + radius - 2}, ${node.y - radius - 4})`}
                className="pointer-events-none"
              >
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

            {showPillBg && (
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
                className="pointer-events-none"
              />
            )}
            <text
              x={node.x}
              y={node.y + radius + 17.5}
              textAnchor="middle"
              fill={node.blocked ? "#fecaca" : "#e2e8f0"}
              fontSize="10.5"
              fontWeight={isActive ? "700" : "500"}
              className="pointer-events-none"
            >
              {shortLabel}
            </text>
          </g>
        );
      })}
    </>
  );
});

export const IocGraphSvg = memo(function IocGraphSvg({
  nodes,
  edges,
  selectedNodeId,
  onSelectNode,
  onRequestBlockNode,
}: IocGraphSvgProps) {
  const [internalSelectedId, setInternalSelectedId] = useState<string | null>(null);
  const [kindFilter, setKindFilter] = useState<NodeKindFilter>("all");
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [, startTransition] = useTransition();

  const canvasBoxRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const viewportGroupRef = useRef<SVGGElement | null>(null);
  const zoomLabelRef = useRef<HTMLSpanElement | null>(null);
  const lastZoomPctRef = useRef<number>(-1);
  const tooltipRef = useRef<FloatingTooltipHandle | null>(null);
  const lastTopologyKeyRef = useRef<string | null>(null);
  const cachedRectsRef = useRef<{
    svgRect: DOMRect;
    boxRect: DOMRect;
    scaleToCss: number;
    offsetX: number;
    offsetY: number;
  } | null>(null);

  // Imperative viewport state (zero React re-renders during drag/wheel!)
  const viewportRef = useRef<GraphViewport>({ scale: 1, x: 0, y: 0 });
  const pendingFlushRafRef = useRef<number | null>(null);
  const animRafRef = useRef<number | null>(null);
  const draggingRef = useRef(false);
  const dragOriginRef = useRef<{
    clientX: number;
    clientY: number;
    startX: number;
    startY: number;
    scaleToCss: number;
  } | null>(null);

  const activeSelectedId = selectedNodeId !== undefined ? selectedNodeId : internalSelectedId;
  const activeSelectedIdRef = useRef<string | null>(activeSelectedId);
  activeSelectedIdRef.current = activeSelectedId;

  const selectNode = useCallback(
    (nextId: string | null) => {
      setInternalSelectedId(nextId);
      onSelectNode?.(nextId);
    },
    [onSelectNode],
  );

  const handleToggleSelect = useCallback(
    (nodeId: string) => {
      selectNode(activeSelectedIdRef.current === nodeId ? null : nodeId);
    },
    [selectNode],
  );

  useEffect(() => {
    function handleKey(ev: KeyboardEvent) {
      if (ev.key === "Escape") {
        if (isFullscreen) {
          setIsFullscreen(false);
        } else if (activeSelectedIdRef.current) {
          selectNode(null);
        }
      }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isFullscreen, selectNode]);

  // Layer 2: Stable topology-keyed coordinate layout (never recomputes on pan/zoom/hover/select/block!)
  const topologyKey = useMemo(() => buildGraphTopologyKey(nodes, edges), [nodes, edges]);
  const coordsById = useMemo(() => {
    const t0 = typeof performance !== "undefined" ? performance.now() : 0;
    const extent = computeOptimalGraphExtent(nodes.length, VIEW_W, VIEW_H);
    const laid = computeRadarLayout(nodes, extent.width, extent.height, edges);
    const map = new Map<string, { x: number; y: number; clusterId?: string | null }>();
    for (const item of laid) {
      map.set(item.node_id, { x: item.x, y: item.y, clusterId: item.clusterId });
    }
    if (typeof window !== "undefined") {
      const bench = (
        window as unknown as {
          __VS_BENCH__?: { layoutComputes?: number; layoutTotalMs?: number };
        }
      ).__VS_BENCH__;
      if (bench) {
        bench.layoutComputes = (bench.layoutComputes ?? 0) + 1;
        bench.layoutTotalMs = (bench.layoutTotalMs ?? 0) + (performance.now() - t0);
      }
    }
    return map;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topologyKey]);

  const positioned = useMemo<PositionedRadarNode[]>(() => {
    return nodes.map((node) => {
      const coord = coordsById.get(node.node_id);
      return {
        ...node,
        x: coord?.x ?? VIEW_W / 2,
        y: coord?.y ?? VIEW_H / 2,
        clusterId: coord?.clusterId ?? null,
      };
    });
  }, [nodes, coordsById]);

  const nodeMap = useMemo(() => new Map(positioned.map((n) => [n.node_id, n])), [positioned]);
  const nodeMapRef = useRef(nodeMap);
  nodeMapRef.current = nodeMap;

  const fitViewport = useMemo(
    () => computeFitViewport(positioned, VIEW_W, VIEW_H, MIN_ZOOM, 1.05, 48),
    [positioned],
  );
  const fitViewportRef = useRef(fitViewport);
  fitViewportRef.current = fitViewport;

  if (lastTopologyKeyRef.current !== topologyKey) {
    lastTopologyKeyRef.current = topologyKey;
    viewportRef.current = fitViewport;
  }

  const readViewportMetrics = useCallback(() => {
    if (cachedRectsRef.current) {
      return cachedRectsRef.current;
    }
    const svg = svgRef.current;
    const box = canvasBoxRef.current;
    if (!svg || !box) return null;
    const svgRect = svg.getBoundingClientRect();
    const boxRect = box.getBoundingClientRect();
    if (svgRect.width <= 0 || svgRect.height <= 0) return null;
    const metrics = {
      svgRect,
      boxRect,
      ...getSvgViewportMetrics(svgRect),
    };
    cachedRectsRef.current = metrics;
    return metrics;
  }, []);

  // Invalidate cached bounding rects cleanly via ResizeObserver / scroll (avoids forced reflows on wheel/hover)
  useEffect(() => {
    if (viewMode !== "graph") {
      cachedRectsRef.current = null;
      return;
    }
    const box = canvasBoxRef.current;
    const invalidate = () => {
      cachedRectsRef.current = null;
    };
    let ro: ResizeObserver | null = null;
    if (box && typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver(invalidate);
      ro.observe(box);
    }
    window.addEventListener("scroll", invalidate, { passive: true });
    window.addEventListener("resize", invalidate, { passive: true });
    return () => {
      ro?.disconnect();
      window.removeEventListener("scroll", invalidate);
      window.removeEventListener("resize", invalidate);
      cachedRectsRef.current = null;
    };
  }, [viewMode, isFullscreen]);

  // Imperative DOM commit for viewport matrix + zoom readout (only touches zoom text when % changes!)
  const applyViewportDom = useCallback((vp: GraphViewport) => {
    viewportRef.current = vp;
    if (viewportGroupRef.current) {
      viewportGroupRef.current.setAttribute("transform", formatMatrix(vp));
    }
    const pct = Math.round(vp.scale * 100);
    if (zoomLabelRef.current && pct !== lastZoomPctRef.current) {
      lastZoomPctRef.current = pct;
      zoomLabelRef.current.textContent = `${pct}%`;
    }
  }, []);

  const cancelViewportAnimation = useCallback(() => {
    if (animRafRef.current !== null) {
      window.cancelAnimationFrame(animRafRef.current);
      animRafRef.current = null;
    }
  }, []);

  const scheduleViewportFlush = useCallback(() => {
    if (pendingFlushRafRef.current !== null) return;
    pendingFlushRafRef.current = window.requestAnimationFrame(() => {
      pendingFlushRafRef.current = null;
      applyViewportDom(viewportRef.current);
    });
  }, [applyViewportDom]);

  const animateViewportTo = useCallback(
    (target: GraphViewport, durationMs: number) => {
      cancelViewportAnimation();
      if (durationMs <= 0 || prefersReducedMotion()) {
        applyViewportDom(target);
        return;
      }
      const start = { ...viewportRef.current };
      const t0 = performance.now();
      const step = (now: number) => {
        const progress = Math.min(1, (now - t0) / durationMs);
        const eased = easeOutCubic(progress);
        applyViewportDom({
          scale: start.scale + (target.scale - start.scale) * eased,
          x: start.x + (target.x - start.x) * eased,
          y: start.y + (target.y - start.y) * eased,
        });
        if (progress < 1) {
          animRafRef.current = window.requestAnimationFrame(step);
        } else {
          animRafRef.current = null;
        }
      };
      animRafRef.current = window.requestAnimationFrame(step);
    },
    [applyViewportDom, cancelViewportAnimation],
  );

  // Sync initial fit viewport ONLY when topology changes or switching back to graph view
  useEffect(() => {
    if (viewMode !== "graph") return;
    cancelViewportAnimation();
    applyViewportDom(fitViewportRef.current);
  }, [topologyKey, viewMode, applyViewportDom, cancelViewportAnimation]);

  // Cleanup any active animation frames on unmount
  useEffect(() => {
    return () => {
      if (pendingFlushRafRef.current !== null) {
        window.cancelAnimationFrame(pendingFlushRafRef.current);
        pendingFlushRafRef.current = null;
      }
      if (animRafRef.current !== null) {
        window.cancelAnimationFrame(animRafRef.current);
        animRafRef.current = null;
      }
    };
  }, []);

  // Native non-passive wheel listener: zero page-scroll conflict & cursor-anchored rAF zoom
  useEffect(() => {
    if (viewMode !== "graph") return;
    const svg = svgRef.current;
    if (!svg) return;

    const handleNativeWheel = (ev: globalThis.WheelEvent) => {
      ev.preventDefault();
      cancelViewportAnimation();
      tooltipRef.current?.hide();

      const metrics = readViewportMetrics();
      if (!metrics) return;

      const { svgRect, scaleToCss, offsetX, offsetY } = metrics;
      const anchorSvgX = (ev.clientX - svgRect.left - offsetX) / scaleToCss;
      const anchorSvgY = (ev.clientY - svgRect.top - offsetY) / scaleToCss;

      // Normalize pixel/line delta smoothly across Chrome, Edge, and Firefox
      const deltaPx =
        ev.deltaMode === 1
          ? ev.deltaY * 18
          : ev.deltaMode === 2
            ? ev.deltaY * 120
            : ev.deltaY;
      const clampedDelta = Math.max(-180, Math.min(180, deltaPx));
      const factor = Math.exp(-clampedDelta * 0.0018);

      const current = viewportRef.current;
      viewportRef.current = zoomViewportAroundPoint(
        current,
        current.scale * factor,
        anchorSvgX,
        anchorSvgY,
        MIN_ZOOM,
        MAX_ZOOM,
      );
      scheduleViewportFlush();
    };

    svg.addEventListener("wheel", handleNativeWheel, { passive: false });
    return () => {
      svg.removeEventListener("wheel", handleNativeWheel);
    };
  }, [
    viewMode,
    positioned.length,
    cancelViewportAnimation,
    scheduleViewportFlush,
    readViewportMetrics,
  ]);

  const handlePointerDown = useCallback(
    (ev: PointerEvent<SVGSVGElement>) => {
      if (ev.button !== 0) return;
      if ((ev.target as Element).closest("[data-radar-node='true']")) return;
      cancelViewportAnimation();
      tooltipRef.current?.hide();

      const svg = ev.currentTarget;
      const metrics = readViewportMetrics();
      const scaleToCss = metrics?.scaleToCss ?? getSvgViewportMetrics(svg.getBoundingClientRect()).scaleToCss;

      draggingRef.current = true;
      dragOriginRef.current = {
        clientX: ev.clientX,
        clientY: ev.clientY,
        startX: viewportRef.current.x,
        startY: viewportRef.current.y,
        scaleToCss,
      };
      svg.style.cursor = "grabbing";
      try {
        svg.setPointerCapture(ev.pointerId);
      } catch {
        // Ignore unsupported synthetic pointer IDs
      }
    },
    [cancelViewportAnimation, readViewportMetrics],
  );

  const handlePointerMove = useCallback(
    (ev: PointerEvent<SVGSVGElement>) => {
      if (!draggingRef.current || !dragOriginRef.current) return;
      const origin = dragOriginRef.current;
      const dxSvg = (ev.clientX - origin.clientX) / origin.scaleToCss;
      const dySvg = (ev.clientY - origin.clientY) / origin.scaleToCss;
      viewportRef.current = {
        scale: viewportRef.current.scale,
        x: origin.startX + dxSvg,
        y: origin.startY + dySvg,
      };
      scheduleViewportFlush();
    },
    [scheduleViewportFlush],
  );

  const handlePointerEnd = useCallback(
    (ev: PointerEvent<SVGSVGElement>) => {
      if (!draggingRef.current) return;
      const origin = dragOriginRef.current;
      draggingRef.current = false;
      dragOriginRef.current = null;
      ev.currentTarget.style.cursor = "grab";
      try {
        if (ev.currentTarget.hasPointerCapture(ev.pointerId)) {
          ev.currentTarget.releasePointerCapture(ev.pointerId);
        }
      } catch {
        // Ignore if capture already released
      }
      if (origin && Math.hypot(ev.clientX - origin.clientX, ev.clientY - origin.clientY) < 4) {
        selectNode(null);
      }
    },
    [selectNode],
  );

  // Compute collision-clamped floating tooltip coordinates relative to canvas container
  const showTooltipForNode = useCallback(
    (nodeId: string | null) => {
      if (!nodeId || draggingRef.current) {
        tooltipRef.current?.hide();
        return;
      }
      const node = nodeMapRef.current.get(nodeId);
      const metrics = readViewportMetrics();
      if (!node || !metrics) {
        tooltipRef.current?.hide();
        return;
      }
      const { svgRect, boxRect, scaleToCss, offsetX, offsetY } = metrics;
      const vp = viewportRef.current;

      const screenX =
        (node.x * vp.scale + vp.x) * scaleToCss + offsetX + (svgRect.left - boxRect.left);
      const screenY =
        (node.y * vp.scale + vp.y) * scaleToCss + offsetY + (svgRect.top - boxRect.top);
      const { left, top } = clampFloatingTooltip(
        screenX,
        screenY,
        TOOLTIP_EST_W,
        TOOLTIP_EST_H,
        boxRect.width,
        boxRect.height,
      );
      tooltipRef.current?.show({ node, left, top });
    },
    [readViewportMetrics],
  );

  const handleSvgPointerOver = useCallback(
    (ev: PointerEvent<SVGSVGElement>) => {
      if (draggingRef.current) return;
      const targetEl = (ev.target as Element).closest("[data-radar-node='true']");
      const nodeId = targetEl?.getAttribute("data-node-id") ?? null;
      if (nodeId) {
        showTooltipForNode(nodeId);
      }
    },
    [showTooltipForNode],
  );

  const handleSvgPointerOut = useCallback(
    (ev: PointerEvent<SVGSVGElement>) => {
      const fromNode = (ev.target as Element).closest("[data-radar-node='true']");
      if (!fromNode) return;
      const related = ev.relatedTarget as Element | null;
      const toNode = related?.closest("[data-radar-node='true']");
      if (toNode !== fromNode) {
        showTooltipForNode(toNode?.getAttribute("data-node-id") ?? null);
      }
    },
    [showTooltipForNode],
  );

  const handleSvgFocus = useCallback(
    (ev: FocusEvent<SVGSVGElement>) => {
      const targetEl = (ev.target as Element).closest("[data-radar-node='true']");
      const nodeId = targetEl?.getAttribute("data-node-id") ?? null;
      showTooltipForNode(nodeId);
    },
    [showTooltipForNode],
  );

  const handleSvgBlur = useCallback(
    (ev: FocusEvent<SVGSVGElement>) => {
      const related = ev.relatedTarget as Element | null;
      const toNode = related?.closest("[data-radar-node='true']");
      showTooltipForNode(toNode?.getAttribute("data-node-id") ?? null);
    },
    [showTooltipForNode],
  );

  const handleButtonZoom = useCallback(
    (multiplier: number) => {
      tooltipRef.current?.hide();
      const current = viewportRef.current;
      const target = zoomViewportAroundPoint(
        current,
        current.scale * multiplier,
        VIEW_W / 2,
        VIEW_H / 2,
        MIN_ZOOM,
        MAX_ZOOM,
      );
      animateViewportTo(target, BUTTON_ZOOM_DURATION_MS);
    },
    [animateViewportTo],
  );

  const handleResetViewport = useCallback(() => {
    tooltipRef.current?.hide();
    animateViewportTo(fitViewportRef.current, FIT_ANIMATION_DURATION_MS);
  }, [animateViewportTo]);

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

  const kindCounts = useMemo(() => {
    const counts: Record<RadarNode["kind"], number> = {
      campaign: 0,
      bank_account: 0,
      domain: 0,
      phone: 0,
    };
    for (const n of positioned) {
      counts[n.kind] += 1;
    }
    return counts;
  }, [positioned]);

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

  const selectedNeighbors = useMemo(() => {
    if (!selectedNode) return [];
    return Array.from(neighborIdsByNode.get(selectedNode.node_id) ?? [])
      .map((id) => nodeMap.get(id))
      .filter((n): n is PositionedRadarNode => Boolean(n));
  }, [selectedNode, neighborIdsByNode, nodeMap]);

  function handleSelectFilter(next: NodeKindFilter) {
    startTransition(() => {
      setKindFilter(next);
    });
  }

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
                  onClick={() => handleButtonZoom(0.8)}
                  aria-label="Thu nhỏ sơ đồ"
                  title="Thu nhỏ"
                  className="inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-md text-ink-secondary hover:bg-surface-subtle hover:text-ink"
                >
                  <ZoomOut className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
                <span
                  ref={zoomLabelRef}
                  style={{ contain: "layout style" }}
                  className="tabular-num inline-block min-w-[44px] text-center font-mono text-[11px] text-ink-secondary"
                >
                  {Math.round(viewportRef.current.scale * 100)}%
                </span>
                <button
                  type="button"
                  onClick={() => handleButtonZoom(1.25)}
                  aria-label="Phóng to sơ đồ"
                  title="Phóng to"
                  className="inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-md text-ink-secondary hover:bg-surface-subtle hover:text-ink"
                >
                  <ZoomIn className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
                <button
                  type="button"
                  onClick={handleResetViewport}
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

        {/* Entity kind filters + stable legend row */}
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

            {KIND_ENTRIES.map(([kind, cfg]) => {
              const count = kindCounts[kind];
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

          <div className="flex min-h-[28px] items-center gap-2 text-[11px] text-ink-muted">
            <span className="inline-flex items-center gap-1">
              <span
                aria-hidden="true"
                className="inline-block h-2.5 w-2.5 rounded-full border border-dashed border-rose-400 bg-rose-700"
              />
              <span>Đang áp dụng chặn</span>
            </span>
            <button
              type="button"
              onClick={() => selectNode(null)}
              disabled={!selectedNode}
              aria-hidden={!selectedNode}
              tabIndex={selectedNode ? 0 : -1}
              className={`inline-flex min-h-[28px] items-center gap-1 rounded-md border border-border-strong bg-surface-subtle px-2 py-0.5 text-[11px] font-medium text-ink-secondary transition-opacity duration-150 hover:text-ink ${
                selectedNode ? "cursor-pointer opacity-100" : "pointer-events-none opacity-0"
              }`}
            >
              <X className="h-3 w-3" aria-hidden="true" />
              <span>Bỏ chọn</span>
            </button>
          </div>
        </div>

        {viewMode === "graph" ? (
          <div
            ref={canvasBoxRef}
            style={{ contain: "layout paint style" }}
            className={`radar-canvas-grid relative overflow-hidden rounded-xl border border-border-subtle ${
              isFullscreen ? "flex min-h-0 flex-1 flex-col" : ""
            }`}
          >
            {/* Fixed-height static hint bar (NEVER wraps or changes height on hover!) */}
            <div className="flex h-8 shrink-0 items-center justify-between gap-2 border-b border-border-subtle/70 bg-surface-subtle/80 px-3 text-[11px] text-ink-muted">
              <span className="truncate">
                Di chuột vào nút để xem giải thích số liệu · Nhấp để cố định liên kết
              </span>
              <span className="hidden shrink-0 text-[10px] sm:inline">
                Kéo nền để di chuyển · Cuộn chuột để thu phóng
              </span>
            </div>

            {/* Floating overlay tooltip (zero layout shift, zero pointer obstruction) */}
            <FloatingNodeTooltip ref={tooltipRef} />

            {positioned.length === 0 ? (
              <div className="flex h-64 items-center justify-center p-6 text-center text-xs text-ink-muted">
                Chưa có chiến dịch hoặc dấu hiệu nghi vấn nào được ghi nhận.
              </div>
            ) : (
              <svg
                ref={svgRef}
                data-lenis-prevent
                viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
                preserveAspectRatio="xMidYMid meet"
                role="group"
                aria-label="Sơ đồ mạng lưới liên kết chiến dịch và dấu hiệu nghi vấn"
                onPointerDown={handlePointerDown}
                onPointerMove={handlePointerMove}
                onPointerUp={handlePointerEnd}
                onPointerCancel={handlePointerEnd}
                onPointerOver={handleSvgPointerOver}
                onPointerOut={handleSvgPointerOut}
                onFocus={handleSvgFocus}
                onBlur={handleSvgBlur}
                style={{ cursor: "grab" }}
                className={`block w-full touch-none select-none ${
                  isFullscreen ? "min-h-0 flex-1" : "h-[340px] sm:h-[420px]"
                }`}
              >
                <title>Mạng lưới liên kết chiến dịch và dấu hiệu nghi vấn</title>
                <g ref={viewportGroupRef} transform={formatMatrix(viewportRef.current)}>
                  <GraphSceneLayer
                    positioned={positioned}
                    edges={edges}
                    nodeMap={nodeMap}
                    matchingFilterIds={matchingFilterIds}
                    focusedIds={focusedIds}
                    selectedNodeId={activeSelectedId}
                    onToggleSelect={handleToggleSelect}
                  />
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
                      .filter((nb): nb is PositionedRadarNode => Boolean(nb))
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
                      {nb.blocked && (
                        <ShieldAlert className="h-3 w-3 text-rose-400" aria-hidden="true" />
                      )}
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
});
