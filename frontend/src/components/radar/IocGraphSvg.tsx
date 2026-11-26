"use client";

import { Network, Table2 } from "lucide-react";
import { useMemo, useState, useTransition } from "react";

import { computeRadarLayout } from "@/lib/radarLayout";
import type { RadarEdge, RadarNode } from "@/lib/types";

interface IocGraphSvgProps {
  nodes: RadarNode[];
  edges: RadarEdge[];
}

type NodeKindFilter = "all" | RadarNode["kind"];

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
    labelVi: "Chiến dịch Lừa đảo",
    shortVi: "Chiến dịch",
    shapeLabel: "Lục giác",
  },
  bank_account: {
    fill: "#0ea5e9",
    stroke: "#bae6fd",
    textFill: "#090e1a",
    labelVi: "Tài khoản Nhận (Ẩn danh)",
    shortVi: "Tài khoản",
    shapeLabel: "Hình tròn",
  },
  domain: {
    fill: "#f97316",
    stroke: "#fed7aa",
    textFill: "#090e1a",
    labelVi: "Tên miền Giả mạo",
    shortVi: "Tên miền",
    shapeLabel: "Hình thoi",
  },
  phone: {
    fill: "#9333ea",
    stroke: "#e9d5ff",
    textFill: "#ffffff",
    labelVi: "Số điện thoại Mồi",
    shortVi: "SĐT",
    shapeLabel: "Hình vuông",
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

export function IocGraphSvg({ nodes, edges }: IocGraphSvgProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [kindFilter, setKindFilter] = useState<NodeKindFilter>("all");
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const [, startTransition] = useTransition();

  const positioned = useMemo(() => computeRadarLayout(nodes, 760, 420), [nodes]);
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

  const matchingIds = useMemo(() => {
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

  const filteredTableNodes = useMemo(
    () => (kindFilter === "all" ? positioned : positioned.filter((n) => n.kind === kindFilter)),
    [positioned, kindFilter],
  );

  const selectedNode = selectedId ? (nodeMap.get(selectedId) ?? null) : (positioned[0] ?? null);

  function handleSelectFilter(next: NodeKindFilter) {
    startTransition(() => {
      setKindFilter(next);
    });
  }

  return (
    <section
      aria-labelledby="ioc-graph-heading"
      className="rounded-2xl border border-border-subtle bg-surface/95 p-4 shadow-lg sm:p-5"
    >
      <div className="mb-3 flex flex-wrap items-start justify-between gap-2.5">
        <div className="flex items-start gap-2">
          <Network className="mt-0.5 h-5 w-5 shrink-0 text-sky-400" aria-hidden="true" />
          <div>
            <h2 id="ioc-graph-heading" className="text-sm font-bold text-ink">
              Đồ thị Liên kết Chiến dịch &amp; Cụm IOC Ẩn danh (Zero Raw PII)
            </h2>
            <p className="text-xs text-ink-muted">
              Nhấp hoặc nhấn Enter vào từng nút để soi cụm liên kết. Khối bị khóa hiển thị vòng đỏ.
            </p>
          </div>
        </div>

        <div
          role="group"
          aria-label="Chế độ hiển thị đồ thị IOC"
          className="inline-flex shrink-0 rounded-lg border border-border-strong bg-surface-deep p-0.5 text-[11px]"
        >
          <button
            type="button"
            aria-pressed={viewMode === "graph"}
            onClick={() => setViewMode("graph")}
            className={`inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-md px-2.5 py-1 font-semibold transition-colors ${
              viewMode === "graph"
                ? "bg-sky-500/20 text-sky-200"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            <Network className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Đồ thị</span>
          </button>
          <button
            type="button"
            aria-pressed={viewMode === "table"}
            onClick={() => setViewMode("table")}
            className={`inline-flex min-h-[34px] cursor-pointer items-center gap-1.5 rounded-md px-2.5 py-1 font-semibold transition-colors ${
              viewMode === "table"
                ? "bg-sky-500/20 text-sky-200"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            <Table2 className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Bảng liên kết</span>
          </button>
        </div>
      </div>

      {/* Interactive kind filter legend (shapes + colors for WCAG 1.4.1 non-color redundancy) */}
      <div
        role="group"
        aria-label="Lọc loại thực thể trên đồ thị"
        className="mb-3 flex flex-wrap items-center gap-1.5 text-[11px]"
      >
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

        {(Object.entries(KIND_META) as Array<[RadarNode["kind"], (typeof KIND_META)[RadarNode["kind"]]]>).map(
          ([kind, cfg]) => {
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
          },
        )}
      </div>

      {viewMode === "graph" ? (
        <div className="overflow-hidden rounded-xl border border-border-subtle bg-surface-deep">
          <div className="flex items-center justify-between border-b border-border-subtle/70 bg-surface-subtle/60 px-3 py-1.5 text-[11px] text-ink-muted sm:hidden">
            <span>Màn hình nhỏ: chạm &ldquo;Bảng liên kết&rdquo; để xem rõ từng thực thể.</span>
          </div>

          {positioned.length === 0 ? (
            <div className="flex h-56 items-center justify-center p-6 text-center text-xs text-ink-muted">
              Chưa có cụm chiến dịch hoặc thực thể IOC nào được ghi nhận trên đồ thị Fraud Ops.
            </div>
          ) : (
            <svg
              viewBox="0 0 760 420"
              role="group"
              aria-label="Sơ đồ mạng lưới chiến dịch lừa đảo và thực thể IOC đã che dấu PII"
              className="h-auto w-full"
            >
              <title>Đồ thị liên kết chiến dịch lừa đảo và IOC ẩn danh VeriShield AI</title>

              {edges.map((edge, idx) => {
                const src = nodeMap.get(edge.source);
                const dst = nodeMap.get(edge.target);
                if (!src || !dst) return null;
                const isVisible = matchingIds.has(src.node_id) && matchingIds.has(dst.node_id);
                const isHighlighted =
                  selectedNode?.node_id === edge.source || selectedNode?.node_id === edge.target;

                return (
                  <line
                    key={`${edge.source}-${edge.target}-${idx}`}
                    x1={src.x}
                    y1={src.y}
                    x2={dst.x}
                    y2={dst.y}
                    stroke={isHighlighted ? "#38bdf8" : "#334155"}
                    strokeWidth={isHighlighted ? 2.4 : 1.3}
                    strokeOpacity={isVisible ? 1 : 0.16}
                    strokeDasharray={dst.blocked || src.blocked ? "5 4" : undefined}
                  />
                );
              })}

              {positioned.map((node) => {
                const style = KIND_META[node.kind];
                const isCampaign = node.kind === "campaign";
                const radius = isCampaign ? 22 : 16;
                const isActive = selectedNode?.node_id === node.node_id;
                const isDimmed = !matchingIds.has(node.node_id);
                const nodeFill = node.blocked ? "#991b1b" : style.fill;
                const countFill = node.blocked ? "#ffffff" : style.textFill;
                const nodeStroke = isActive ? "#ffffff" : style.stroke;
                const strokeWidth = isActive ? 3 : 1.6;

                return (
                  <g
                    key={node.node_id}
                    role="button"
                    tabIndex={0}
                    aria-pressed={isActive}
                    aria-label={`${style.labelVi} (${style.shapeLabel}): ${node.label} (${node.hit_count} ca${
                      node.blocked ? ", đã bị chặn" : ""
                    })`}
                    onClick={() => setSelectedId(node.node_id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setSelectedId(node.node_id);
                      }
                    }}
                    opacity={isDimmed ? 0.22 : 1}
                    className="cursor-pointer transition-opacity duration-150"
                  >
                    {node.blocked && (
                      <circle
                        cx={node.x}
                        cy={node.y}
                        r={radius + 7}
                        fill="none"
                        stroke="#ef4444"
                        strokeWidth={2.5}
                        strokeDasharray="4 2"
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
                    <text
                      x={node.x}
                      y={node.y + radius + 16}
                      textAnchor="middle"
                      fill={node.blocked ? "#fecaca" : "#e2e8f0"}
                      fontSize="11"
                      fontWeight={isActive ? "700" : "500"}
                    >
                      {node.label.length > 26 ? `${node.label.slice(0, 24)}…` : node.label}
                    </text>
                  </g>
                );
              })}
            </svg>
          )}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-border-subtle bg-surface-deep">
          <table className="w-full min-w-[520px] border-collapse text-left text-xs">
            <caption className="sr-only">
              Bảng liên kết chiến dịch lừa đảo và thực thể IOC ẩn danh
            </caption>
            <thead>
              <tr className="border-b border-border-subtle bg-surface-subtle text-[11px] font-semibold text-ink-secondary">
                <th scope="col" className="px-3 py-2.5">
                  Thực thể (Ẩn danh PII)
                </th>
                <th scope="col" className="px-3 py-2.5">
                  Phân loại
                </th>
                <th scope="col" className="px-3 py-2.5 text-right">
                  Lượt ghi nhận
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
                    Không có thực thể nào khớp bộ lọc hiện tại.
                  </td>
                </tr>
              ) : (
                filteredTableNodes.map((node) => {
                  const cfg = KIND_META[node.kind];
                  const neighbors = Array.from(neighborIdsByNode.get(node.node_id) ?? [])
                    .map((id) => nodeMap.get(id)?.label)
                    .filter((lbl): lbl is string => Boolean(lbl));
                  const isActive = selectedNode?.node_id === node.node_id;

                  return (
                    <tr
                      key={node.node_id}
                      onClick={() => setSelectedId(node.node_id)}
                      className={`cursor-pointer transition-colors ${
                        isActive ? "bg-sky-500/10" : "hover:bg-surface-subtle/70"
                      }`}
                    >
                      <td className="tabular-num px-3 py-2.5 font-mono font-semibold text-ink">
                        {node.label}
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
                          className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${
                            node.blocked
                              ? "bg-rose-500/20 text-rose-200"
                              : "bg-amber-500/15 text-amber-200"
                          }`}
                        >
                          {node.blocked ? "ĐÃ KHÓA" : node.risk_level}
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

      {selectedNode && (
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-border-subtle bg-surface-subtle px-3.5 py-2.5 text-xs">
          <div>
            <span className="text-ink-muted">Đang chọn: </span>
            <strong className="tabular-num font-mono text-ink">{selectedNode.label}</strong>
            <span className="tabular-num ml-2 text-ink-muted">
              ({KIND_META[selectedNode.kind].labelVi} · {selectedNode.hit_count} lượt ghi nhận)
            </span>
          </div>
          <span
            className={`rounded px-2 py-0.5 font-mono text-[11px] font-bold ${
              selectedNode.blocked
                ? "bg-rose-500/20 text-rose-200"
                : "bg-amber-500/15 text-amber-200"
            }`}
          >
            {selectedNode.blocked ? "ĐÃ KHÓA HỆ SINH THÁI" : selectedNode.risk_level}
          </span>
        </div>
      )}
    </section>
  );
}
