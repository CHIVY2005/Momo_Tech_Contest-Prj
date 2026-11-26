"use client";

import { Network } from "lucide-react";
import { useMemo, useState } from "react";

import { computeRadarLayout } from "@/lib/radarLayout";
import type { RadarEdge, RadarNode } from "@/lib/types";

interface IocGraphSvgProps {
  nodes: RadarNode[];
  edges: RadarEdge[];
}

const KIND_COLORS: Record<RadarNode["kind"], { fill: string; stroke: string; labelVi: string }> = {
  campaign: { fill: "#f59e0b", stroke: "#fde68a", labelVi: "Chiến dịch Lừa đảo" },
  bank_account: { fill: "#0ea5e9", stroke: "#bae6fd", labelVi: "Tài khoản Nhận (Ẩn danh)" },
  domain: { fill: "#f97316", stroke: "#fed7aa", labelVi: "Tên miền Giả mạo" },
  phone: { fill: "#a855f7", stroke: "#e9d5ff", labelVi: "Số điện thoại Mồi" },
};

export function IocGraphSvg({ nodes, edges }: IocGraphSvgProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const positioned = useMemo(() => computeRadarLayout(nodes, 760, 420), [nodes]);
  const nodeMap = useMemo(() => new Map(positioned.map((n) => [n.node_id, n])), [positioned]);
  const selectedNode = selectedId ? nodeMap.get(selectedId) ?? null : positioned[0] ?? null;

  return (
    <section
      aria-labelledby="ioc-graph-heading"
      className="rounded-2xl border border-slate-800 bg-[#111827]/95 p-5 shadow-lg"
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Network className="h-5 w-5 text-sky-400" aria-hidden="true" />
          <div>
            <h2 id="ioc-graph-heading" className="text-sm font-bold text-slate-50">
              Đồ thị Liên kết Chiến dịch &amp; Cụm IOC Ẩn danh (Zero Raw PII)
            </h2>
            <p className="text-xs text-slate-400">
              Nhấp hoặc nhấn Enter vào từng nút để soi mối liên hệ đồng xuất hiện giữa SĐT, STK và tên miền.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-300">
          {Object.entries(KIND_COLORS).map(([key, cfg]) => (
            <span key={key} className="inline-flex items-center gap-1.5">
              <span
                className="inline-block h-2.5 w-2.5 rounded-full"
                style={{ backgroundColor: cfg.fill }}
                aria-hidden="true"
              />
              <span>{cfg.labelVi}</span>
            </span>
          ))}
        </div>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#070b14]">
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
                strokeDasharray={dst.blocked || src.blocked ? "5 4" : undefined}
              />
            );
          })}

          {positioned.map((node) => {
            const style = KIND_COLORS[node.kind];
            const isCampaign = node.kind === "campaign";
            const radius = isCampaign ? 22 : 16;
            const isActive = selectedNode?.node_id === node.node_id;

            return (
              <g
                key={node.node_id}
                role="button"
                tabIndex={0}
                aria-pressed={isActive}
                aria-label={`${style.labelVi}: ${node.label} (${node.hit_count} ca${
                  node.blocked ? ", đã bị chặn" : ""
                })`}
                onClick={() => setSelectedId(node.node_id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setSelectedId(node.node_id);
                  }
                }}
                className="cursor-pointer"
              >
                {node.blocked && (
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={radius + 6}
                    fill="none"
                    stroke="#ef4444"
                    strokeWidth={2.5}
                  />
                )}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={radius}
                  fill={node.blocked ? "#991b1b" : style.fill}
                  stroke={isActive ? "#ffffff" : style.stroke}
                  strokeWidth={isActive ? 3 : 1.5}
                />
                <text
                  x={node.x}
                  y={node.y + 4}
                  textAnchor="middle"
                  fill="#090e1a"
                  fontSize="10"
                  fontWeight="700"
                >
                  {node.hit_count}
                </text>
                <text
                  x={node.x}
                  y={node.y + radius + 15}
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
      </div>

      {selectedNode && (
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-800 bg-[#0b1120] px-3.5 py-2.5 text-xs">
          <div>
            <span className="text-slate-400">Đang chọn: </span>
            <strong className="font-[family-name:var(--font-mono)] text-slate-100">
              {selectedNode.label}
            </strong>
            <span className="ml-2 text-slate-400">
              ({KIND_COLORS[selectedNode.kind].labelVi} · {selectedNode.hit_count} lượt ghi nhận)
            </span>
          </div>
          <span
            className={`rounded px-2 py-0.5 font-[family-name:var(--font-mono)] text-[11px] font-bold ${
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
