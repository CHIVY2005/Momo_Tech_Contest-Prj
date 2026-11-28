"use client";

import "@xyflow/react/dist/style.css";

import {
  Background,
  BackgroundVariant,
  Controls,
  type Edge,
  Handle,
  MarkerType,
  MiniMap,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";
import {
  AlertTriangle,
  Building2,
  FileSearch,
  Globe,
  Landmark,
  Link2,
  Mail,
  Phone,
  RotateCcw,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";
import { memo, useEffect, useMemo } from "react";

import {
  type CaseEntityKind,
  type CaseGraphEdge,
  type CaseGraphNode,
  ENTITY_KIND_LABELS,
  type RiskTone,
  VERIFICATION_STATE_META,
} from "@/lib/caseGraph";

type FlowNodeData = CaseGraphNode & Record<string, unknown>;
type FlowEntityNode = Node<FlowNodeData, "caseEntity">;

const TONE_BORDER: Record<RiskTone, string> = {
  safe: "border-emerald-500/55",
  info: "border-sky-500/50",
  suspicious: "border-amber-500/55",
  high: "border-orange-500/60",
  critical: "border-rose-500/70",
};

const TONE_STRIPE: Record<RiskTone, string> = {
  safe: "bg-emerald-400",
  info: "bg-sky-400",
  suspicious: "bg-amber-400",
  high: "bg-orange-400",
  critical: "bg-rose-500",
};

const VERIFICATION_PILL: Record<CaseGraphNode["verificationState"], string> = {
  verified_evidence: "border-emerald-500/40 bg-emerald-500/12 text-emerald-200",
  extracted_info: "border-sky-500/40 bg-sky-500/12 text-sky-200",
  suspected_relation: "border-amber-500/45 bg-amber-500/12 text-amber-200",
  unverified_info: "border-slate-500/45 bg-slate-500/15 text-slate-300",
};

function EntityIcon({ kind }: { kind: CaseEntityKind }) {
  const cls = "h-3.5 w-3.5 shrink-0";
  switch (kind) {
    case "case":
      return <FileSearch className={`${cls} text-amber-300`} aria-hidden="true" />;
    case "url":
      return <Link2 className={`${cls} text-orange-300`} aria-hidden="true" />;
    case "domain":
      return <Globe className={`${cls} text-sky-300`} aria-hidden="true" />;
    case "phone":
      return <Phone className={`${cls} text-purple-300`} aria-hidden="true" />;
    case "bank_account":
      return <Landmark className={`${cls} text-cyan-300`} aria-hidden="true" />;
    case "email":
      return <Mail className={`${cls} text-sky-300`} aria-hidden="true" />;
    case "brand":
      return <Building2 className={`${cls} text-amber-300`} aria-hidden="true" />;
    case "signal":
      return <AlertTriangle className={`${cls} text-amber-300`} aria-hidden="true" />;
    case "evidence_source":
      return <ShieldCheck className={`${cls} text-emerald-300`} aria-hidden="true" />;
    case "verdict":
      return <ShieldAlert className={`${cls} text-rose-300`} aria-hidden="true" />;
  }
}

const CaseEntityNodeCard = memo(function CaseEntityNodeCard({
  data,
  selected,
}: NodeProps<FlowEntityNode>) {
  const verMeta = VERIFICATION_STATE_META[data.verificationState];

  return (
    <div
      className={`relative w-[216px] overflow-hidden rounded-xl border bg-surface px-3 py-2.5 shadow-lg transition-colors ${
        selected
          ? "border-amber-400 ring-2 ring-amber-400/35"
          : `${TONE_BORDER[data.riskTone]} hover:border-slate-400`
      }`}
    >
      <span
        aria-hidden="true"
        className={`absolute inset-y-0 left-0 w-1 ${TONE_STRIPE[data.riskTone]}`}
      />
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2 !w-2 !border-slate-700 !bg-slate-400"
      />
      <Handle
        type="source"
        position={Position.Right}
        className="!h-2 !w-2 !border-slate-700 !bg-amber-400"
      />

      <div className="flex items-center justify-between gap-1.5 pl-1">
        <span className="inline-flex min-w-0 items-center gap-1 text-[10px] font-semibold text-ink-muted">
          <EntityIcon kind={data.kind} />
          <span className="truncate">{ENTITY_KIND_LABELS[data.kind]}</span>
        </span>
      </div>

      <p className="mt-1 truncate pl-1 font-mono text-xs font-bold text-ink" title={data.label}>
        {data.label}
      </p>
      <p className="mt-0.5 truncate pl-1 text-[10.5px] text-ink-muted" title={data.subtitle}>
        {data.subtitle}
      </p>

      <div className="mt-2 pl-1">
        <span
          className={`inline-block rounded border px-1.5 py-0.5 text-[9.5px] font-semibold ${
            VERIFICATION_PILL[data.verificationState]
          }`}
        >
          {verMeta.label}
        </span>
      </div>
    </div>
  );
});

const NODE_TYPES = { caseEntity: CaseEntityNodeCard };

interface FraudRelationshipFlowCanvasProps {
  graphNodes: CaseGraphNode[];
  graphEdges: CaseGraphEdge[];
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  showMiniMap: boolean;
  layoutNonce: number;
  onSelectNode: (nodeId: string | null) => void;
  onSelectEdge: (edgeId: string | null) => void;
  onResetLayout: () => void;
}

function toFlowNodes(items: CaseGraphNode[], selectedNodeId: string | null): FlowEntityNode[] {
  return items.map((item) => ({
    id: item.id,
    type: "caseEntity",
    position: { x: item.x, y: item.y },
    selected: item.id === selectedNodeId,
    data: { ...item },
  }));
}

function toFlowEdges(items: CaseGraphEdge[], selectedEdgeId: string | null): Edge[] {
  return items.map((edge) => {
    const isSelected = edge.id === selectedEdgeId;
    const stroke = isSelected
      ? "#f59e0b"
      : edge.verificationState === "verified_evidence"
        ? "#38bdf8"
        : edge.verificationState === "suspected_relation"
          ? "#f59e0b"
          : "#64748b";
    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: edge.label,
      selected: isSelected,
      animated: false,
      style: {
        stroke,
        strokeWidth: isSelected ? 2.4 : 1.5,
        strokeDasharray:
          edge.verificationState === "suspected_relation" ||
          edge.verificationState === "unverified_info"
            ? "5 4"
            : undefined,
      },
      labelStyle: { fill: "#cbd5e1", fontSize: 10, fontWeight: 500 },
      labelBgStyle: { fill: "#070b14", fillOpacity: 0.88 },
      labelBgPadding: [5, 3] as [number, number],
      labelBgBorderRadius: 4,
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: stroke,
        width: 14,
        height: 14,
      },
    };
  });
}

function InnerFlowCanvas({
  graphNodes,
  graphEdges,
  selectedNodeId,
  selectedEdgeId,
  showMiniMap,
  layoutNonce,
  onSelectNode,
  onSelectEdge,
  onResetLayout,
}: FraudRelationshipFlowCanvasProps) {
  const initialNodes = useMemo(
    () => toFlowNodes(graphNodes, selectedNodeId),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [graphNodes, layoutNonce],
  );
  const initialEdges = useMemo(
    () => toFlowEdges(graphEdges, selectedEdgeId),
    [graphEdges, selectedEdgeId],
  );

  const [nodes, setNodes, onNodesChange] = useNodesState<FlowEntityNode>(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const { fitView } = useReactFlow();

  useEffect(() => {
    setNodes(toFlowNodes(graphNodes, selectedNodeId));
    const timer = window.setTimeout(() => {
      void fitView({ padding: 0.16, duration: 220 });
    }, 30);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphNodes, layoutNonce]);

  useEffect(() => {
    setNodes((prev) =>
      prev.map((n) => ({
        ...n,
        selected: n.id === selectedNodeId,
      })),
    );
  }, [selectedNodeId, setNodes]);

  useEffect(() => {
    setEdges(toFlowEdges(graphEdges, selectedEdgeId));
  }, [graphEdges, selectedEdgeId, setEdges]);

  return (
    <div
      data-lenis-prevent-wheel
      className="vs-flow-canvas relative h-[430px] w-full overflow-hidden rounded-xl border border-border-subtle bg-surface-deep sm:h-[470px]"
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={(_ev, node) => {
          onSelectEdge(null);
          onSelectNode(node.id);
        }}
        onEdgeClick={(_ev, edge) => {
          onSelectNode(null);
          onSelectEdge(edge.id);
        }}
        onPaneClick={() => {
          onSelectNode(null);
          onSelectEdge(null);
        }}
        fitView
        fitViewOptions={{ padding: 0.16 }}
        minZoom={0.3}
        maxZoom={1.9}
        nodesConnectable={false}
        elementsSelectable
        proOptions={{ hideAttribution: false }}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#273449" />
        <Controls showInteractive={false} position="bottom-left" />
        {showMiniMap && (
          <MiniMap
            pannable
            zoomable
            position="bottom-right"
            nodeColor={(n) => {
              const tone = (n.data as FlowNodeData | undefined)?.riskTone;
              if (tone === "critical") return "#ef4444";
              if (tone === "high") return "#f97316";
              if (tone === "suspicious") return "#f59e0b";
              if (tone === "safe") return "#10b981";
              return "#0ea5e9";
            }}
            maskColor="rgba(7, 11, 20, 0.72)"
          />
        )}
      </ReactFlow>

      <div className="pointer-events-auto absolute top-2.5 right-2.5 z-10 flex items-center gap-1.5">
        <button
          type="button"
          onClick={() => {
            onResetLayout();
            void fitView({ padding: 0.16, duration: 220 });
          }}
          className="vs-pressable inline-flex min-h-[32px] cursor-pointer items-center gap-1.5 rounded-lg border border-border-strong bg-surface/95 px-2.5 py-1 text-[11px] font-semibold text-ink-secondary shadow-md hover:border-amber-400/70 hover:text-ink"
        >
          <RotateCcw className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
          <span>Tự động bố cục</span>
        </button>
      </div>
    </div>
  );
}

export function FraudRelationshipFlowCanvas(props: FraudRelationshipFlowCanvasProps) {
  return (
    <ReactFlowProvider>
      <InnerFlowCanvas {...props} />
    </ReactFlowProvider>
  );
}
