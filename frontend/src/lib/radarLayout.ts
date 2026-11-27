import type { RadarEdge, RadarNode } from "./types";

export interface PositionedRadarNode extends RadarNode {
  x: number;
  y: number;
  clusterId?: string | null;
}

export interface GraphViewport {
  scale: number;
  x: number;
  y: number;
}

export interface GraphExtent {
  width: number;
  height: number;
}

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val));
}

/**
 * Return an adaptive virtual layout plane so small graphs fill the default canvas
 * while larger graphs (50, 100, 500+ nodes) expand cleanly without cramming or overlap.
 */
export function computeOptimalGraphExtent(
  nodeCount: number,
  baseWidth: number = 860,
  baseHeight: number = 480,
): GraphExtent {
  if (nodeCount <= 26) {
    return { width: baseWidth, height: baseHeight };
  }
  const factor = Math.sqrt(nodeCount / 14);
  return {
    width: Math.round(baseWidth * factor),
    height: Math.round(baseHeight * factor),
  };
}

/**
 * Compute a deterministic structural topology signature so layout only recomputes
 * when node IDs/kinds or edges actually change (ignoring hover, selection, or block toggles).
 */
export function buildGraphTopologyKey(
  nodes: ReadonlyArray<Pick<RadarNode, "node_id" | "kind">>,
  edges: ReadonlyArray<Pick<RadarEdge, "source" | "target" | "relation">>,
): string {
  const nodePart = nodes.map((n) => `${n.node_id}:${n.kind}`).join("|");
  const edgePart = edges.map((e) => `${e.source}>${e.target}:${e.relation}`).join("|");
  return `${nodes.length}#${edges.length}#${nodePart}#${edgePart}`;
}

/**
 * Compute the viewport transform (matrix scale + translation in SVG viewBox units)
 * that centers and fits all positioned nodes inside the visible SVG viewBox.
 */
export function computeFitViewport(
  positioned: ReadonlyArray<Pick<PositionedRadarNode, "x" | "y" | "kind">>,
  viewWidth: number,
  viewHeight: number,
  minScale: number = 0.2,
  maxScale: number = 1.15,
  padding: number = 56,
): GraphViewport {
  if (positioned.length === 0) {
    return { scale: 1, x: 0, y: 0 };
  }

  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const n of positioned) {
    const padX = n.kind === "campaign" ? 88 : 68;
    const padTop = n.kind === "campaign" ? 32 : 24;
    const padBottom = n.kind === "campaign" ? 50 : 42;
    if (n.x - padX < minX) minX = n.x - padX;
    if (n.x + padX > maxX) maxX = n.x + padX;
    if (n.y - padTop < minY) minY = n.y - padTop;
    if (n.y + padBottom > maxY) maxY = n.y + padBottom;
  }

  const contentW = Math.max(120, maxX - minX);
  const contentH = Math.max(120, maxY - minY);
  const availW = Math.max(120, viewWidth - padding);
  const availH = Math.max(120, viewHeight - padding);
  const rawScale = Math.min(availW / contentW, availH / contentH);
  const scale = clamp(Number(rawScale.toFixed(4)), minScale, maxScale);

  const centerX = (minX + maxX) / 2;
  const centerY = (minY + maxY) / 2;
  const x = viewWidth / 2 - centerX * scale;
  const y = viewHeight / 2 - centerY * scale;

  return { scale, x, y };
}

/**
 * Zoom around a specific SVG viewBox anchor coordinate so the point under the cursor stays fixed.
 */
export function zoomViewportAroundPoint(
  current: GraphViewport,
  targetScale: number,
  anchorSvgX: number,
  anchorSvgY: number,
  minScale: number,
  maxScale: number,
): GraphViewport {
  const nextScale = clamp(targetScale, minScale, maxScale);
  if (Math.abs(nextScale - current.scale) < 1e-5) {
    return current;
  }
  const worldX = (anchorSvgX - current.x) / current.scale;
  const worldY = (anchorSvgY - current.y) / current.scale;
  return {
    scale: nextScale,
    x: anchorSvgX - worldX * nextScale,
    y: anchorSvgY - worldY * nextScale,
  };
}

/**
 * Clamp floating tooltip coordinates inside the graph container with edge collision avoidance.
 */
export function clampFloatingTooltip(
  anchorX: number,
  anchorY: number,
  tooltipWidth: number,
  tooltipHeight: number,
  containerWidth: number,
  containerHeight: number,
  margin: number = 10,
): { left: number; top: number; placement: "top" | "bottom" } {
  const gap = 14;
  const preferredTop = anchorY - tooltipHeight - gap;
  let placement: "top" | "bottom" = "top";
  let top = preferredTop;

  if (preferredTop < margin) {
    placement = "bottom";
    top = anchorY + gap;
  }
  if (top + tooltipHeight > containerHeight - margin) {
    top = Math.max(margin, containerHeight - tooltipHeight - margin);
  }

  const centeredLeft = anchorX - tooltipWidth / 2;
  const maxLeft = Math.max(margin, containerWidth - tooltipWidth - margin);
  const left = clamp(centeredLeft, margin, maxLeft);

  return { left: Math.round(left), top: Math.round(top), placement };
}

function layoutConcentricFallback(
  nodes: RadarNode[],
  width: number,
  height: number,
): PositionedRadarNode[] {
  const cx = width / 2;
  const cy = height / 2;
  const campaigns = nodes.filter((n) => n.kind === "campaign");
  const iocs = nodes.filter((n) => n.kind !== "campaign");
  const positioned: PositionedRadarNode[] = [];

  campaigns.forEach((node, idx) => {
    if (campaigns.length === 1) {
      positioned.push({ ...node, x: Math.round(cx), y: Math.round(cy), clusterId: node.node_id });
      return;
    }
    const angle = (2 * Math.PI * idx) / campaigns.length - Math.PI / 2;
    const rx = width * 0.19;
    const ry = height * 0.21;
    positioned.push({
      ...node,
      x: Math.round(clamp(cx + rx * Math.cos(angle), 52, width - 52)),
      y: Math.round(clamp(cy + ry * Math.sin(angle), 48, height - 48)),
      clusterId: node.node_id,
    });
  });

  const useTwoRings = iocs.length > 14;
  iocs.forEach((node, idx) => {
    const ringIndex = useTwoRings ? idx % 2 : 0;
    const ringCount = useTwoRings
      ? Math.max(1, Math.ceil((iocs.length - ringIndex) / 2))
      : Math.max(1, iocs.length);
    const posInRing = useTwoRings ? Math.floor(idx / 2) : idx;
    const phase = useTwoRings && ringIndex === 1 ? Math.PI / ringCount : 0;
    const angle = (2 * Math.PI * posInRing) / ringCount - Math.PI / 3 + phase;
    const rx = useTwoRings ? width * (ringIndex === 0 ? 0.31 : 0.43) : width * 0.39;
    const ry = useTwoRings ? height * (ringIndex === 0 ? 0.29 : 0.41) : height * 0.37;
    positioned.push({
      ...node,
      x: Math.round(clamp(cx + rx * Math.cos(angle), 52, width - 52)),
      y: Math.round(clamp(cy + ry * Math.sin(angle), 48, height - 48)),
      clusterId: null,
    });
  });

  return positioned;
}

/**
 * Spatial-hash O(N) label-aware repulsion pass.
 * Checks only 3x3 neighboring grid cells instead of all O(N^2) pairs.
 */
function runSpatialRepulsion(
  positioned: PositionedRadarNode[],
  minDx: number,
  minDy: number,
  padX: number,
  padY: number,
  width: number,
  height: number,
  iterations: number,
): void {
  const count = positioned.length;
  if (count <= 1) return;

  const invDx = 1 / minDx;
  const invDy = 1 / minDy;
  const grid = new Map<number, number[]>();

  const packCell = (gx: number, gy: number): number => ((gx + 2048) << 12) | (gy + 2048);

  for (let iter = 0; iter < iterations; iter += 1) {
    grid.clear();
    for (let i = 0; i < count; i += 1) {
      const node = positioned[i]!;
      const gx = Math.floor(node.x * invDx);
      const gy = Math.floor(node.y * invDy);
      const key = packCell(gx, gy);
      const bucket = grid.get(key);
      if (bucket) {
        bucket.push(i);
      } else {
        grid.set(key, [i]);
      }
    }

    let movedAny = false;
    for (let i = 0; i < count; i += 1) {
      const a = positioned[i]!;
      const gx = Math.floor(a.x * invDx);
      const gy = Math.floor(a.y * invDy);

      for (let ox = -1; ox <= 1; ox += 1) {
        for (let oy = -1; oy <= 1; oy += 1) {
          const bucket = grid.get(packCell(gx + ox, gy + oy));
          if (!bucket) continue;
          for (let bIdx = 0; bIdx < bucket.length; bIdx += 1) {
            const j = bucket[bIdx]!;
            if (j <= i) continue;
            const b = positioned[j]!;
            const dx = b.x - a.x;
            const dy = b.y - a.y;
            const absDx = Math.abs(dx);
            const absDy = Math.abs(dy);
            if (absDx < minDx && absDy < minDy) {
              movedAny = true;
              const overlapX = (minDx - absDx) * 0.42;
              const overlapY = (minDy - absDy) * 0.48;
              const pushX = dx === 0 ? (i % 2 === 0 ? 1 : -1) : Math.sign(dx);
              const pushY = dy === 0 ? (j % 2 === 0 ? 1 : -1) : Math.sign(dy);
              const aWeight = a.kind === "campaign" ? 0.2 : 0.5;
              const bWeight = b.kind === "campaign" ? 0.2 : 0.5;
              if (absDx * invDx > absDy * invDy) {
                a.x = clamp(a.x - pushX * overlapX * aWeight, padX, width - padX);
                b.x = clamp(b.x + pushX * overlapX * bWeight, padX, width - padX);
              } else {
                a.y = clamp(a.y - pushY * overlapY * aWeight, padY, height - padY);
                b.y = clamp(b.y + pushY * overlapY * bWeight, padY, height - padY);
              }
            }
          }
        }
      }
    }

    if (!movedAny) {
      break;
    }
  }
}

/**
 * Compute cluster-aware coordinates for the threat network.
 * When edges are supplied, IOCs are grouped around their parent campaign hubs with multi-ring
 * outward fans and O(N) spatial-grid separation to eliminate overlaps across 14 to 500+ nodes.
 */
export function computeRadarLayout(
  nodes: RadarNode[],
  width: number,
  height: number,
  edges: ReadonlyArray<RadarEdge> = [],
): PositionedRadarNode[] {
  const campaigns = nodes.filter((n) => n.kind === "campaign");
  const iocs = nodes.filter((n) => n.kind !== "campaign");

  if (edges.length === 0 || campaigns.length === 0) {
    return layoutConcentricFallback(nodes, width, height);
  }

  const campaignIds = new Set(campaigns.map((c) => c.node_id));
  const iocToCampaigns = new Map<string, string[]>();
  const campaignToIocs = new Map<string, string[]>();
  for (const camp of campaigns) {
    campaignToIocs.set(camp.node_id, []);
  }

  for (const edge of edges) {
    if (campaignIds.has(edge.source) && !campaignIds.has(edge.target)) {
      const list = iocToCampaigns.get(edge.target) ?? [];
      if (!list.includes(edge.source)) list.push(edge.source);
      iocToCampaigns.set(edge.target, list);
      const cList = campaignToIocs.get(edge.source) ?? [];
      if (!cList.includes(edge.target)) cList.push(edge.target);
      campaignToIocs.set(edge.source, cList);
    } else if (campaignIds.has(edge.target) && !campaignIds.has(edge.source)) {
      const list = iocToCampaigns.get(edge.source) ?? [];
      if (!list.includes(edge.target)) list.push(edge.target);
      iocToCampaigns.set(edge.source, list);
      const cList = campaignToIocs.get(edge.target) ?? [];
      if (!cList.includes(edge.source)) cList.push(edge.source);
      campaignToIocs.set(edge.target, cList);
    }
  }

  const cx = width / 2;
  const cy = height / 2;
  const padX = Math.max(82, Math.min(130, Math.round(width * 0.08)));
  const padY = Math.max(58, Math.min(96, Math.round(height * 0.09)));

  const hubCoords = new Map<string, { x: number; y: number }>();
  const positioned: PositionedRadarNode[] = [];

  // Place campaign hubs in well-separated cluster anchors (grid for > 4 clusters so 500-node graphs stay clean)
  if (campaigns.length === 1) {
    const only = campaigns[0]!;
    hubCoords.set(only.node_id, { x: cx, y: cy });
    positioned.push({ ...only, x: Math.round(cx), y: Math.round(cy), clusterId: only.node_id });
  } else if (campaigns.length === 2) {
    const anchors = [
      { x: width * 0.31, y: cy },
      { x: width * 0.69, y: cy },
    ];
    campaigns.forEach((camp, idx) => {
      const pt = anchors[idx]!;
      hubCoords.set(camp.node_id, pt);
      positioned.push({ ...camp, x: Math.round(pt.x), y: Math.round(pt.y), clusterId: camp.node_id });
    });
  } else if (campaigns.length === 3) {
    const anchors = [
      { x: width * 0.27, y: height * 0.34 },
      { x: width * 0.73, y: height * 0.34 },
      { x: width * 0.5, y: height * 0.67 },
    ];
    campaigns.forEach((camp, idx) => {
      const pt = anchors[idx]!;
      hubCoords.set(camp.node_id, pt);
      positioned.push({ ...camp, x: Math.round(pt.x), y: Math.round(pt.y), clusterId: camp.node_id });
    });
  } else {
    const cols = Math.ceil(Math.sqrt((campaigns.length * width) / Math.max(1, height)));
    const rows = Math.ceil(campaigns.length / cols);
    const cellW = width / cols;
    const cellH = height / rows;
    campaigns.forEach((camp, idx) => {
      const col = idx % cols;
      const row = Math.floor(idx / cols);
      const rowCount = row === rows - 1 ? campaigns.length - row * cols : cols;
      const rowOffset = rowCount < cols ? ((cols - rowCount) * cellW) / 2 : 0;
      const pt = {
        x: clamp(rowOffset + (col + 0.5) * cellW, padX + 45, width - padX - 45),
        y: clamp((row + 0.5) * cellH, padY + 35, height - padY - 35),
      };
      hubCoords.set(camp.node_id, pt);
      positioned.push({ ...camp, x: Math.round(pt.x), y: Math.round(pt.y), clusterId: camp.node_id });
    });
  }

  const iocById = new Map(iocs.map((n) => [n.node_id, n]));
  const placedIocs = new Set<string>();
  const sharedIocs: RadarNode[] = [];
  const orphanIocs: RadarNode[] = [];

  for (const ioc of iocs) {
    const parents = iocToCampaigns.get(ioc.node_id) ?? [];
    if (parents.length > 1) {
      sharedIocs.push(ioc);
    } else if (parents.length === 0) {
      orphanIocs.push(ioc);
    }
  }

  // Place exclusive IOCs around their parent campaign hub using multi-ring packing when dense
  for (const camp of campaigns) {
    const hub = hubCoords.get(camp.node_id)!;
    const exclusiveIds = (campaignToIocs.get(camp.node_id) ?? []).filter(
      (id) => (iocToCampaigns.get(id)?.length ?? 0) === 1 && iocById.has(id),
    );
    if (exclusiveIds.length === 0) continue;

    if (exclusiveIds.length <= 8 && campaigns.length <= 3) {
      const outwardAngle =
        campaigns.length === 1 ? -Math.PI / 2 : Math.atan2(hub.y - cy, hub.x - cx);
      const span =
        campaigns.length === 1
          ? 2 * Math.PI
          : Math.min(Math.PI * 1.18, Math.max(Math.PI * 0.55, exclusiveIds.length * 0.58));
      const baseRadius = Math.min(width, height) * (exclusiveIds.length > 4 ? 0.24 : 0.22);

      exclusiveIds.forEach((iocId, idx) => {
        const node = iocById.get(iocId);
        if (!node) return;
        const ratio =
          exclusiveIds.length === 1
            ? 0
            : campaigns.length === 1
              ? idx / exclusiveIds.length - 0.5
              : idx / (exclusiveIds.length - 1) - 0.5;
        const angle = outwardAngle + ratio * span;
        const r = baseRadius + (exclusiveIds.length > 4 && idx % 2 === 1 ? 26 : 0);
        positioned.push({
          ...node,
          x: Math.round(clamp(hub.x + r * Math.cos(angle), padX, width - padX)),
          y: Math.round(clamp(hub.y + r * Math.sin(angle), padY, height - padY)),
          clusterId: camp.node_id,
        });
        placedIocs.add(iocId);
      });
    } else {
      // Multi-ring spiral around cluster anchor for medium/large clusters (50–500+ nodes)
      let cursor = 0;
      let ring = 0;
      while (cursor < exclusiveIds.length) {
        const radiusX = 112 + ring * 94;
        const radiusY = 82 + ring * 68;
        const ringCapacity = Math.max(6, Math.floor((2 * Math.PI * ((radiusX + radiusY) / 2)) / 106));
        const sliceCount = Math.min(ringCapacity, exclusiveIds.length - cursor);
        const phase = ring * 0.45;
        for (let k = 0; k < sliceCount; k += 1) {
          const iocId = exclusiveIds[cursor + k]!;
          const node = iocById.get(iocId);
          if (!node) continue;
          const angle = phase + (2 * Math.PI * k) / sliceCount;
          positioned.push({
            ...node,
            x: Math.round(clamp(hub.x + radiusX * Math.cos(angle), padX, width - padX)),
            y: Math.round(clamp(hub.y + radiusY * Math.sin(angle), padY, height - padY)),
            clusterId: camp.node_id,
          });
          placedIocs.add(iocId);
        }
        cursor += sliceCount;
        ring += 1;
      }
    }
  }

  // Place shared IOCs near the midpoint between their parent hubs
  sharedIocs.forEach((node, idx) => {
    if (placedIocs.has(node.node_id)) return;
    const parents = (iocToCampaigns.get(node.node_id) ?? [])
      .map((cid) => hubCoords.get(cid))
      .filter((p): p is { x: number; y: number } => Boolean(p));
    const avgX =
      parents.length > 0 ? parents.reduce((s, p) => s + p.x, 0) / parents.length : cx;
    const avgY =
      parents.length > 0 ? parents.reduce((s, p) => s + p.y, 0) / parents.length : cy;
    const ringAngle = (idx * 2.399963) % (2 * Math.PI);
    const ringDist = 28 + Math.floor(idx / 6) * 32;
    positioned.push({
      ...node,
      x: Math.round(clamp(avgX + ringDist * Math.cos(ringAngle), padX, width - padX)),
      y: Math.round(clamp(avgY + ringDist * Math.sin(ringAngle), padY, height - padY)),
      clusterId: null,
    });
    placedIocs.add(node.node_id);
  });

  // Place orphan IOCs neatly along bottom edge without colliding with campaign clusters
  orphanIocs.forEach((node, idx) => {
    if (placedIocs.has(node.node_id)) return;
    const cols = Math.max(1, orphanIocs.length);
    const usableW = Math.max(120, width - padX * 2);
    const x = cols === 1 ? cx : padX + (usableW * idx) / Math.max(1, cols - 1);
    const y = height - padY + (idx % 2 === 0 ? 0 : -24);
    positioned.push({
      ...node,
      x: Math.round(clamp(x, padX, width - padX)),
      y: Math.round(clamp(y, padY, height - padY)),
      clusterId: null,
    });
  });

  // Fast O(N) spatial-grid separation pass
  const dense = positioned.length > 80;
  const minDx = dense ? 96 : 114;
  const minDy = dense ? 56 : 56;
  const iters = positioned.length > 200 ? 24 : 24;
  runSpatialRepulsion(positioned, minDx, minDy, padX, padY, width, height, iters);

  return positioned.map((n) => ({
    ...n,
    x: Math.round(n.x),
    y: Math.round(n.y),
  }));
}

const FALLBACK_HASH_LABEL_RE = /^(dom|stk|tel|ioc)_([0-9a-f]{6})\*{4}$/i;

/**
 * Format masked IOC labels cleanly so fallback internal hash stubs (e.g. dom_a1b2c3****)
 * render as readable distinct identifiers while preserving masked PII values (e.g. 99****66).
 */
export function formatMaskedIoc(maskedValue: string, fallbackId?: string): string {
  const raw = maskedValue.trim();
  const hashStub = FALLBACK_HASH_LABEL_RE.exec(raw);
  if (hashStub) {
    const prefix = hashStub[1]?.toLowerCase();
    const shortId = (hashStub[2] ?? "").toUpperCase();
    if (prefix === "dom") return `Tên miền #${shortId}`;
    if (prefix === "stk") return `STK #${shortId}`;
    if (prefix === "tel") return `SĐT #${shortId}`;
    return `Dấu hiệu #${shortId}`;
  }
  return raw || (fallbackId ? `#${fallbackId.slice(0, 6).toUpperCase()}` : "—");
}

export function formatNodeDisplayLabel(
  node: Pick<RadarNode, "kind" | "label" | "node_id">,
): string {
  return formatMaskedIoc(node.label, node.node_id);
}

export function formatRadarTimestamp(iso?: string | null): string {
  if (!iso) return "—";
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return "—";
  const d = new Date(ms);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  return `${hh}:${mm} · ${dd}/${mo}`;
}

export function computeRuleStatus(
  expiresAt?: string | null,
  nowMs: number = Date.now(),
): { code: "active" | "expiring" | "expired"; label: string } {
  if (!expiresAt) {
    return { code: "active", label: "Đang áp dụng" };
  }
  const expMs = Date.parse(expiresAt);
  if (Number.isNaN(expMs)) {
    return { code: "active", label: "Đang áp dụng" };
  }
  const diff = expMs - nowMs;
  if (diff <= 0) {
    return { code: "expired", label: "Đã hết hạn" };
  }
  if (diff <= 5 * 60_000) {
    return { code: "expiring", label: "Sắp hết hạn" };
  }
  return { code: "active", label: "Đang áp dụng" };
}

export function formatRemainingTtl(expiresAt?: string | null, nowMs: number = Date.now()): string {
  if (!expiresAt) {
    return "Hiệu lực mặc định";
  }
  const targetMs = Date.parse(expiresAt);
  if (Number.isNaN(targetMs)) {
    return "Hiệu lực mặc định";
  }
  const diffMs = targetMs - nowMs;
  if (diffMs <= 0) {
    return "Đã hết hạn";
  }
  const mins = Math.ceil(diffMs / 60_000);
  if (mins >= 120) {
    const hrs = Math.floor(mins / 60);
    const remMins = mins % 60;
    return remMins > 0 ? `Còn ${hrs}g ${remMins}p` : `Còn ${hrs} giờ`;
  }
  return `Còn ${mins} phút`;
}

/**
 * Compute delay (ms) until the next active block-rule expiry or 30s countdown tick,
 * or null when there are no active rules to monitor.
 */
export function getNextRuleExpiryDelayMs(
  rules: ReadonlyArray<{ expires_at?: string | null }>,
  nowMs: number = Date.now(),
): number | null {
  if (rules.length === 0) {
    return null;
  }

  let earliestTarget: number | null = null;
  for (const r of rules) {
    if (!r.expires_at) continue;
    const parsed = Date.parse(r.expires_at);
    if (!Number.isNaN(parsed)) {
      if (earliestTarget === null || parsed < earliestTarget) {
        earliestTarget = parsed;
      }
    }
  }

  if (earliestTarget === null) {
    return 30_000;
  }
  const diff = earliestTarget - nowMs;
  if (diff <= 0) {
    return 5_000;
  }
  return Math.min(diff + 250, 30_000);
}
