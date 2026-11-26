import type { RadarEdge, RadarNode } from "./types";

export interface PositionedRadarNode extends RadarNode {
  x: number;
  y: number;
  clusterId?: string | null;
}

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val));
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
 * Compute cluster-aware coordinates for the threat network.
 * When edges are supplied, IOCs are grouped around their parent campaign hubs with outward fans
 * and deterministic label-overlap separation to minimize edge crossings and label clipping.
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
  const padX = Math.max(82, Math.round(width * 0.11));
  const padY = Math.max(58, Math.round(height * 0.13));

  const hubCoords = new Map<string, { x: number; y: number }>();
  const positioned: PositionedRadarNode[] = [];

  // Place campaign hubs in well-separated cluster anchors
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
    const rx = width * 0.27;
    const ry = height * 0.25;
    campaigns.forEach((camp, idx) => {
      const angle = (2 * Math.PI * idx) / campaigns.length - Math.PI / 2;
      const pt = {
        x: clamp(cx + rx * Math.cos(angle), padX + 45, width - padX - 45),
        y: clamp(cy + ry * Math.sin(angle), padY + 35, height - padY - 35),
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

  // Place exclusive IOCs in clean outward arcs around their parent campaign hub
  for (const camp of campaigns) {
    const hub = hubCoords.get(camp.node_id)!;
    const exclusiveIds = (campaignToIocs.get(camp.node_id) ?? []).filter(
      (id) => (iocToCampaigns.get(id)?.length ?? 0) === 1 && iocById.has(id),
    );
    if (exclusiveIds.length === 0) continue;

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
    const offset = (idx - (sharedIocs.length - 1) / 2) * 34;
    positioned.push({
      ...node,
      x: Math.round(clamp(avgX + offset, padX, width - padX)),
      y: Math.round(clamp(avgY + (idx % 2 === 0 ? -18 : 18), padY, height - padY)),
      clusterId: null,
    });
    placedIocs.add(node.node_id);
  });

  // Place orphan IOCs neatly along bottom edge without colliding with campaign clusters
  orphanIocs.forEach((node, idx) => {
    if (placedIocs.has(node.node_id)) return;
    const cols = Math.max(1, orphanIocs.length);
    const usableW = Math.max(120, width - padX * 2);
    const x =
      cols === 1 ? cx : padX + (usableW * idx) / Math.max(1, cols - 1);
    const y = height - padY + (idx % 2 === 0 ? 0 : -24);
    positioned.push({
      ...node,
      x: Math.round(clamp(x, padX, width - padX)),
      y: Math.round(clamp(y, padY, height - padY)),
      clusterId: null,
    });
  });

  // Deterministic label-aware repulsion pass to eliminate overlapping nodes/labels
  const minDx = 114;
  const minDy = 56;
  for (let iter = 0; iter < 24; iter += 1) {
    for (let i = 0; i < positioned.length; i += 1) {
      for (let j = i + 1; j < positioned.length; j += 1) {
        const a = positioned[i]!;
        const b = positioned[j]!;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const absDx = Math.abs(dx);
        const absDy = Math.abs(dy);
        if (absDx < minDx && absDy < minDy) {
          const overlapX = (minDx - absDx) * 0.35;
          const overlapY = (minDy - absDy) * 0.45;
          const pushX = dx === 0 ? (i % 2 === 0 ? 1 : -1) : Math.sign(dx);
          const pushY = dy === 0 ? (j % 2 === 0 ? 1 : -1) : Math.sign(dy);
          const aWeight = a.kind === "campaign" ? 0.2 : 0.5;
          const bWeight = b.kind === "campaign" ? 0.2 : 0.5;
          if (absDx / minDx > absDy / minDy) {
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
