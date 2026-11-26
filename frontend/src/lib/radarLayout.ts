import type { RadarNode } from "./types";

export interface PositionedRadarNode extends RadarNode {
  x: number;
  y: number;
}

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val));
}

export function computeRadarLayout(
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
      positioned.push({ ...node, x: Math.round(cx), y: Math.round(cy) });
      return;
    }
    const angle = (2 * Math.PI * idx) / campaigns.length - Math.PI / 2;
    const rx = width * 0.19;
    const ry = height * 0.21;
    positioned.push({
      ...node,
      x: Math.round(clamp(cx + rx * Math.cos(angle), 52, width - 52)),
      y: Math.round(clamp(cy + ry * Math.sin(angle), 48, height - 48)),
    });
  });

  iocs.forEach((node, idx) => {
    const count = Math.max(1, iocs.length);
    const angle = (2 * Math.PI * idx) / count - Math.PI / 3;
    const rx = width * 0.39;
    const ry = height * 0.37;
    positioned.push({
      ...node,
      x: Math.round(clamp(cx + rx * Math.cos(angle), 52, width - 52)),
      y: Math.round(clamp(cy + ry * Math.sin(angle), 48, height - 48)),
    });
  });

  return positioned;
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
    return 250;
  }
  return Math.min(diff + 250, 30_000);
}
