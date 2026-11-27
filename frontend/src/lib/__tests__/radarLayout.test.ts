import assert from "node:assert/strict";
import test from "node:test";

import {
  buildGraphTopologyKey,
  clampFloatingTooltip,
  computeFitViewport,
  computeOptimalGraphExtent,
  computeRadarLayout,
  computeRuleStatus,
  formatNodeDisplayLabel,
  formatRadarTimestamp,
  formatRemainingTtl,
  getNextRuleExpiryDelayMs,
  zoomViewportAroundPoint,
} from "../radarLayout.ts";
import type { RadarEdge, RadarNode } from "../types.ts";

test("computeRadarLayout places campaign hubs inside inner ring and IOC nodes within SVG bounds", () => {
  const sampleNodes: RadarNode[] = [
    {
      node_id: "camp_1",
      kind: "campaign",
      label: "Mạo danh NAPAS",
      hit_count: 12,
      risk_level: "CRITICAL_SCAM",
      blocked: false,
    },
    {
      node_id: "ioc_1",
      kind: "bank_account",
      label: "1903****8899",
      hit_count: 8,
      risk_level: "CRITICAL_SCAM",
      blocked: true,
    },
    {
      node_id: "ioc_2",
      kind: "domain",
      label: "na***op.top",
      hit_count: 6,
      risk_level: "HIGH_RISK",
      blocked: false,
    },
  ];

  const positioned = computeRadarLayout(sampleNodes, 760, 420);
  assert.equal(positioned.length, 3);
  for (const node of positioned) {
    assert.ok(node.x >= 40 && node.x <= 720, `x out of bounds: ${node.x}`);
    assert.ok(node.y >= 40 && node.y <= 380, `y out of bounds: ${node.y}`);
  }
});

test("formatRemainingTtl formats active countdown and expired timestamps", () => {
  const baseMs = Date.parse("2026-11-26T02:00:00Z");
  assert.equal(formatRemainingTtl("2026-11-26T02:25:00Z", baseMs), "Còn 25 phút");
  assert.equal(formatRemainingTtl("2026-11-26T01:59:00Z", baseMs), "Đã hết hạn");
  assert.equal(formatRemainingTtl(null, baseMs), "Hiệu lực mặc định");
});

test("getNextRuleExpiryDelayMs schedules refresh at earliest rule expiry or 30s tick", () => {
  const nowMs = Date.parse("2026-11-26T02:00:00Z");
  assert.equal(getNextRuleExpiryDelayMs([], nowMs), null);
  assert.equal(
    getNextRuleExpiryDelayMs([{ expires_at: "2026-11-26T02:00:05Z" }], nowMs),
    5250,
  );
  assert.equal(
    getNextRuleExpiryDelayMs([{ expires_at: "2026-11-26T01:59:59Z" }], nowMs),
    5_000,
  );
  assert.equal(
    getNextRuleExpiryDelayMs([{ expires_at: "2026-11-26T02:20:00Z" }], nowMs),
    30_000,
  );
});

test("computeRadarLayout staggers high IOC counts onto two concentric rings within SVG bounds", () => {
  const manyIocs: RadarNode[] = Array.from({ length: 24 }, (_, idx) => ({
    node_id: `ioc_${idx}`,
    kind: idx % 2 === 0 ? "bank_account" : "domain",
    label: `19****${String(idx).padStart(2, "0")}`,
    hit_count: idx + 1,
    risk_level: "HIGH_RISK",
    blocked: false,
  }));
  const positioned = computeRadarLayout(manyIocs, 760, 420);
  assert.equal(positioned.length, 24);
  const radii = new Set(
    positioned.map((n) => Math.round(Math.hypot((n.x - 380) / 760, (n.y - 210) / 420) * 10)),
  );
  assert.ok(radii.size >= 2, "Expected at least two staggered concentric rings for 24 IOCs");
});

test("computeRadarLayout groups IOCs around parent campaign clusters when edges are provided", () => {
  const nodes: RadarNode[] = [
    {
      node_id: "camp_a",
      kind: "campaign",
      label: "Giả mạo NAPAS",
      hit_count: 7,
      risk_level: "CRITICAL_SCAM",
      blocked: false,
    },
    {
      node_id: "camp_b",
      kind: "campaign",
      label: "Giả danh công an",
      hit_count: 5,
      risk_level: "CRITICAL_SCAM",
      blocked: false,
    },
    {
      node_id: "ioc_a1",
      kind: "domain",
      label: "na****.top",
      hit_count: 7,
      risk_level: "HIGH_RISK",
      blocked: false,
    },
    {
      node_id: "ioc_b1",
      kind: "bank_account",
      label: "99****66",
      hit_count: 5,
      risk_level: "HIGH_RISK",
      blocked: false,
    },
  ];
  const edges: RadarEdge[] = [
    { source: "camp_a", target: "ioc_a1", relation: "primary_ioc" },
    { source: "camp_b", target: "ioc_b1", relation: "primary_ioc" },
  ];

  const laid = computeRadarLayout(nodes, 860, 480, edges);
  const byId = new Map(laid.map((n) => [n.node_id, n]));
  const campA = byId.get("camp_a")!;
  const campB = byId.get("camp_b")!;
  const iocA1 = byId.get("ioc_a1")!;
  const iocB1 = byId.get("ioc_b1")!;

  const distA1ToA = Math.hypot(iocA1.x - campA.x, iocA1.y - campA.y);
  const distA1ToB = Math.hypot(iocA1.x - campB.x, iocA1.y - campB.y);
  const distB1ToB = Math.hypot(iocB1.x - campB.x, iocB1.y - campB.y);
  const distB1ToA = Math.hypot(iocB1.x - campA.x, iocB1.y - campA.y);

  assert.ok(distA1ToA < distA1ToB, "ioc_a1 should cluster closer to camp_a than camp_b");
  assert.ok(distB1ToB < distB1ToA, "ioc_b1 should cluster closer to camp_b than camp_a");
});

test("formatNodeDisplayLabel, computeRuleStatus, and formatRadarTimestamp format operational metadata", () => {
  assert.equal(
    formatNodeDisplayLabel({ kind: "domain", label: "dom_a1b2c3****", node_id: "a1b2c3" }),
    "Tên miền #A1B2C3",
  );
  assert.equal(
    formatNodeDisplayLabel({ kind: "bank_account", label: "99****66", node_id: "deadbeef" }),
    "99****66",
  );

  const nowMs = Date.parse("2026-11-26T10:00:00Z");
  assert.equal(computeRuleStatus("2026-11-26T10:25:00Z", nowMs).code, "active");
  assert.equal(computeRuleStatus("2026-11-26T10:03:00Z", nowMs).code, "expiring");
  assert.equal(computeRuleStatus("2026-11-26T09:59:00Z", nowMs).code, "expired");
  assert.equal(formatRadarTimestamp(null), "—");
  assert.match(formatRadarTimestamp("2026-11-26T10:00:00Z"), /^\d{2}:\d{2} · \d{2}\/\d{2}$/);
});

test("topology key stays stable across block-status changes and viewport helpers preserve anchor", () => {
  const nodesA: RadarNode[] = [
    {
      node_id: "camp_1",
      kind: "campaign",
      label: "Chiến dịch A",
      hit_count: 5,
      risk_level: "CRITICAL_SCAM",
      blocked: false,
    },
    {
      node_id: "ioc_1",
      kind: "domain",
      label: "na****.top",
      hit_count: 4,
      risk_level: "HIGH_RISK",
      blocked: false,
    },
  ];
  const nodesB: RadarNode[] = [
    { ...nodesA[0]!, blocked: true, hit_count: 9 },
    { ...nodesA[1]!, blocked: true, hit_count: 8 },
  ];
  const edges: RadarEdge[] = [{ source: "camp_1", target: "ioc_1", relation: "primary_ioc" }];
  assert.equal(buildGraphTopologyKey(nodesA, edges), buildGraphTopologyKey(nodesB, edges));

  const start = { scale: 1, x: 20, y: -15 };
  const anchorX = 320;
  const anchorY = 180;
  const worldBeforeX = (anchorX - start.x) / start.scale;
  const worldBeforeY = (anchorY - start.y) / start.scale;
  const zoomed = zoomViewportAroundPoint(start, 1.8, anchorX, anchorY, 0.2, 2.8);
  const worldAfterX = (anchorX - zoomed.x) / zoomed.scale;
  const worldAfterY = (anchorY - zoomed.y) / zoomed.scale;
  assert.ok(Math.abs(worldAfterX - worldBeforeX) < 1e-6);
  assert.ok(Math.abs(worldAfterY - worldBeforeY) < 1e-6);

  // Edge collision clamping keeps floating tooltip strictly inside container bounds
  const nearTopLeft = clampFloatingTooltip(12, 10, 260, 72, 680, 420);
  assert.equal(nearTopLeft.placement, "bottom");
  assert.ok(nearTopLeft.left >= 10 && nearTopLeft.top >= 10);
  const nearBottomRight = clampFloatingTooltip(670, 415, 260, 72, 680, 420);
  assert.ok(nearBottomRight.left + 260 <= 670);
  assert.ok(nearBottomRight.top + 72 <= 410);
});

test("adaptive extent + spatial repulsion keeps 500-node graph non-overlapping and fits viewBox", () => {
  const numCampaigns = 12;
  const nodes: RadarNode[] = [];
  const edges: RadarEdge[] = [];
  for (let c = 0; c < numCampaigns; c += 1) {
    nodes.push({
      node_id: `c_${c}`,
      kind: "campaign",
      label: `Chiến dịch ${c}`,
      hit_count: 6,
      risk_level: "CRITICAL_SCAM",
      blocked: c === 0,
    });
  }
  for (let i = 0; i < 488; i += 1) {
    const id = `i_${i}`;
    nodes.push({
      node_id: id,
      kind: i % 3 === 0 ? "bank_account" : i % 3 === 1 ? "domain" : "phone",
      label: `19****${String(i % 100).padStart(2, "0")}`,
      hit_count: 3,
      risk_level: "HIGH_RISK",
      blocked: false,
    });
    edges.push({ source: `c_${i % numCampaigns}`, target: id, relation: "associated_ioc" });
  }

  const extent = computeOptimalGraphExtent(nodes.length, 860, 480);
  assert.ok(extent.width > 860 && extent.height > 480);

  const laid = computeRadarLayout(nodes, extent.width, extent.height, edges);
  assert.equal(laid.length, 500);

  const fit = computeFitViewport(laid, 860, 480, 0.2, 1.05, 48);
  assert.ok(fit.scale >= 0.2 && fit.scale <= 1.05);

  // Verify near-zero tight node center collisions (<36x30px)
  let tightOverlaps = 0;
  for (let i = 0; i < laid.length; i += 1) {
    for (let j = i + 1; j < laid.length; j += 1) {
      if (Math.abs(laid[i]!.x - laid[j]!.x) < 36 && Math.abs(laid[i]!.y - laid[j]!.y) < 30) {
        tightOverlaps += 1;
      }
    }
  }
  assert.ok(tightOverlaps < 10, `Expected minimal overlaps at 500 nodes, got ${tightOverlaps}`);
});
