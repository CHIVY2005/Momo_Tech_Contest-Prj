import assert from "node:assert/strict";
import test from "node:test";

import {
  computeRadarLayout,
  formatRemainingTtl,
  getNextRuleExpiryDelayMs,
} from "../radarLayout.ts";
import type { RadarNode } from "../types.ts";

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
