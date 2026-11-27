import assert from "node:assert/strict";
import test from "node:test";

import {
  countDurationMs,
  easeOutCubic,
  interpolateCount,
  spotlightPosition,
  staggerDelaysMs,
} from "../motion/motionMath.ts";

test("easeOutCubic clamps and hits endpoints", () => {
  assert.equal(easeOutCubic(-1), 0);
  assert.equal(easeOutCubic(0), 0);
  assert.equal(easeOutCubic(1), 1);
  assert.equal(easeOutCubic(2), 1);
  assert.ok(easeOutCubic(0.5) > 0.5);
});

test("interpolateCount is integer, monotonic, exact at ends, supports retarget downwards", () => {
  assert.equal(interpolateCount(0, 93, 0), 0);
  assert.equal(interpolateCount(0, 93, 1), 93);
  assert.equal(interpolateCount(93, 12, 1), 12);
  assert.equal(interpolateCount(93, 12, 0), 93);
  assert.ok(Number.isInteger(interpolateCount(0, 93, 0.37)));
  assert.ok(interpolateCount(0, 93, 0.3) <= interpolateCount(0, 93, 0.6));
  assert.equal(interpolateCount(0, 93, -5), 0);
  assert.equal(interpolateCount(0, 93, 5), 93);
});

test("countDurationMs bounded 240..600", () => {
  assert.equal(countDurationMs(5, 5), 240);
  assert.equal(countDurationMs(0, 1000), 600);
  assert.equal(countDurationMs(0, 50), 400);
});

test("staggerDelaysMs compresses to budget", () => {
  assert.deepEqual(staggerDelaysMs(0, 40, 200), []);
  assert.deepEqual(staggerDelaysMs(1, 40, 200), [0]);
  assert.deepEqual(staggerDelaysMs(3, 40, 200), [0, 40, 80]);
  assert.deepEqual(staggerDelaysMs(11, 40, 200), [0, 20, 40, 60, 80, 100, 120, 140, 160, 180, 200]);
});

test("spotlightPosition clamps and handles empty rect", () => {
  const r = { left: 100, top: 50, width: 200, height: 100 };
  assert.deepEqual(spotlightPosition(r, 200, 100), { xPct: 50, yPct: 50 });
  assert.deepEqual(spotlightPosition(r, 0, 999), { xPct: 0, yPct: 100 });
  assert.deepEqual(spotlightPosition({ left: 0, top: 0, width: 0, height: 0 }, 5, 5), {
    xPct: 50,
    yPct: 50,
  });
});
