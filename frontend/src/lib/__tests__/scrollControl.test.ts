import assert from "node:assert/strict";
import test from "node:test";

import {
  ANCHOR_OFFSET_PX,
  createScrollLockCounter,
  parseSameDocumentHash,
  shouldAutoScrollIntoView,
  shouldEnableSmoothScroll,
} from "../motion/scrollControl.ts";

test("ANCHOR_OFFSET_PX matches sticky header scroll-margin", () => {
  assert.equal(ANCHOR_OFFSET_PX, 84);
});

test("shouldEnableSmoothScroll", () => {
  assert.equal(shouldEnableSmoothScroll({ reducedMotion: false, hasWindow: true }), true);
  assert.equal(shouldEnableSmoothScroll({ reducedMotion: true, hasWindow: true }), false);
  assert.equal(shouldEnableSmoothScroll({ reducedMotion: false, hasWindow: false }), false);
});

test("parseSameDocumentHash accepts safe same-page anchors only", () => {
  assert.equal(parseSameDocumentHash("#thu-vien-giay-phep", "/technical"), "thu-vien-giay-phep");
  assert.equal(parseSameDocumentHash("/technical#main-content", "/technical"), "main-content");
  assert.equal(parseSameDocumentHash("/privacy#x", "/technical"), null);
  assert.equal(parseSameDocumentHash("#", "/"), null);
  assert.equal(parseSameDocumentHash("", "/"), null);
  assert.equal(parseSameDocumentHash(null, "/"), null);
  assert.equal(parseSameDocumentHash('#a"],b', "/"), null);
  assert.equal(parseSameDocumentHash("https://evil.example/#a", "/"), null);
  assert.equal(parseSameDocumentHash("//evil.example/#a", "/"), null);
  assert.equal(parseSameDocumentHash("#9abc", "/"), null);
  assert.equal(parseSameDocumentHash(`#a${"b".repeat(64)}`, "/"), null);
});

test("shouldAutoScrollIntoView", () => {
  const base = { viewportHeight: 800, headerHeight: 84, alreadyScrolledForCase: false };
  assert.equal(shouldAutoScrollIntoView({ ...base, targetTop: 300 }), false);
  assert.equal(shouldAutoScrollIntoView({ ...base, targetTop: 700 }), true);
  assert.equal(shouldAutoScrollIntoView({ ...base, targetTop: 20 }), true);
  assert.equal(
    shouldAutoScrollIntoView({ ...base, targetTop: 700, alreadyScrolledForCase: true }),
    false,
  );
});

test("createScrollLockCounter is ref-counted and release is idempotent", () => {
  const calls: boolean[] = [];
  const c = createScrollLockCounter((l) => calls.push(l));
  const r1 = c.acquire();
  const r2 = c.acquire();
  r1();
  r1();
  assert.deepEqual(calls, [true]);
  r2();
  assert.deepEqual(calls, [true, false]);
  const r3 = c.acquire();
  assert.deepEqual(calls, [true, false, true]);
  r3();
  assert.deepEqual(calls, [true, false, true, false]);
});
