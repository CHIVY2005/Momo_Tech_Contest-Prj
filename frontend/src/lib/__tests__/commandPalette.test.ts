import assert from "node:assert/strict";
import test from "node:test";

import { findRegenerableUserTurn } from "../assistantSession.ts";
import {
  buildPaletteCommands,
  COMMAND_PALETTE_PLACEHOLDER,
  computeMinimalScrollTop,
  filterPaletteCommands,
  getNextActiveCommandId,
  groupPaletteCommands,
  hasPointerMoved,
  normalizeVietnameseSearch,
  type PaletteCommand,
  resolveActiveCommandId,
} from "../commandPalette.ts";

test("normalizeVietnameseSearch handles Vietnamese diacritics and đ/Đ cleanly", () => {
  assert.equal(normalizeVietnameseSearch("Giám Sát Gian Lận"), "giam sat gian lan");
  assert.equal(normalizeVietnameseSearch("Đường dẫn & Sơ đồ liên kết"), "duong dan & so do lien ket");
});

test("buildPaletteCommands omits workspace actions when no active case and never leaks PII", () => {
  const noCase = buildPaletteCommands({
    hasActiveCase: false,
    maskedCaseId: null,
    pathname: "/",
  });
  assert.equal(noCase.some((c) => c.group === "workspace"), false);
  assert.ok(noCase.some((c) => c.id === "nav-radar"));
  assert.ok(noCase.some((c) => c.id === "nav-technical"));
  assert.ok(noCase.some((c) => c.id === "nav-privacy"));

  const withCase = buildPaletteCommands({
    hasActiveCase: true,
    maskedCaseId: "vs_1234…9999",
    pathname: "/",
  });
  assert.ok(withCase.some((c) => c.id === "open-assistant" && c.label.includes("vs_1234…9999")));
  assert.ok(withCase.some((c) => c.id === "ws-xai"));
  assert.ok(withCase.some((c) => c.id === "ws-graph"));
});

test("filterPaletteCommands matches Vietnamese queries without accents", () => {
  const commands = buildPaletteCommands({
    hasActiveCase: true,
    maskedCaseId: "vs_demo",
    pathname: "/",
  });
  const radarHits = filterPaletteCommands(commands, "giam sat");
  assert.ok(radarHits.some((c) => c.id === "nav-radar"));

  const graphHits = filterPaletteCommands(commands, "so do lien ket");
  assert.ok(graphHits.some((c) => c.id === "ws-graph"));

  const receiptHits = filterPaletteCommands(commands, "bien lai soundbox");
  assert.ok(receiptHits.some((c) => c.id === "safety-receipt-rule"));
});

test("findRegenerableUserTurn allows regenerating completed text turns and skips attachment/streaming/errored turns", () => {
  const textTurn = [
    { id: "u1", role: "user" as const, content: "Giải thích rủi ro của đường dẫn này?" },
    { id: "a1", role: "assistant" as const, content: "Đường dẫn có dấu hiệu giả mạo." },
  ];
  assert.deepEqual(findRegenerableUserTurn(textTurn, "a1"), {
    userMsgId: "u1",
    assistantMsgId: "a1",
    prompt: "Giải thích rủi ro của đường dẫn này?",
  });

  const attachmentTurn = [
    { id: "u2", role: "user" as const, content: "Kiểm tra ảnh", attachmentLabel: "receipt.png" },
    { id: "a2", role: "assistant" as const, content: "Đã kiểm tra." },
  ];
  assert.equal(findRegenerableUserTurn(attachmentTurn, "a2"), null);

  const streamingTurn = [
    { id: "u3", role: "user" as const, content: "Hỏi tiếp" },
    { id: "a3", role: "assistant" as const, content: "Đang...", isStreaming: true },
  ];
  assert.equal(findRegenerableUserTurn(streamingTurn, "a3"), null);
});

function makeCmd(
  id: string,
  group: PaletteCommand["group"],
  disabled = false,
): PaletteCommand {
  return {
    id,
    label: `Command ${id}`,
    description: `Description ${id}`,
    group,
    keywords: [id],
    disabled,
    action: { type: "navigate", href: "/" },
  };
}

test("COMMAND_PALETTE_PLACEHOLDER uses concise Vietnamese copy without overflow", () => {
  assert.equal(COMMAND_PALETTE_PLACEHOLDER, "Tìm kiếm lệnh hoặc chức năng...");
});

test("groupPaletteCommands orders items by canonical group sequence and omits empty groups", () => {
  const cmds = [
    makeCmd("s1", "safety"),
    makeCmd("n1", "navigation"),
    makeCmd("q1", "quick"),
    makeCmd("n2", "navigation"),
  ];
  const { groups, flat } = groupPaletteCommands(cmds);
  assert.deepEqual(
    groups.map((g) => g.group),
    ["quick", "navigation", "safety"],
  );
  assert.deepEqual(
    flat.map((c) => c.id),
    ["q1", "n1", "n2", "s1"],
  );
});

test("resolveActiveCommandId auto-selects first enabled command and resets cleanly when filtered out or disabled", () => {
  const cmds = [
    makeCmd("d1", "quick", true),
    makeCmd("a1", "quick", false),
    makeCmd("a2", "navigation", false),
  ];
  assert.equal(resolveActiveCommandId(cmds, null), "a1");
  assert.equal(resolveActiveCommandId(cmds, "a2"), "a2");
  assert.equal(resolveActiveCommandId(cmds, "d1"), "a1");
  assert.equal(resolveActiveCommandId(cmds, "missing-id"), "a1");
  assert.equal(resolveActiveCommandId([makeCmd("only-disabled", "quick", true)], null), null);
  assert.equal(resolveActiveCommandId([], "a1"), null);
});

test("getNextActiveCommandId navigates across groups, skips disabled items, wraps cleanly, and supports Home/End", () => {
  const cmds = [
    makeCmd("d0", "quick", true),
    makeCmd("q1", "quick", false),
    makeCmd("d1", "workspace", true),
    makeCmd("w1", "workspace", false),
    makeCmd("s1", "safety", false),
    makeCmd("d2", "safety", true),
  ];

  // ArrowDown forward across groups skipping disabled items + wrap
  assert.equal(getNextActiveCommandId(cmds, "q1", "next"), "w1");
  assert.equal(getNextActiveCommandId(cmds, "w1", "next"), "s1");
  assert.equal(getNextActiveCommandId(cmds, "s1", "next"), "q1");

  // ArrowUp backward skipping disabled items + wrap
  assert.equal(getNextActiveCommandId(cmds, "s1", "prev"), "w1");
  assert.equal(getNextActiveCommandId(cmds, "w1", "prev"), "q1");
  assert.equal(getNextActiveCommandId(cmds, "q1", "prev"), "s1");

  // Home and End select first/last enabled item
  assert.equal(getNextActiveCommandId(cmds, "w1", "first"), "q1");
  assert.equal(getNextActiveCommandId(cmds, "w1", "last"), "s1");

  // Empty / all-disabled lists return null
  assert.equal(getNextActiveCommandId([makeCmd("only-d", "quick", true)], null, "next"), null);
  assert.equal(getNextActiveCommandId([], null, "prev"), null);
});

test("computeMinimalScrollTop scrolls only the minimum required distance inside the list container", () => {
  const base = {
    containerTop: 100,
    containerBottom: 400, // 300px viewport
    scrollHeight: 760,
    clientHeight: 300, // maxScroll = 460
    paddingTop: 8,
    paddingBottom: 8,
  };

  // Already fully visible inside [108, 392] -> zero scroll change
  assert.equal(
    computeMinimalScrollTop({ ...base, scrollTop: 50, itemTop: 120, itemBottom: 172 }),
    50,
  );

  // Item extends 24px past bottom visible edge (392) -> scroll down by exactly 24px
  assert.equal(
    computeMinimalScrollTop({ ...base, scrollTop: 0, itemTop: 364, itemBottom: 416 }),
    24,
  );

  // Item extends 18px above top visible edge (108) -> scroll up by exactly 18px
  assert.equal(
    computeMinimalScrollTop({ ...base, scrollTop: 120, itemTop: 90, itemBottom: 142 }),
    102,
  );

  // Sub-pixel fractional overflow (125%/150% DPI scaling) rounds outward so item is never clipped
  assert.equal(
    computeMinimalScrollTop({ ...base, scrollTop: 10, itemTop: 340.6, itemBottom: 392.4 }),
    11,
  );
  assert.equal(
    computeMinimalScrollTop({ ...base, scrollTop: 40, itemTop: 107.4, itemBottom: 159.4 }),
    39,
  );

  // Snap to top when returning to first item reveals top group heading
  assert.equal(
    computeMinimalScrollTop({ ...base, scrollTop: 420, itemTop: 108, itemBottom: 160, snapToTop: true }),
    0,
  );

  // Clamps to maxScroll and handles non-overflowing lists
  assert.equal(
    computeMinimalScrollTop({ ...base, scrollTop: 450, itemTop: 400, itemBottom: 500 }),
    460,
  );
  assert.equal(
    computeMinimalScrollTop({
      ...base,
      scrollHeight: 280,
      clientHeight: 300,
      scrollTop: 0,
      itemTop: 240,
      itemBottom: 292,
    }),
    0,
  );
});

test("hasPointerMoved ignores stationary pointer events during auto-scroll and detects genuine movement", () => {
  assert.equal(hasPointerMoved({ x: 320, y: 240 }, { x: 320, y: 240 }), false);
  assert.equal(hasPointerMoved({ x: 320, y: 240 }, { x: 321, y: 240 }), false);
  assert.equal(hasPointerMoved({ x: 320, y: 240 }, { x: 323, y: 240 }), true);
  assert.equal(hasPointerMoved(null, { x: 320, y: 240 }), true);
});
