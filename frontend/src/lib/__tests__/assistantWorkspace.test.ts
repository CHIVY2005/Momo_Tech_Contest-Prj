import assert from "node:assert/strict";
import { test } from "node:test";

import { assistantWidthBounds, clampAssistantWidth, nextAssistantWidth } from "../assistantLayout.ts";
import { createConversationRecord, expireInterruptedTurn, getCaseTokenExpiry, readConversationRecord } from "../assistantConversation.ts";

test("docked width respects viewport bounds and keyboard adjustments", () => {
  for (const viewport of [375, 768, 1024, 1440, 1920]) {
    const bounds = assistantWidthBounds(viewport);
    assert.equal(bounds.max, Math.floor(viewport * 0.85));
    assert.equal(bounds.min, Math.min(400, bounds.max));
    assert.equal(clampAssistantWidth(620, viewport), Math.min(620, bounds.max));
  }
  assert.equal(nextAssistantWidth("ArrowLeft", 620, 1024), 644);
  assert.equal(nextAssistantWidth("ArrowRight", 620, 1024), 596);
  assert.equal(nextAssistantWidth("Home", 620, 1024), 400);
  assert.equal(nextAssistantWidth("End", 620, 1024), 870);
  assert.equal(nextAssistantWidth("Enter", 800, 1024), 620);
  assert.equal(nextAssistantWidth("Tab", 620, 1024), null);
});

test("checkpoints restore only the chosen, unexpired and case-bound conversation", () => {
  const expiry = 2_000_000_000;
  const token = `${Buffer.from(JSON.stringify({ cid: "case-one", exp: expiry })).toString("base64url")}.fixture`;
  const record = createConversationRecord("case-one", token);
  assert.equal(getCaseTokenExpiry("case-two", token), null);
  assert.equal(getCaseTokenExpiry("case-one", "broken"), null);
  assert.equal(record.expiresAt, expiry * 1000);
  const raw = JSON.stringify(record);
  assert.equal(readConversationRecord(raw, record.id, expiry * 1000 - 1)?.caseId, "case-one");
  assert.equal(readConversationRecord(raw, crypto.randomUUID(), expiry * 1000 - 1), null);
  assert.equal(readConversationRecord(raw, record.id, expiry * 1000), null);
  assert.equal(readConversationRecord(JSON.stringify({ ...record, caseId: "case-two" }), record.id), null);
});

test("an interrupted stream keeps partial text and never becomes completed history", () => {
  const record = createConversationRecord("case-one", null);
  const snapshot = {
    ...record.snapshot,
    streaming: true,
    messages: [
      { id: "question", role: "user" as const, content: "Check?" },
      { id: "reply", role: "assistant" as const, content: "Partial", isStreaming: true },
    ],
  };
  const restored = expireInterruptedTurn(snapshot);
  assert.equal(restored.streaming, false);
  assert.equal(restored.messages[1]?.content, "Partial");
  assert.equal(restored.messages[1]?.isStreaming, false);
  assert.ok(restored.messages[1]?.errorMessage);
});
