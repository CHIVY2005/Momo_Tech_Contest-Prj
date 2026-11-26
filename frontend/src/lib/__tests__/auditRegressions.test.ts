import assert from "node:assert/strict";
import test from "node:test";

import {
  isValidAnalysisReport,
  maskDisplayIoc,
  sanitizeValidationErrorDetail,
} from "../formatters.ts";
import { consumeUtf8SseStream } from "../sse.ts";

test("consumeUtf8SseStream ignores unterminated trailing frame at EOF", async () => {
  const encoder = new TextEncoder();
  const payload =
    'event: trace\ndata: {"step_id":"s1","title":"Bước 1","status":"done","detail":"ok","duration_ms":5}\n\n' +
    'event: result\ndata: {"case_id":"vs_truncated"}';

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode(payload));
      controller.close();
    },
  });

  const received: Array<{ event: string; data: unknown }> = [];
  await consumeUtf8SseStream(stream, (ev) => received.push(ev));

  assert.equal(received.length, 1);
  assert.equal(received[0]?.event, "trace");
});

test("sanitizeValidationErrorDetail omits raw input values such as PIN or bank account", () => {
  const detail = [
    {
      type: "string_too_short",
      loc: ["body", "analyst_pin"],
      msg: "String should have at least 4 characters",
      input: "999",
    },
  ];
  const msg = sanitizeValidationErrorDetail(detail);
  assert.ok(msg.includes("analyst_pin"));
  assert.ok(!msg.includes("999"));
});

test("maskDisplayIoc conceals middle digits on raw accounts and phones without double-masking", () => {
  assert.equal(maskDisplayIoc("190384756201"), "1903****6201");
  assert.equal(maskDisplayIoc("12345678"), "12****78");
  assert.equal(maskDisplayIoc("0912345678"), "091****678");
  assert.equal(maskDisplayIoc("1903****6201"), "1903****6201");
});

test("isValidAnalysisReport rejects partial or malformed payloads and accepts complete reports", () => {
  assert.equal(isValidAnalysisReport({}), false);
  assert.equal(isValidAnalysisReport([]), false);
  // Partial object missing required dashboard arrays (url_findings, evidence, iocs, etc.) must fail
  assert.equal(
    isValidAnalysisReport({
      case_id: "vs_partial",
      risk_score: 12,
      verdict: "SAFE",
      actions: { pre_transfer: { should_hold_transfer: false } },
    }),
    false,
  );
  assert.equal(
    isValidAnalysisReport({
      case_id: "vs_complete",
      created_at: "2026-11-26T03:00:00Z",
      mode: "personal",
      in_active_call: false,
      risk_score: 12,
      verdict: "SAFE",
      confidence: 0.9,
      degraded_mode: false,
      safety_advisory_detected: false,
      prompt_injection_detected: false,
      active_block_rule_hit: false,
      receipt_verification_status: "NOT_APPLICABLE",
      summary_vi: "Không ghi nhận dấu hiệu lừa đảo.",
      transcript: null,
      classifier: null,
      matched_playbooks: [],
      manipulation_tactics: [],
      highlighted_phrases: [],
      iocs: { phones: [], bank_accounts: [], urls: [], domains: [], brands: [] },
      vietqr_findings: [],
      url_findings: [],
      sandbox: null,
      image_forensics: null,
      receipt_logic: null,
      evidence: [],
      actions: {
        counter_replies: [],
        family_shield_message: "",
        urgent_steps: [],
        merchant_balance_warning: null,
        pre_transfer: {
          should_hold_transfer: false,
          cooling_off_seconds: 0,
          triggered_by_active_call: false,
          blocked_by_ops_rule: false,
          warning_headline: "",
          verification_questions: [],
        },
      },
      trace: [],
      community_hits: 0,
    }),
    true,
  );
  // Malformed nested array entries (null evidence item or VietQR missing string raw) must be rejected
  assert.equal(
    isValidAnalysisReport({
      case_id: "vs_bad_nested",
      created_at: "2026-11-26T03:00:00Z",
      mode: "personal",
      risk_score: 12,
      verdict: "SAFE",
      summary_vi: "ok",
      matched_playbooks: [],
      manipulation_tactics: [],
      highlighted_phrases: [],
      iocs: { phones: [], bank_accounts: [], urls: [], domains: [], brands: [] },
      vietqr_findings: [{ raw: null, kind: "VALID_VIETQR", crc_valid: true }],
      url_findings: [],
      evidence: [null],
      actions: {
        counter_replies: [],
        family_shield_message: "",
        urgent_steps: [],
        pre_transfer: {
          should_hold_transfer: false,
          cooling_off_seconds: 0,
          verification_questions: [],
        },
      },
      trace: [],
    }),
    false,
  );
  // Valid report except VietQR account_number is a number instead of string|null must be rejected
  assert.equal(
    isValidAnalysisReport({
      case_id: "vs_bad_qr_acct",
      created_at: "2026-11-26T03:00:00Z",
      mode: "personal",
      risk_score: 12,
      verdict: "SAFE",
      summary_vi: "ok",
      matched_playbooks: [],
      manipulation_tactics: [],
      highlighted_phrases: [],
      iocs: { phones: [], bank_accounts: [], urls: [], domains: [], brands: [] },
      vietqr_findings: [
        {
          raw: "000201",
          kind: "VALID_VIETQR",
          crc_valid: true,
          account_number: 190384756201,
          receive_scam_detected: false,
          beneficiary_mismatch: false,
        },
      ],
      url_findings: [],
      evidence: [],
      actions: {
        counter_replies: [],
        family_shield_message: "",
        urgent_steps: [],
        merchant_balance_warning: null,
        pre_transfer: {
          should_hold_transfer: false,
          cooling_off_seconds: 0,
          warning_headline: "",
          verification_questions: [],
        },
      },
      trace: [],
    }),
    false,
  );
});
