import assert from "node:assert/strict";
import test from "node:test";

import { analyzeStream } from "../api.ts";
import {
  isValidAnalysisReport,
  isValidTraceStep,
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
  const validBaseReport = {
    case_id: "vs_complete",
    created_at: "2026-11-26T03:00:00Z",
    mode: "merchant",
    in_active_call: false,
    risk_score: 12,
    verdict: "SAFE",
    confidence: 0.9,
    degraded_mode: false,
    safety_advisory_detected: false,
    prompt_injection_detected: false,
    active_block_rule_hit: false,
    receipt_verification_status: "UNVERIFIED_SCREENSHOT",
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
    receipt_logic: {
      is_receipt_candidate: true,
      bank_detected: "Vietcombank",
      reference_code: "FT26330123456",
      reference_valid: true,
      timestamp_checked: true,
      timestamp_anomaly: false,
      amount_checked: true,
      amount_format_anomaly: false,
      geometry_checked: false,
      geometry_anomaly: false,
      beneficiary_checked: false,
      beneficiary_mismatch: false,
      replay_checked: true,
      is_replayed: false,
      verification_status: "UNVERIFIED_SCREENSHOT",
      logic_risk_points: 0,
      reasons: [],
    },
    evidence: [],
    actions: {
      counter_replies: [],
      family_shield_message: "",
      urgent_steps: [],
      merchant_balance_warning: "Kiểm tra số dư trước khi giao hàng.",
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
  };
  assert.equal(isValidAnalysisReport(validBaseReport), true);
  assert.equal(isValidAnalysisReport({ ...validBaseReport, evidence: [null] }), false);
  assert.equal(
    isValidAnalysisReport({
      ...validBaseReport,
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
    }),
    false,
  );
  assert.equal(
    isValidAnalysisReport({
      ...validBaseReport,
      active_block_rule_hit: true,
      actions: {
        ...validBaseReport.actions,
        pre_transfer: {
          ...validBaseReport.actions.pre_transfer,
          should_hold_transfer: true,
          blocked_by_ops_rule: false,
        },
      },
    }),
    false,
  );
  // String "false" on receipt_logic.beneficiary_checked would render as truthy in JS — must be rejected!
  assert.equal(
    isValidAnalysisReport({
      ...validBaseReport,
      receipt_logic: {
        ...validBaseReport.receipt_logic,
        beneficiary_checked: "false",
      },
    }),
    false,
  );
  // Malformed image_forensics missing finite ocr_height_cv must be rejected before rendering ElaCompareView
  assert.equal(
    isValidAnalysisReport({
      ...validBaseReport,
      image_forensics: {
        filename: "evidence.jpg",
        format: "JPEG",
        width: 400,
        height: 500,
        dhash_hex: "1122334455667788",
        exif_software: null,
        editing_software_detected: false,
        tamper_score: 0,
        ela_heatmap_base64: null,
        qr_payloads: [],
        ocr_text: "",
        ocr_height_cv: "not-a-number",
        reasons: [],
      },
    }),
    false,
  );
  // Live SSE TraceStep guard rejects object-valued detail while accepting valid TraceStep
  assert.equal(
    isValidTraceStep({
      step_id: "s1",
      title: "Bước 1",
      status: "done",
      detail: { nested: "boom" },
      duration_ms: 4,
    }),
    false,
  );
  assert.equal(
    isValidTraceStep({
      step_id: "s1",
      title: "Bước 1",
      status: "done",
      detail: "Hoàn tất",
      duration_ms: 4,
    }),
    true,
  );
});

test("analyzeStream skips well-framed SSE trace with invalid nested detail without invoking onTrace", async () => {
  const validResult = {
    case_id: "vs_sse_trace_guard",
    created_at: "2026-11-26T00:00:00Z",
    mode: "personal",
    in_active_call: false,
    risk_score: 10,
    verdict: "SAFE",
    confidence: 0.9,
    degraded_mode: false,
    safety_advisory_detected: false,
    prompt_injection_detected: false,
    active_block_rule_hit: false,
    receipt_verification_status: "NOT_APPLICABLE",
    summary_vi: "An toàn.",
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
  };

  const encoder = new TextEncoder();
  const sseBody =
    'event: trace\ndata: {"step_id":"s1","title":"Bước 1","status":"done","detail":{"nested":"boom"},"duration_ms":4}\n\n' +
    `event: result\ndata: ${JSON.stringify(validResult)}\n\n`;

  const origFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode(sseBody));
          controller.close();
        },
      }),
      { status: 200, headers: { "Content-Type": "text/event-stream" } },
    )) as typeof fetch;

  try {
    let traceCalls = 0;
    const fd = new FormData();
    fd.set("mode", "personal");
    fd.set("text", "test");
    const report = await analyzeStream(fd, {
      onTrace: () => {
        traceCalls += 1;
      },
    });
    assert.equal(traceCalls, 0);
    assert.equal(report.case_id, "vs_sse_trace_guard");
  } finally {
    globalThis.fetch = origFetch;
  }
});
