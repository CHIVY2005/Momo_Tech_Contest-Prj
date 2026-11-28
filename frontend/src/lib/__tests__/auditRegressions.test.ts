import assert from "node:assert/strict";
import test from "node:test";

import {
  analyzeStream,
  analyzeSyncWithSession,
  fetchReportPdfBlob,
} from "../api.ts";
import { formatClassifierLabel } from "../copy.ts";
import type { CaseSessionInfo } from "../types";
import {
  formatVietQrAmount,
  formatVndInputDisplay,
  isValidAnalysisReport,
  isValidTraceStep,
  maskDisplayIoc,
  parseRawAmountDigits,
  sanitizeValidationErrorDetail,
  shouldShowReceiptCard,
  validateAnalystPinInput,
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

test("sanitizeValidationErrorDetail omits raw input values and internal field names", () => {
  const detail = [
    {
      type: "string_too_short",
      loc: ["body", "analyst_pin"],
      msg: "String should have at least 4 characters",
      input: "999",
    },
  ];
  const msg = sanitizeValidationErrorDetail(detail);
  assert.ok(msg.includes("mã PIN xác thực"));
  assert.ok(!msg.includes("analyst_pin"));
  assert.ok(!msg.includes("999"));
});

test("maskDisplayIoc conceals middle digits on raw accounts and phones without double-masking", () => {
  assert.equal(maskDisplayIoc("190384756201"), "19****01");
  assert.equal(maskDisplayIoc("1012345678"), "10****78");
  assert.equal(maskDisplayIoc("12345678"), "12****78");
  assert.equal(maskDisplayIoc("0912345678"), "091****678");
  assert.equal(maskDisplayIoc("19****01"), "19****01");
});

test("formatVietQrAmount never renders NaN VND on PII-scrubbed amounts", () => {
  assert.equal(formatVietQrAmount(null), "QR tĩnh (tự nhập số tiền)");
  assert.equal(formatVietQrAmount("19****01"), "19****01");
  assert.ok(formatVietQrAmount("1850000").includes("VND"));
  assert.ok(!formatVietQrAmount("19****01").includes("NaN"));
});

test("parseRawAmountDigits and formatVndInputDisplay format thousands while keeping raw backend digits", () => {
  assert.equal(parseRawAmountDigits("15.000.000"), "15000000");
  assert.equal(parseRawAmountDigits("00150000 VND"), "150000");
  assert.equal(parseRawAmountDigits("000"), "0");
  assert.equal(parseRawAmountDigits("abc"), "");
  assert.equal(formatVndInputDisplay("15000000"), "15.000.000");
  assert.equal(formatVndInputDisplay("500000"), "500.000");
  assert.equal(formatVndInputDisplay("0"), "0");
  assert.equal(formatVndInputDisplay(""), "");
});

test("shouldShowReceiptCard shows receipt card whenever calibrated status is applicable", () => {
  assert.equal(
    shouldShowReceiptCard({
      receipt_verification_status: "TAMPER_OR_LOGIC_ANOMALY",
      receipt_logic: null,
    }),
    true,
  );
  assert.equal(
    shouldShowReceiptCard({
      receipt_verification_status: "UNVERIFIED_SCREENSHOT",
      receipt_logic: { is_receipt_candidate: false },
    }),
    true,
  );
  assert.equal(
    shouldShowReceiptCard({
      receipt_verification_status: "NOT_APPLICABLE",
      receipt_logic: { is_receipt_candidate: false },
    }),
    false,
  );
});

test("validateAnalystPinInput returns Vietnamese message when PIN is empty or < 4 chars", () => {
  assert.ok(validateAnalystPinInput("") !== null);
  assert.ok(validateAnalystPinInput("123") !== null);
  assert.equal(validateAnalystPinInput("2026"), null);
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

function createMinimalValidReport(caseId: string) {
  return {
    case_id: caseId,
    created_at: "2026-11-27T00:00:00Z",
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
    summary_vi: "Không phát hiện dấu hiệu lừa đảo.",
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
}

test("analyzeStream captures SSE event: session and invokes onSession with token metadata", async () => {
  const validResult = createMinimalValidReport("vs_0123456789abcdef0123456789abcdef");
  const encoder = new TextEncoder();
  const sseBody =
    `event: result\ndata: ${JSON.stringify(validResult)}\n\n` +
    'event: session\ndata: {"case_id":"vs_0123456789abcdef0123456789abcdef","case_access_token":"tok_signed_123","expires_at":"2026-11-27T02:00:00Z"}\n\n' +
    'event: session\ndata: {"case_id":"vs_bad","case_access_token":12345}\n\n';

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
    const sessions: CaseSessionInfo[] = [];
    const fd = new FormData();
    fd.set("mode", "personal");
    fd.set("text", "test");
    const report = await analyzeStream(fd, {
      onSession: (session) => {
        sessions.push(session);
      },
    });
    assert.equal(report.case_id, "vs_0123456789abcdef0123456789abcdef");
    assert.equal(sessions.length, 1);
    assert.deepEqual(sessions[0], {
      case_id: "vs_0123456789abcdef0123456789abcdef",
      case_access_token: "tok_signed_123",
      expires_at: "2026-11-27T02:00:00Z",
    });
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("analyzeSyncWithSession returns report and X-Case-Access-Token header value", async () => {
  const validResult = createMinimalValidReport("vs_sync_case_01");
  const origFetch = globalThis.fetch;
  let callCount = 0;

  globalThis.fetch = (async () => {
    callCount += 1;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (callCount === 1) {
      headers["X-Case-Access-Token"] = "tok_sync_header_abc";
    }
    return new Response(JSON.stringify(validResult), { status: 200, headers });
  }) as typeof fetch;

  try {
    const fd = new FormData();
    fd.set("mode", "personal");
    fd.set("text", "test");

    const first = await analyzeSyncWithSession(fd);
    assert.equal(first.report.case_id, "vs_sync_case_01");
    assert.equal(first.caseAccessToken, "tok_sync_header_abc");

    const second = await analyzeSyncWithSession(fd);
    assert.equal(second.report.case_id, "vs_sync_case_01");
    assert.equal(second.caseAccessToken, null);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("analyzeStream falls back to analyzeSyncWithSession when res.body is null and fires onResult + onSession", async () => {
  const validResult = createMinimalValidReport("vs_fallback_case_01");
  const origFetch = globalThis.fetch;
  const calledUrls: string[] = [];

  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    calledUrls.push(url);
    if (url.endsWith("/api/v1/analyze/stream")) {
      return {
        ok: true,
        status: 200,
        body: null,
        headers: new Headers(),
      } as unknown as Response;
    }
    return new Response(JSON.stringify(validResult), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "X-Case-Access-Token": "tok_fallback_xyz",
      },
    });
  }) as typeof fetch;

  try {
    const events: string[] = [];
    let capturedSession: CaseSessionInfo | null = null;
    const fd = new FormData();
    fd.set("mode", "personal");
    fd.set("text", "test");

    const report = await analyzeStream(fd, {
      onResult: (r) => {
        events.push(`result:${r.case_id}`);
      },
      onSession: (s) => {
        events.push(`session:${s.case_id}`);
        capturedSession = s;
      },
    });

    assert.equal(report.case_id, "vs_fallback_case_01");
    assert.deepEqual(calledUrls, ["/api/v1/analyze/stream", "/api/v1/analyze"]);
    assert.deepEqual(events, ["result:vs_fallback_case_01", "session:vs_fallback_case_01"]);
    assert.deepEqual(capturedSession, {
      case_id: "vs_fallback_case_01",
      case_access_token: "tok_fallback_xyz",
    });
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("analyzeStream !res.body fallback fires onResult without onSession when X-Case-Access-Token is absent", async () => {
  const validResult = createMinimalValidReport("vs_fallback_no_tok");
  const origFetch = globalThis.fetch;

  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/v1/analyze/stream")) {
      return {
        ok: true,
        status: 200,
        body: null,
        headers: new Headers(),
      } as unknown as Response;
    }
    return new Response(JSON.stringify(validResult), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;

  try {
    let resultCalls = 0;
    let sessionCalls = 0;
    const fd = new FormData();
    fd.set("mode", "personal");
    fd.set("text", "test");

    const report = await analyzeStream(fd, {
      onResult: () => {
        resultCalls += 1;
      },
      onSession: () => {
        sessionCalls += 1;
      },
    });

    assert.equal(report.case_id, "vs_fallback_no_tok");
    assert.equal(resultCalls, 1);
    assert.equal(sessionCalls, 0);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("fetchReportPdfBlob sends X-Case-Access-Token header and returns blob + filename on HTTP 200", async () => {
  const origFetch = globalThis.fetch;
  let capturedUrl = "";
  let capturedToken: string | null = null;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    capturedUrl = String(input);
    const headers = new Headers(init?.headers);
    capturedToken = headers.get("X-Case-Access-Token");
    return new Response(new Uint8Array([0x25, 0x50, 0x44, 0x46]), {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": 'attachment; filename="VeriShield_vs_pdf_ok.pdf"',
      },
    });
  }) as typeof fetch;

  try {
    const { blob, filename } = await fetchReportPdfBlob("vs_pdf_ok", "tok_pdf_secret");
    assert.equal(capturedUrl, "/api/v1/cases/vs_pdf_ok/report.pdf");
    assert.equal(capturedToken, "tok_pdf_secret");
    assert.equal(filename, "VeriShield_vs_pdf_ok.pdf");
    assert.equal(blob.size, 4);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("fetchReportPdfBlob falls back to default filename when Content-Disposition is omitted", async () => {
  const origFetch = globalThis.fetch;

  globalThis.fetch = (async () =>
    new Response(new Uint8Array([0x25, 0x50, 0x44, 0x46]), {
      status: 200,
      headers: { "Content-Type": "application/pdf" },
    })) as typeof fetch;

  try {
    const { blob, filename } = await fetchReportPdfBlob("vs_case_77", "tok_pdf_77");
    assert.equal(filename, "VeriShield_vs_case_77.pdf");
    assert.equal(blob.size, 4);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("fetchReportPdfBlob throws Vietnamese expiry error on HTTP 403 and on null/blank token without calling fetch", async () => {
  const origFetch = globalThis.fetch;
  let fetchCalls = 0;

  globalThis.fetch = (async () => {
    fetchCalls += 1;
    return new Response(JSON.stringify({ detail: "Forbidden" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;

  try {
    await assert.rejects(
      () => fetchReportPdfBlob("vs_case_null", null),
      (err: unknown) =>
        err instanceof Error && /hết hạn|không hợp lệ|phân tích lại/i.test(err.message),
    );
    await assert.rejects(
      () => fetchReportPdfBlob("vs_case_blank", "   "),
      (err: unknown) =>
        err instanceof Error && /hết hạn|không hợp lệ|phân tích lại/i.test(err.message),
    );
    assert.equal(fetchCalls, 0);

    await assert.rejects(
      () => fetchReportPdfBlob("vs_case_403", "tok_expired"),
      (err: unknown) =>
        err instanceof Error && /hết hạn|không hợp lệ|phân tích lại/i.test(err.message),
    );
    assert.equal(fetchCalls, 1);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("formatClassifierLabel maps all 7 uppercase SCAM_LABELS to Vietnamese without raw enum leak", () => {
  const labels = [
    "SAFE_NORMAL",
    "SAFE_ADVISORY",
    "SCAM_IMPERSONATION",
    "SCAM_TASK_INVEST_LOAN",
    "SCAM_PHISHING_APK_OTP",
    "SCAM_URGENT_BORROW",
    "PROMPT_INJECTION",
  ];
  for (const label of labels) {
    const formatted = formatClassifierLabel(label);
    assert.notEqual(formatted, label);
    assert.ok(formatted.length >= 10);
  }
});
