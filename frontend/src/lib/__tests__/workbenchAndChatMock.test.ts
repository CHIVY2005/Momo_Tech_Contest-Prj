import assert from "node:assert/strict";
import test from "node:test";

import {
  analyzeStream,
  fetchReportPdfBlob,
  persistAssistantEvidence,
  shouldShowReceiptCard,
  streamAssistantChat,
  streamAssistantEvidenceChat,
} from "../api.ts";
import {
  extractUrlsFromText,
  inferAnalyzeMode,
  validateAttachmentBatch,
} from "../composerUtils.ts";
import { formatClassifierLabel } from "../copy.ts";
import { formatVndInputDisplay, parseRawAmountDigits } from "../formatters.ts";
import { parseSafeMarkdownBlocks } from "../safeMarkdown.ts";
import type {
  AssistantCitationItem,
  AssistantDoneEvent,
  AssistantEvidenceReportEvent,
  AssistantSafetyNoticeEvent,
  AssistantStatusEvent,
  AssistantToolStatusEvent,
  TraceStep,
} from "../types";

function makeSyntheticFile(name: string, type: string, sizeBytes: number): File {
  return new File([new Uint8Array(sizeBytes)], name, { type });
}

function buildMockReport(overrides: Record<string, unknown> = {}) {
  return {
    case_id: "vs_mock_0123456789abcdef0123456789ab",
    created_at: "2026-11-28T05:10:00Z",
    mode: "wallet_transfer",
    in_active_call: true,
    risk_score: 88,
    verdict: "CRITICAL_SCAM",
    confidence: 0.94,
    degraded_mode: false,
    safety_advisory_detected: false,
    prompt_injection_detected: false,
    active_block_rule_hit: false,
    receipt_verification_status: "NOT_APPLICABLE",
    summary_vi:
      "Cảnh báo rủi ro rất cao: nội dung có dấu hiệu giả mạo cơ quan chức năng yêu cầu chuyển tiền qua đường dẫn lạ.",
    transcript: null,
    classifier: {
      available: true,
      predicted_label: "SCAM_IMPERSONATION",
      scam_probability: 0.96,
      advisory_probability: 0.01,
      latency_ms: 11,
    },
    matched_playbooks: ["Giả danh Công an / Cài đặt ứng dụng giả mạo"],
    manipulation_tactics: ["Đe dọa pháp lý khẩn cấp", "Thúc ép chuyển tiền giữ bí mật"],
    highlighted_phrases: ["chuyển 15.000.000", "xác minh tài khoản"],
    iocs: {
      phones: ["091****678"],
      bank_accounts: ["8800****56"],
      urls: ["https://dichvucong-giamao.top/xac-minh"],
      domains: ["dichvucong-giamao.top"],
      brands: [],
    },
    vietqr_findings: [],
    url_findings: [
      {
        url: "https://dichvucong-giamao.top/xac-minh",
        domain: "dichvucong-giamao.top",
        normalized_ascii_domain: "dichvucong-giamao.top",
        final_url: "https://dichvucong-giamao.top/xac-minh",
        redirect_hops: 0,
        is_blocked_ssrf: false,
        is_idn_homoglyph: false,
        spoofed_brand: null,
        urlhaus_listed: false,
        risk_points: 68,
        reasons: ["Tên miền mới sử dụng đuôi .top có dấu hiệu giả mạo."],
      },
    ],
    sandbox: null,
    image_forensics: null,
    image_forensics_list: [],
    receipt_logic: null,
    evidence: [
      {
        source: "url_inspector",
        severity: "CRITICAL",
        title: "Phát hiện rủi ro từ đường dẫn trang web",
        detail: "Tên miền có dấu hiệu giả mạo cổng dịch vụ công.",
        snippet: "https://dichvucong-giamao.top/xac-minh",
      },
    ],
    actions: {
      counter_replies: [
        "Tôi sẽ tự liên hệ công an phường hoặc tổng đài chính thức để xác minh, không chuyển tiền qua cuộc gọi.",
      ],
      family_shield_message:
        "[Cảnh báo từ VeriShield AI] Cả nhà cảnh giác thủ đoạn giả danh cơ quan công an gọi điện yêu cầu chuyển tiền.",
      urgent_steps: [
        "Ngắt cuộc gọi ngay lập tức và tuyệt đối không chuyển tiền.",
        "Không cài đặt tệp lạ và không cung cấp mã OTP.",
      ],
      merchant_balance_warning: null,
      pre_transfer: {
        should_hold_transfer: true,
        cooling_off_seconds: 30,
        triggered_by_active_call: true,
        blocked_by_ops_rule: false,
        warning_headline:
          "Tạm dừng để kiểm tra 30 giây — hãy bình tĩnh xác minh lại khi đang nghe cuộc gọi thúc ép chuyển tiền",
        verification_questions: [
          "Người yêu cầu chuyển tiền có đang giục gấp hoặc yêu cầu bạn giữ bí mật cuộc gọi không?",
        ],
      },
    },
    trace: [],
    community_hits: 0,
    llm_provider: "gemini",
    llm_model: "gemini-2.5-flash",
    llm_latency_ms: 420,
    ...overrides,
  };
}

test("mock input workbench validates attachments, infers wallet_transfer mode, and streams Vietnamese scam result", async () => {
  const inputText =
    "Anh ơi em đang bị công an gọi thúc chuyển 15.000.000đ vào https://dichvucong-giamao.top/xac-minh gấp";
  const rawDigits = parseRawAmountDigits("15.000.000");
  assert.equal(rawDigits, "15000000");
  assert.equal(formatVndInputDisplay(rawDigits), "15.000.000");
  assert.deepEqual(extractUrlsFromText(inputText), ["https://dichvucong-giamao.top/xac-minh"]);

  const png = makeSyntheticFile("mock-evidence.png", "image/png", 2048);
  const webm = makeSyntheticFile("mock-call.webm", "audio/webm", 4096);
  const svgBad = makeSyntheticFile("vector.svg", "image/svg+xml", 256);

  const batchOk = validateAttachmentBatch([], [], [png, webm]);
  assert.equal(batchOk.acceptedImages.length, 1);
  assert.equal(batchOk.acceptedAudios.length, 1);
  assert.equal(batchOk.errors.length, 0);

  const batchBad = validateAttachmentBatch([], [], [svgBad]);
  assert.equal(batchBad.errors.length, 1);
  assert.ok(batchBad.errors[0]?.includes("WebM"));

  const resolvedMode = inferAnalyzeMode({
    expectedMerchantAccount: "",
    transferAmount: rawDigits,
    inActiveCall: true,
  });
  assert.equal(resolvedMode, "wallet_transfer");

  const fd = new FormData();
  fd.set("mode", resolvedMode);
  fd.set("text", inputText);
  fd.set("in_active_call", "true");
  fd.set("transfer_amount", rawDigits);
  fd.append("images", png);
  fd.append("audios", webm);

  const reportPayload = buildMockReport();
  const encoder = new TextEncoder();
  const traceStepsPayload: TraceStep[] = [
    {
      step_id: "media_forensics",
      title: "Phân tích tính xác thực của hình ảnh, mã QR và ghi âm",
      status: "done",
      detail: "Đã kiểm tra 1 hình ảnh và 1 tệp ghi âm.",
      duration_ms: 14,
    },
    {
      step_id: "cyber_guardrails",
      title: "Kiểm tra đường dẫn đáng ngờ và danh sách chặn",
      status: "warning",
      detail: "Ghi nhận 1 đường dẫn có dấu hiệu giả mạo.",
      duration_ms: 28,
    },
    {
      step_id: "onnx_and_kb",
      title: "Đối chiếu nội dung với các kịch bản lừa đảo phổ biến",
      status: "done",
      detail: "Đã phân loại ngữ cảnh và ghi nhận 1 kịch bản tương tự.",
      duration_ms: 11,
    },
    {
      step_id: "multimodal_calibration",
      title: "Tổng hợp bằng chứng và đánh giá mức độ rủi ro",
      status: "done",
      detail: "Mức độ rủi ro: 88/100 (rủi ro rất cao)",
      duration_ms: 420,
    },
  ];

  const sseText =
    traceStepsPayload.map((st) => `event: trace\ndata: ${JSON.stringify(st)}\n\n`).join("") +
    `event: session\ndata: ${JSON.stringify({
      case_id: reportPayload.case_id,
      case_access_token: "tok_mock_wallet_88",
      expires_at: "2026-11-28T07:10:00Z",
    })}\n\n` +
    `event: result\ndata: ${JSON.stringify(reportPayload)}\n\n`;

  const origFetch = globalThis.fetch;
  const sentForms: FormData[] = [];
  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    if (init?.body instanceof FormData) {
      sentForms.push(init.body);
    }
    const bytes = encoder.encode(sseText);
    const splitAt = Math.floor(bytes.length / 2);
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes.slice(0, splitAt));
          controller.enqueue(bytes.slice(splitAt));
          controller.close();
        },
      }),
      { status: 200, headers: { "Content-Type": "text/event-stream" } },
    );
  }) as typeof fetch;

  try {
    const seenTraces: TraceStep[] = [];
    let seenToken: string | null = null;
    const report = await analyzeStream(fd, {
      onTrace: (st) => seenTraces.push(st),
      onSession: (sess) => {
        seenToken = sess.case_access_token;
      },
    });

    assert.equal(sentForms.length, 1);
    const sent = sentForms[0]!;
    assert.equal(sent.get("mode"), "wallet_transfer");
    assert.equal(sent.get("transfer_amount"), "15000000");
    assert.equal(sent.get("in_active_call"), "true");
    assert.equal(seenTraces.length, 4);
    assert.equal(seenToken, "tok_mock_wallet_88");
    assert.equal(report.verdict, "CRITICAL_SCAM");
    assert.equal(report.risk_score, 88);
    assert.equal(report.actions.pre_transfer.should_hold_transfer, true);
    assert.equal(
      formatClassifierLabel(report.classifier?.predicted_label ?? ""),
      "Giả mạo cơ quan nhà nước, công an hoặc ngân hàng",
    );
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("mock merchant receipt flow enforces SAFE Merchant Honesty Guardrail", async () => {
  const merchantAccount = "190311112222";
  const resolvedMode = inferAnalyzeMode({
    expectedMerchantAccount: merchantAccount,
    transferAmount: "",
    inActiveCall: false,
  });
  assert.equal(resolvedMode, "merchant");

  const merchantReport = buildMockReport({
    case_id: "vs_mock_merchant_safe_01",
    mode: "merchant",
    in_active_call: false,
    risk_score: 12,
    verdict: "SAFE",
    receipt_verification_status: "UNVERIFIED_SCREENSHOT",
    summary_vi:
      "Ảnh chụp biên lai chưa ghi nhận dấu hiệu chỉnh sửa, nhưng hệ thống không thể xác nhận tiền đã vào tài khoản chỉ từ ảnh chụp. Chỉ giao hàng sau khi kiểm tra trực tiếp biến động số dư trên ứng dụng ngân hàng hoặc loa thông báo nhận tiền.",
    classifier: {
      available: true,
      predicted_label: "SAFE_NORMAL",
      scam_probability: 0.04,
      advisory_probability: 0.02,
      latency_ms: 9,
    },
    matched_playbooks: [],
    manipulation_tactics: [],
    url_findings: [],
    evidence: [],
    receipt_logic: {
      is_receipt_candidate: true,
      bank_detected: "Techcombank",
      reference_code: "FT26331000123",
      reference_valid: true,
      timestamp_checked: true,
      timestamp_anomaly: false,
      amount_checked: true,
      amount_format_anomaly: false,
      geometry_checked: true,
      geometry_anomaly: false,
      beneficiary_checked: true,
      beneficiary_mismatch: false,
      extracted_recipient_account: "19****22",
      replay_checked: true,
      is_replayed: false,
      verification_status: "UNVERIFIED_SCREENSHOT",
      logic_risk_points: 0,
      reasons: [],
    },
    actions: {
      counter_replies: [],
      family_shield_message: "",
      urgent_steps: ["Kiểm tra trực tiếp biến động số dư trước khi giao hàng."],
      merchant_balance_warning:
        "Lưu ý bắt buộc cho người bán: Ảnh chụp màn hình biên lai không phải bằng chứng tiền đã vào tài khoản. Chỉ giao hàng sau khi kiểm tra trực tiếp biến động số dư trên ứng dụng ngân hàng hoặc loa thông báo nhận tiền.",
      pre_transfer: {
        should_hold_transfer: false,
        cooling_off_seconds: 0,
        triggered_by_active_call: false,
        blocked_by_ops_rule: false,
        warning_headline: "",
        verification_questions: [],
      },
    },
  });

  const sseText = `event: result\ndata: ${JSON.stringify(merchantReport)}\n\n`;
  const encoder = new TextEncoder();
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode(sseText));
          controller.close();
        },
      }),
      { status: 200, headers: { "Content-Type": "text/event-stream" } },
    )) as typeof fetch;

  try {
    const fd = new FormData();
    fd.set("mode", "merchant");
    fd.set("text", "Khách gửi ảnh chuyển khoản Techcombank FT26331000123");
    fd.set("expected_merchant_account", merchantAccount);

    const report = await analyzeStream(fd, {});
    assert.equal(report.verdict, "SAFE");
    assert.equal(report.receipt_verification_status, "UNVERIFIED_SCREENSHOT");
    assert.equal(shouldShowReceiptCard(report), true);
    assert.ok(report.actions.merchant_balance_warning?.includes("biến động số dư"));
    assert.equal(
      formatClassifierLabel(report.classifier?.predicted_label ?? ""),
      "Nội dung giao dịch hoặc trao đổi thông thường",
    );
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("mock chatbot multi-turn Q&A, local-only supplementary evidence, persist, and PDF download", async () => {
  const caseId = "vs_mock_0123456789abcdef0123456789ab";
  const token = "tok_mock_wallet_88";
  const encoder = new TextEncoder();
  const origFetch = globalThis.fetch;

  const calls: Array<{ url: string; method: string; token: string | null }> = [];
  let chatTurn = 0;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const headers = new Headers(init?.headers);
    calls.push({
      url,
      method: init?.method ?? "GET",
      token: headers.get("X-Case-Access-Token"),
    });

    if (url === "/api/v1/assistant/chat/stream") {
      chatTurn += 1;
      const body = JSON.parse(String(init?.body ?? "{}")) as {
        history: Array<{ role: string; content: string }>;
      };
      if (chatTurn === 2) {
        assert.equal(body.history.length, 2);
      }
      const sseFrames =
        'event: status\ndata: {"phase":"retrieving","label":"Đang đối chiếu hồ sơ..."}\n\n' +
        'event: tool_status\ndata: {"tool":"check_url_safety","state":"done","label":"Đã kiểm tra đường dẫn"}\n\n' +
        'event: safety_notice\ndata: {"code":"VERIFY_OFFICIAL_CHANNEL","message":"Luôn xác minh qua kênh chính thức."}\n\n' +
        `event: delta\ndata: {"text":"## Hướng dẫn lượt ${chatTurn}\\n- Không chuyển **tiền tạm giữ**."}\n\n` +
        'event: citation\ndata: {"items":[{"id":"KB:sop_police","source_type":"kb","title":"Quy trình ứng phó giả danh công an"}]}\n\n' +
        'event: done\ndata: {"degraded_mode":false,"output_tier":1,"suggested_followups":["Cách báo cáo số tài khoản?"]}\n\n';
      return new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(encoder.encode(sseFrames));
            controller.close();
          },
        }),
        { status: 200, headers: { "Content-Type": "text/event-stream" } },
      );
    }

    if (url === "/api/v1/assistant/chat/evidence/stream") {
      const fd = init?.body as FormData;
      assert.equal(fd.get("allow_external_media_ai"), "false");
      assert.equal(fd.get("case_id"), caseId);
      const sseFrames =
        'event: status\ndata: {"phase":"analyzing","label":"Đang xử lý cục bộ bằng chứng bổ sung..."}\n\n' +
        'event: evidence_report\ndata: {"draft_id":"drf_mock_99","can_contribute_radar":true,"risk_score":84,"verdict":"CRITICAL_SCAM","receipt_verification_status":"NOT_APPLICABLE","summary_vi":"Phát hiện đường dẫn giả mạo trong ảnh bổ sung."}\n\n' +
        'event: delta\ndata: {"text":"Bằng chứng bổ sung đã được kiểm tra hoàn toàn cục bộ."}\n\n' +
        'event: done\ndata: {"degraded_mode":false,"output_tier":0,"suggested_followups":[]}\n\n';
      return new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(encoder.encode(sseFrames));
            controller.close();
          },
        }),
        { status: 200, headers: { "Content-Type": "text/event-stream" } },
      );
    }

    if (url === "/api/v1/assistant/evidence/drf_mock_99/persist") {
      return new Response(
        JSON.stringify({
          child_case_id: "vs_child_mock_01",
          child_case_access_token: "tok_child_mock_01",
          expires_at: "2026-11-28T07:15:00Z",
          contributed_to_radar: true,
          parent_case_id: caseId,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }

    if (url === "/api/v1/cases/vs_child_mock_01/report.pdf") {
      return new Response(new Uint8Array([0x25, 0x50, 0x44, 0x46]), {
        status: 200,
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": 'attachment; filename="VeriShield_vs_child_mock_01.pdf"',
        },
      });
    }

    throw new Error(`Unexpected fetch URL in mock test: ${url}`);
  }) as typeof fetch;

  try {
    // Turn 1
    let md1 = "";
    const statuses1: AssistantStatusEvent[] = [];
    const tools1: AssistantToolStatusEvent[] = [];
    const notices1: AssistantSafetyNoticeEvent[] = [];
    const citations1: AssistantCitationItem[][] = [];
    const dones1: AssistantDoneEvent[] = [];

    await streamAssistantChat(
      { case_id: caseId, message: "Vì sao hồ sơ này bị cảnh báo?", history: [] },
      token,
      {
        onStatus: (ev) => statuses1.push(ev),
        onToolStatus: (ev) => tools1.push(ev),
        onSafetyNotice: (ev) => notices1.push(ev),
        onDelta: (d) => {
          md1 += d;
        },
        onCitation: (items) => citations1.push(items),
        onDone: (ev) => dones1.push(ev),
      },
    );

    const blocks = parseSafeMarkdownBlocks(md1);
    assert.equal(blocks[0]?.type, "heading");
    assert.equal(blocks[1]?.type, "ul");
    assert.equal(tools1[0]?.state, "done");
    assert.equal(notices1[0]?.code, "VERIFY_OFFICIAL_CHANNEL");
    assert.equal(citations1[0]?.[0]?.id, "KB:sop_police");
    assert.deepEqual(dones1[0]?.suggested_followups, ["Cách báo cáo số tài khoản?"]);

    // Turn 2 with bounded history
    let md2 = "";
    await streamAssistantChat(
      {
        case_id: caseId,
        message: "Cách báo cáo số tài khoản?",
        history: [
          { role: "user", content: "Vì sao hồ sơ này bị cảnh báo?" },
          { role: "assistant", content: md1 },
        ],
      },
      token,
      {
        onDelta: (d) => {
          md2 += d;
        },
      },
    );
    assert.ok(md2.includes("lượt 2"));

    // Supplementary local-only evidence in assistant
    const extraForm = new FormData();
    extraForm.set("case_id", caseId);
    extraForm.set("message", "Kiểm tra ảnh tin nhắn bổ sung này");
    extraForm.set("allow_external_media_ai", "false");
    extraForm.set("attachment", makeSyntheticFile("extra.png", "image/png", 1024));

    const evidenceEvents: AssistantEvidenceReportEvent[] = [];
    await streamAssistantEvidenceChat(extraForm, token, {
      onEvidenceReport: (ev) => evidenceEvents.push(ev),
    });
    assert.equal(evidenceEvents[0]?.draft_id, "drf_mock_99");
    assert.equal(evidenceEvents[0]?.risk_score, 84);

    // Persist + PDF download
    const persisted = await persistAssistantEvidence("drf_mock_99", caseId, true, token);
    assert.equal(persisted.child_case_id, "vs_child_mock_01");
    assert.equal(persisted.contributed_to_radar, true);

    const { blob, filename } = await fetchReportPdfBlob(
      persisted.child_case_id,
      persisted.child_case_access_token,
    );
    assert.equal(filename, "VeriShield_vs_child_mock_01.pdf");
    assert.equal(blob.size, 4);

    assert.equal(calls.length, 5);
    assert.equal(calls[4]?.token, "tok_child_mock_01");
  } finally {
    globalThis.fetch = origFetch;
  }
});
