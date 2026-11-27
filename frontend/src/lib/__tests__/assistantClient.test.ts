import assert from "node:assert/strict";
import test from "node:test";

import {
  AssistantApiError,
  persistAssistantEvidence,
  streamAssistantChat,
  streamAssistantEvidenceChat,
} from "../api.ts";
import { parseSafeMarkdownBlocks } from "../safeMarkdown.ts";
import type {
  AssistantChatPayload,
  AssistantCitationItem,
  AssistantDoneEvent,
  AssistantErrorEvent,
  AssistantEvidenceReportEvent,
  AssistantSafetyNoticeEvent,
  AssistantStatusEvent,
  AssistantToolStatusEvent,
  PersistEvidenceResponse,
} from "../types";

test("parseSafeMarkdownBlocks parses headings, paragraphs, lists, bold, and inline code", () => {
  const md = [
    "## Các bước xử lý khẩn cấp",
    "",
    "Gọi ngay **tổng đài chính thức** và kiểm tra mã `FT263301`.",
    "",
    "- Không bấm vào đường dẫn lạ",
    "* Không cung cấp **mã OTP** cho bất kỳ ai",
    "",
    "1. Chụp màn hình đoạn chat làm bằng chứng",
    "2. Trình báo **Công an địa phương** hoặc `Cục A05`",
  ].join("\n");

  const blocks = parseSafeMarkdownBlocks(md);
  assert.equal(blocks.length, 4);

  assert.equal(blocks[0]?.type, "heading");
  if (blocks[0]?.type === "heading") {
    assert.equal(blocks[0].level, 2);
    assert.deepEqual(blocks[0].tokens, [{ type: "text", value: "Các bước xử lý khẩn cấp" }]);
  }

  assert.equal(blocks[1]?.type, "paragraph");
  if (blocks[1]?.type === "paragraph") {
    assert.deepEqual(blocks[1].tokens, [
      { type: "text", value: "Gọi ngay " },
      { type: "bold", value: "tổng đài chính thức" },
      { type: "text", value: " và kiểm tra mã " },
      { type: "code", value: "FT263301" },
      { type: "text", value: "." },
    ]);
  }

  assert.equal(blocks[2]?.type, "ul");
  if (blocks[2]?.type === "ul") {
    assert.equal(blocks[2].items.length, 2);
    assert.deepEqual(blocks[2].items[1], [
      { type: "text", value: "Không cung cấp " },
      { type: "bold", value: "mã OTP" },
      { type: "text", value: " cho bất kỳ ai" },
    ]);
  }

  assert.equal(blocks[3]?.type, "ol");
  if (blocks[3]?.type === "ol") {
    assert.equal(blocks[3].items.length, 2);
    assert.deepEqual(blocks[3].items[1], [
      { type: "text", value: "Trình báo " },
      { type: "bold", value: "Công an địa phương" },
      { type: "text", value: " hoặc " },
      { type: "code", value: "Cục A05" },
    ]);
  }
});

test("parseSafeMarkdownBlocks keeps Vietnamese thousands amounts as paragraphs and handles partial streaming syntax", () => {
  const blocks = parseSafeMarkdownBlocks("15.000.000 VND đang chờ **xác minh");
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0]?.type, "paragraph");
  if (blocks[0]?.type === "paragraph") {
    const joined = blocks[0].tokens.map((t) => t.value).join("");
    assert.equal(joined, "15.000.000 VND đang chờ **xác minh");
  }
});

test("parseSafeMarkdownBlocks neutralizes XSS tags, javascript/data links, and external links with zero hrefs", () => {
  const payload = [
    "<script>alert(1)</script>",
    "",
    "<img src=x onerror=alert(1)>",
    "",
    "Bấm [click](javascript:alert(1)) hoặc **[đăng nhập](JAVASCRIPT:alert(2))**",
    "",
    "Hoặc [tải về](data:text/html,<script>alert(1)</script>) và [vb](vbscript:msgbox(1))",
    "",
    "Liên kết ngoài [evil](https://phishing.vn) và ảnh ![pixel](https://tracker.invalid/a.png)",
  ].join("\n");

  const blocks = parseSafeMarkdownBlocks(payload);
  assert.equal(blocks.length, 5);

  const serialized = JSON.stringify(blocks);
  assert.ok(!serialized.includes('"href"'), "AST must never contain href keys");
  assert.ok(!serialized.includes('"link"'), "AST must never contain link token types");
  assert.ok(!serialized.includes('"html"'), "AST must never contain html token types");
  assert.ok(!serialized.includes('"image"'), "AST must never contain image token types");

  // Dangerous schemes must be stripped completely from markdown links
  assert.ok(!/javascript:/i.test(serialized), "javascript: scheme must be stripped from links");
  assert.ok(!/vbscript:/i.test(serialized), "vbscript: scheme must be stripped from links");
  assert.ok(!/data:text\/html/i.test(serialized), "data: scheme must be stripped from links");

  // Raw HTML tags stay inert text tokens (React text children never execute HTML)
  assert.equal(blocks[0]?.type, "paragraph");
  if (blocks[0]?.type === "paragraph") {
    assert.deepEqual(blocks[0].tokens, [{ type: "text", value: "<script>alert(1)</script>" }]);
  }
  assert.equal(blocks[1]?.type, "paragraph");
  if (blocks[1]?.type === "paragraph") {
    assert.deepEqual(blocks[1].tokens, [{ type: "text", value: "<img src=x onerror=alert(1)>" }]);
  }

  // Link labels preserved safely as inert text / bold
  assert.equal(blocks[2]?.type, "paragraph");
  if (blocks[2]?.type === "paragraph") {
    assert.deepEqual(blocks[2].tokens, [
      { type: "text", value: "Bấm click hoặc " },
      { type: "bold", value: "đăng nhập" },
    ]);
  }

  // External link rendered strictly as inert plain text (never an <a> href)
  assert.equal(blocks[4]?.type, "paragraph");
  if (blocks[4]?.type === "paragraph") {
    assert.ok(blocks[4].tokens.every((tok) => tok.type === "text"));
    const combined = blocks[4].tokens.map((tok) => tok.value).join("");
    assert.ok(combined.includes("evil"));
    assert.ok(combined.includes("pixel"));
  }
});

test("streamAssistantChat posts payload with X-Case-Access-Token and dispatches all SSE events", async () => {
  const origFetch = globalThis.fetch;
  let capturedUrl = "";
  let capturedMethod = "";
  let capturedHeaders = new Headers();
  let capturedBody = "";

  const encoder = new TextEncoder();
  const sseFrames = [
    'event: status\ndata: {"phase":"retrieving","label":"Đang đối chiếu hồ sơ và kho tri thức..."}\n\n',
    'event: tool_status\ndata: {"tool":"check_url_safety","state":"running","label":"Đang kiểm tra đường dẫn an toàn..."}\n\n',
    'event: tool_status\ndata: {"tool":"check_url_safety","state":"done","label":"Đã hoàn tất kiểm tra đường dẫn"}\n\n',
    'event: safety_notice\ndata: {"code":"MERCHANT_BALANCE_REQUIRED","message":"Ảnh chụp biên lai không phải bằng chứng tiền đã vào tài khoản."}\n\n',
    'event: delta\ndata: {"text":"Hãy kiểm tra số dư "}\n\n',
    'event: delta\ndata: {"text":"trên ứng dụng ngân hàng."}\n\n',
    'event: citation\ndata: {"items":[{"id":"KB:sop_receipt","source_type":"kb","title":"Quy trình kiểm chứng biên lai"}]}\n\n',
    'event: evidence_report\ndata: {"draft_id":"draft_01","can_contribute_radar":true,"risk_score":86,"verdict":"CRITICAL_SCAM","receipt_verification_status":"TAMPER_OR_LOGIC_ANOMALY","summary_vi":"Phát hiện dấu hiệu chỉnh sửa."}\n\n',
    'event: done\ndata: {"degraded_mode":false,"output_tier":1,"suggested_followups":["Cách đối chiếu sao kê?"]}\n\n',
    'event: error\ndata: {"code":"STREAM_TIMEOUT","message":"Phản hồi quá thời gian chờ."}\n\n',
  ].join("");

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    capturedUrl = String(input);
    capturedMethod = init?.method ?? "";
    capturedHeaders = new Headers(init?.headers);
    capturedBody = typeof init?.body === "string" ? init.body : "";
    const bytes = encoder.encode(sseFrames);
    // Split across UTF-8 multi-byte chunk boundaries to verify streaming robustness
    const mid = Math.floor(bytes.length / 2);
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes.slice(0, mid));
          controller.enqueue(bytes.slice(mid));
          controller.close();
        },
      }),
      { status: 200, headers: { "Content-Type": "text/event-stream" } },
    );
  }) as typeof fetch;

  const payload: AssistantChatPayload = {
    case_id: "vs_9f2a4c8b7e1d6a30c5f28b91e4a7d012",
    message: "Tôi có nên giao hàng ngay không?",
    history: [{ role: "user", content: "Kiểm tra giúp biên lai này" }],
    quick_intent: "verify_info",
  };

  const statuses: AssistantStatusEvent[] = [];
  const toolStatuses: AssistantToolStatusEvent[] = [];
  const notices: AssistantSafetyNoticeEvent[] = [];
  const citations: AssistantCitationItem[][] = [];
  const evidenceReports: AssistantEvidenceReportEvent[] = [];
  const dones: AssistantDoneEvent[] = [];
  const errors: AssistantErrorEvent[] = [];
  let deltaText = "";

  try {
    await streamAssistantChat(payload, "tok_case_secret_123", {
      onStatus: (ev) => statuses.push(ev),
      onToolStatus: (ev) => toolStatuses.push(ev),
      onSafetyNotice: (ev) => notices.push(ev),
      onDelta: (text) => {
        deltaText += text;
      },
      onCitation: (items) => citations.push(items),
      onEvidenceReport: (ev) => evidenceReports.push(ev),
      onDone: (ev) => dones.push(ev),
      onError: (ev) => errors.push(ev),
    });

    assert.equal(capturedUrl, "/api/v1/assistant/chat/stream");
    assert.equal(capturedMethod, "POST");
    assert.equal(capturedHeaders.get("Content-Type"), "application/json");
    assert.equal(capturedHeaders.get("Accept"), "text/event-stream");
    assert.equal(capturedHeaders.get("X-Case-Access-Token"), "tok_case_secret_123");
    assert.deepEqual(JSON.parse(capturedBody), payload);

    assert.equal(statuses.length, 1);
    assert.equal(statuses[0]?.phase, "retrieving");
    assert.equal(toolStatuses.length, 2);
    assert.equal(toolStatuses[1]?.state, "done");
    assert.equal(notices.length, 1);
    assert.equal(notices[0]?.code, "MERCHANT_BALANCE_REQUIRED");
    assert.equal(deltaText, "Hãy kiểm tra số dư trên ứng dụng ngân hàng.");
    assert.equal(citations.length, 1);
    assert.equal(citations[0]?.[0]?.id, "KB:sop_receipt");
    assert.equal(evidenceReports.length, 1);
    assert.equal(evidenceReports[0]?.draft_id, "draft_01");
    assert.equal(dones.length, 1);
    assert.equal(dones[0]?.output_tier, 1);
    assert.deepEqual(dones[0]?.suggested_followups, ["Cách đối chiếu sao kê?"]);
    assert.equal(errors.length, 1);
    assert.equal(errors[0]?.code, "STREAM_TIMEOUT");
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("streamAssistantChat omits X-Case-Access-Token when null and maps HTTP 401/403/429/500 cleanly", async () => {
  const origFetch = globalThis.fetch;
  let capturedHasTokenHeader = true;

  // 1. Null token omits header
  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    capturedHasTokenHeader = headers.has("X-Case-Access-Token");
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(
            new TextEncoder().encode(
              'event: done\ndata: {"degraded_mode":false,"output_tier":2,"suggested_followups":[]}\n\n',
            ),
          );
          controller.close();
        },
      }),
      { status: 200, headers: { "Content-Type": "text/event-stream" } },
    );
  }) as typeof fetch;

  try {
    await streamAssistantChat(
      { case_id: null, message: "Dấu hiệu lừa đảo giả danh công an?", history: [] },
      null,
      {},
    );
    assert.equal(capturedHasTokenHeader, false);

    // 2. HTTP 403 -> Vietnamese expired session error
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ detail: "Invalid case access token signature" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;

    await assert.rejects(
      () =>
        streamAssistantChat(
          { case_id: "vs_123", message: "Giải thích hồ sơ", history: [] },
          "tok_expired",
          {},
        ),
      (err: unknown) =>
        err instanceof AssistantApiError &&
        err.status === 403 &&
        err.code === "CASE_AUTH_FAILED" &&
        /hết hạn|không hợp lệ/i.test(err.message) &&
        !err.message.includes("signature"),
    );

    // 3. HTTP 429 with Retry-After -> Vietnamese rate limit error with retryAfterSeconds
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ detail: "Rate limit exceeded" }), {
        status: 429,
        headers: { "Content-Type": "application/json", "Retry-After": "18" },
      })) as typeof fetch;

    await assert.rejects(
      () =>
        streamAssistantChat(
          { case_id: null, message: "Hỏi nhanh", history: [] },
          null,
          {},
        ),
      (err: unknown) =>
        err instanceof AssistantApiError &&
        err.status === 429 &&
        err.code === "RATE_LIMITED" &&
        err.retryAfterSeconds === 18 &&
        err.message.includes("18"),
    );

    // 4. HTTP 500 -> generic Vietnamese error without leaking internal trace
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ detail: "Traceback sqlite3 OperationalError secret_path" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;

    await assert.rejects(
      () =>
        streamAssistantChat(
          { case_id: null, message: "Hỏi nhanh", history: [] },
          null,
          {},
        ),
      (err: unknown) =>
        err instanceof AssistantApiError &&
        err.status === 500 &&
        !err.message.includes("Traceback") &&
        !err.message.includes("secret_path"),
    );

    // 5. HTTP 401 -> Vietnamese expired session error
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ detail: "Missing token" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;

    await assert.rejects(
      () =>
        streamAssistantChat(
          { case_id: "vs_401", message: "Giải thích", history: [] },
          null,
          {},
        ),
      (err: unknown) =>
        err instanceof AssistantApiError &&
        err.status === 401 &&
        err.code === "CASE_AUTH_FAILED" &&
        /hết hạn|không hợp lệ/i.test(err.message),
    );

    // 6. HTTP 429 turn cap -> TURN_CAP_REACHED friendly Vietnamese error
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ detail: "Exceeded 20 turns per case" }), {
        status: 429,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;

    await assert.rejects(
      () =>
        streamAssistantChat(
          { case_id: "vs_cap", message: "Hỏi tiếp", history: [] },
          "tok_ok",
          {},
        ),
      (err: unknown) =>
        err instanceof AssistantApiError &&
        err.status === 429 &&
        err.code === "TURN_CAP_REACHED" &&
        /giới hạn số lượt/i.test(err.message),
    );
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("parseSafeMarkdownBlocks strips HTML-entity obfuscated javascript schemes cleanly", () => {
  const md =
    "Thử [nhấn](&#106;avascript:alert(1)) và [xem](&#x6A;ava&#x09;script&colon;alert(2))";
  const blocks = parseSafeMarkdownBlocks(md);
  assert.equal(blocks.length, 1);
  if (blocks[0]?.type === "paragraph") {
    const text = blocks[0].tokens.map((t) => t.value).join("");
    assert.equal(text, "Thử nhấn và xem");
    assert.ok(!/alert|script/i.test(text));
  }
});

test("parseSafeMarkdownBlocks neutralizes nested links, angle-bracketed targets, and titled dangerous links", () => {
  const md = [
    "Nested: [[click](javascript:alert(1))](https://evil.vn)",
    "",
    'Angle+Title: [click](<javascript:alert(1)> "t")',
    "",
    "QuotedTitle: [open](javascript:alert(2) 'tooltip')",
    "",
    "DeepNest: [[[[[tap](javascript:alert(3))](https://a.vn)](https://b.vn)](https://c.vn)](https://d.vn)",
  ].join("\n");

  const blocks = parseSafeMarkdownBlocks(md);
  assert.equal(blocks.length, 4);

  const serialized = JSON.stringify(blocks);
  assert.ok(!/javascript:/i.test(serialized), "No javascript: scheme may survive nested/titled links");
  assert.ok(!serialized.includes("alert("), "No alert() payload from dangerous schemes may survive");
  assert.ok(!serialized.includes('"href"'), "AST must never contain href keys");

  if (blocks[0]?.type === "paragraph") {
    const line0 = blocks[0].tokens.map((t) => t.value).join("");
    assert.equal(line0, "Nested: click (https://evil.vn)");
  }
  if (blocks[1]?.type === "paragraph") {
    const line1 = blocks[1].tokens.map((t) => t.value).join("");
    assert.equal(line1, "Angle+Title: click");
  }
  if (blocks[2]?.type === "paragraph") {
    const line2 = blocks[2].tokens.map((t) => t.value).join("");
    assert.equal(line2, "QuotedTitle: open");
  }
});

test("parseSafeMarkdownBlocks processes pathological unclosed bracket/paren inputs in linear time", () => {
  const pathological1 = "[".repeat(20000);
  const pathological2 = "[a](".repeat(5000);
  const pathological3 = `${"[".repeat(15000)}]`;
  const pathological4 = `${"[a](".repeat(4000)})`;

  const start = performance.now();
  const b1 = parseSafeMarkdownBlocks(pathological1);
  const b2 = parseSafeMarkdownBlocks(pathological2);
  const b3 = parseSafeMarkdownBlocks(pathological3);
  const b4 = parseSafeMarkdownBlocks(pathological4);
  const elapsedMs = performance.now() - start;

  assert.equal(b1.length, 1);
  assert.equal(b2.length, 1);
  assert.equal(b3.length, 1);
  assert.equal(b4.length, 1);
  assert.ok(
    elapsedMs < 100,
    `Pathological unclosed link inputs took ${elapsedMs.toFixed(1)}ms (expected linear-time < 100ms)`,
  );
});

test("streamAssistantEvidenceChat posts FormData with X-Case-Access-Token and parses evidence_report SSE", async () => {
  const origFetch = globalThis.fetch;
  let capturedUrl = "";
  let capturedMethod = "";
  let capturedHeaders = new Headers();
  let capturedBody: BodyInit | null | undefined;

  const encoder = new TextEncoder();
  const sseFrames = [
    'event: status\ndata: {"phase":"retrieving","label":"Đang phân tích bằng chứng bổ sung ở chế độ riêng tư cục bộ..."}\n\n',
    'event: evidence_report\ndata: {"draft_id":"drf_0123456789abcdef0123456789abcdef","can_contribute_radar":true,"risk_score":88,"verdict":"CRITICAL_SCAM","receipt_verification_status":"REPLAYED_RECEIPT","summary_vi":"Phát hiện biên lai trùng lặp."}\n\n',
    'event: safety_notice\ndata: {"code":"MERCHANT_BALANCE_REQUIRED","message":"Ảnh chụp biên lai không phải bằng chứng tiền đã vào tài khoản."}\n\n',
    'event: delta\ndata: {"text":"Bằng chứng bổ sung đã được xử lý cục bộ."}\n\n',
    'event: done\ndata: {"degraded_mode":false,"output_tier":0,"suggested_followups":["Cách đối chiếu sao kê?"]}\n\n',
  ].join("");

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    capturedUrl = String(input);
    capturedMethod = init?.method ?? "";
    capturedHeaders = new Headers(init?.headers);
    capturedBody = init?.body;
    const bytes = encoder.encode(sseFrames);
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      }),
      { status: 200, headers: { "Content-Type": "text/event-stream" } },
    );
  }) as typeof fetch;

  const formData = new FormData();
  formData.append("case_id", "vs_parent_123");
  formData.append("message", "Kiểm tra giúp ảnh này");
  formData.append("allow_external_media_ai", "false");

  const evidenceReports: AssistantEvidenceReportEvent[] = [];
  const notices: AssistantSafetyNoticeEvent[] = [];
  const dones: AssistantDoneEvent[] = [];
  let deltaText = "";

  try {
    await streamAssistantEvidenceChat(formData, "tok_parent_secret", {
      onEvidenceReport: (ev) => evidenceReports.push(ev),
      onSafetyNotice: (ev) => notices.push(ev),
      onDelta: (t) => {
        deltaText += t;
      },
      onDone: (ev) => dones.push(ev),
    });

    assert.equal(capturedUrl, "/api/v1/assistant/chat/evidence/stream");
    assert.equal(capturedMethod, "POST");
    assert.equal(capturedHeaders.get("X-Case-Access-Token"), "tok_parent_secret");
    assert.equal(capturedHeaders.get("Accept"), "text/event-stream");
    assert.equal(capturedHeaders.has("Content-Type"), false);
    assert.ok(capturedBody instanceof FormData);

    assert.equal(evidenceReports.length, 1);
    assert.equal(evidenceReports[0]?.draft_id, "drf_0123456789abcdef0123456789abcdef");
    assert.equal(evidenceReports[0]?.receipt_verification_status, "REPLAYED_RECEIPT");
    assert.equal(notices.length, 1);
    assert.equal(deltaText, "Bằng chứng bổ sung đã được xử lý cục bộ.");
    assert.equal(dones[0]?.output_tier, 0);

    // 413 oversize error mapped cleanly in Vietnamese
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ detail: "Payload exceeds 10 MB" }), {
        status: 413,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;

    await assert.rejects(
      () => streamAssistantEvidenceChat(formData, "tok_parent_secret", {}),
      (err: unknown) =>
        err instanceof AssistantApiError &&
        err.status === 413 &&
        err.code === "VALIDATION_ERROR" &&
        /10\s*MB/i.test(err.message),
    );
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("persistAssistantEvidence handles 200 success, 403 auth failure, and 404 expired draft", async () => {
  const origFetch = globalThis.fetch;
  let capturedUrl = "";
  let capturedHeaders = new Headers();
  let capturedBody = "";

  const mockResp: PersistEvidenceResponse = {
    child_case_id: "vs_child_0123456789abcdef0123456789",
    child_case_access_token: "tok_child_secret_456",
    expires_at: "2026-11-27T09:00:00+00:00",
    contributed_to_radar: true,
    parent_case_id: "vs_parent_123",
  };

  try {
    // 1. 200 OK
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = String(input);
      capturedHeaders = new Headers(init?.headers);
      capturedBody = typeof init?.body === "string" ? init.body : "";
      return new Response(JSON.stringify(mockResp), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    const saved = await persistAssistantEvidence(
      "drf_abc123",
      "vs_parent_123",
      true,
      "tok_parent_secret",
    );
    assert.equal(capturedUrl, "/api/v1/assistant/evidence/drf_abc123/persist");
    assert.equal(capturedHeaders.get("Content-Type"), "application/json");
    assert.equal(capturedHeaders.get("X-Case-Access-Token"), "tok_parent_secret");
    assert.deepEqual(JSON.parse(capturedBody), {
      case_id: "vs_parent_123",
      contribute_to_radar: true,
    });
    assert.deepEqual(saved, mockResp);

    // 2. Missing/null token rejects locally with 403 CASE_AUTH_FAILED
    await assert.rejects(
      () => persistAssistantEvidence("drf_abc123", "vs_parent_123", false, null),
      (err: unknown) =>
        err instanceof AssistantApiError &&
        err.status === 403 &&
        err.code === "CASE_AUTH_FAILED",
    );

    // 3. HTTP 403 from server -> CASE_AUTH_FAILED
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ detail: "Invalid token" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;

    await assert.rejects(
      () => persistAssistantEvidence("drf_abc123", "vs_parent_123", false, "tok_bad"),
      (err: unknown) =>
        err instanceof AssistantApiError &&
        err.status === 403 &&
        err.code === "CASE_AUTH_FAILED" &&
        /hết hạn|không hợp lệ/i.test(err.message),
    );

    // 4. HTTP 404 expired / already persisted -> NOT_FOUND
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ detail: "Draft expired" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;

    await assert.rejects(
      () => persistAssistantEvidence("drf_abc123", "vs_parent_123", false, "tok_parent_secret"),
      (err: unknown) =>
        err instanceof AssistantApiError &&
        err.status === 404 &&
        err.code === "NOT_FOUND" &&
        /15 phút|hết hạn|đã được lưu/i.test(err.message),
    );
  } finally {
    globalThis.fetch = origFetch;
  }
});
