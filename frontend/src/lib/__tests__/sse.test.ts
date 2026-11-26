import assert from "node:assert/strict";
import test from "node:test";

import { consumeUtf8SseStream, type ParsedSseEvent, parseSseChunks } from "../sse.ts";

test("parseSseChunks reconstructs Vietnamese JSON events split across arbitrary chunk boundaries", () => {
  const fullStream =
    'event: trace\ndata: {"step_id":"media_forensics","title":"Pháp y ảnh & VietQR","status":"done","detail":"Đã quét 1 mã QR","duration_ms":18}\n\n' +
    'event: result\r\ndata: {"case_id":"vs_demo01","verdict":"CRITICAL_SCAM","summary_vi":"Cảnh báo giả danh Công an thúc ép chuyển khoản"}\r\n\r\n' +
    'event: trace\ndata: {"step_id":"incomplete"';

  const part1 = fullStream.slice(0, 47);
  const part2 = fullStream.slice(47, 155);
  const part3 = fullStream.slice(155);

  const first = parseSseChunks(part1);
  assert.equal(first.events.length, 0);
  assert.equal(first.rest, part1);

  const second = parseSseChunks(first.rest + part2);
  assert.equal(second.events.length, 1);
  assert.equal(second.events[0]?.event, "trace");
  assert.deepEqual(second.events[0]?.data, {
    step_id: "media_forensics",
    title: "Pháp y ảnh & VietQR",
    status: "done",
    detail: "Đã quét 1 mã QR",
    duration_ms: 18,
  });

  const third = parseSseChunks(second.rest + part3);
  assert.equal(third.events.length, 1);
  assert.equal(third.events[0]?.event, "result");
  assert.deepEqual(third.events[0]?.data, {
    case_id: "vs_demo01",
    verdict: "CRITICAL_SCAM",
    summary_vi: "Cảnh báo giả danh Công an thúc ép chuyển khoản",
  });
  assert.equal(third.rest, 'event: trace\ndata: {"step_id":"incomplete"');
});

test("parseSseChunks ignores SSE comment heartbeats and preserves newlines across multi-line data fields", () => {
  const raw =
    ": keep-alive\n\n" +
    'event: custom\ndata: {"hello":\ndata: "xin chào Việt Nam"}\n\n' +
    "event: note\ndata: dòng thứ nhất\ndata: dòng thứ hai\n\n";
  const parsed = parseSseChunks(raw);
  assert.equal(parsed.events.length, 2);
  assert.equal(parsed.events[0]?.event, "custom");
  assert.deepEqual(parsed.events[0]?.data, { hello: "xin chào Việt Nam" });
  assert.equal(parsed.events[1]?.event, "note");
  assert.equal(parsed.events[1]?.data, "dòng thứ nhất\ndòng thứ hai");
  assert.equal(parsed.rest, "");
});

test("consumeUtf8SseStream preserves multi-byte UTF-8 Vietnamese characters split mid-codepoint", async () => {
  const payload =
    'event: trace\ndata: {"step_id":"onnx_and_kb","detail":"Đối chiếu ngữ nghĩa tiếng Việt chuẩn xác 100%"}\n\n';
  const encoded = new TextEncoder().encode(payload);

  // Split every 5 bytes so multi-byte UTF-8 codepoints (Đ, ố, ữ, ĩ, ệ) are sliced mid-character
  const byteStream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (let offset = 0; offset < encoded.length; offset += 5) {
        controller.enqueue(encoded.subarray(offset, offset + 5));
      }
      controller.close();
    },
  });

  const received: ParsedSseEvent[] = [];
  await consumeUtf8SseStream(byteStream, (ev) => received.push(ev));

  assert.equal(received.length, 1);
  assert.deepEqual(received[0]?.data, {
    step_id: "onnx_and_kb",
    detail: "Đối chiếu ngữ nghĩa tiếng Việt chuẩn xác 100%",
  });
});
