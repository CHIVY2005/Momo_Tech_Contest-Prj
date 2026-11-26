export interface ParsedSseEvent {
  event: string;
  data: unknown;
}

/**
 * Parse incremental SSE text buffer into complete events and retain any incomplete trailing frame.
 * Handles both LF (\n\n) and CRLF (\r\n\r\n) frame delimiters, heartbeat comments, and multi-line data.
 */
export function parseSseChunks(buffer: string): {
  events: ParsedSseEvent[];
  rest: string;
} {
  const events: ParsedSseEvent[] = [];
  const delimiterRegex = /\r?\n\r?\n/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null = delimiterRegex.exec(buffer);

  while (match !== null) {
    const rawBlock = buffer.slice(lastIndex, match.index);
    lastIndex = match.index + match[0].length;

    const lines = rawBlock.split(/\r?\n/);
    let eventName = "message";
    const dataLines: string[] = [];

    for (const line of lines) {
      if (!line || line.startsWith(":")) {
        continue;
      }
      if (line.startsWith("event:")) {
        eventName = line.slice(6).trim() || "message";
      } else if (line.startsWith("data:")) {
        const value = line.slice(5);
        dataLines.push(value.startsWith(" ") ? value.slice(1) : value);
      }
    }

    if (dataLines.length > 0) {
      const joined = dataLines.join("\n");
      let parsedData: unknown = joined;
      try {
        parsedData = JSON.parse(joined);
      } catch {
        parsedData = joined;
      }
      events.push({ event: eventName, data: parsedData });
    }

    match = delimiterRegex.exec(buffer);
  }

  return {
    events,
    rest: buffer.slice(lastIndex),
  };
}

/**
 * Consume a ReadableStream<Uint8Array> SSE response safely across multi-byte UTF-8 boundaries.
 * Dispatches strictly frame-terminated (\n\n or \r\n\r\n) events; discards truncated EOF tails.
 */
export async function consumeUtf8SseStream(
  stream: ReadableStream<Uint8Array>,
  onEvent: (ev: ParsedSseEvent) => void,
): Promise<void> {
  const reader = stream.getReader();
  const decoder = new TextDecoder("utf-8");
  let carry = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        carry += decoder.decode();
        const { events } = parseSseChunks(carry);
        for (const ev of events) {
          onEvent(ev);
        }
        break;
      }
      carry += decoder.decode(value, { stream: true });
      const { events, rest } = parseSseChunks(carry);
      carry = rest;
      for (const ev of events) {
        onEvent(ev);
      }
    }
  } finally {
    reader.releaseLock();
  }
}
