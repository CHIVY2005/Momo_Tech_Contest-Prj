/**
 * Pure-TS Safe Markdown parser for "Trợ lý VeriShield" responses.
 * Zero React/JSX imports, zero HTML execution, O(N) bounded scanning.
 * Supports nested ordered/unordered lists (preserving native HTML numbering & start),
 * loose lists, continuation paragraphs, fenced code blocks, blockquotes, headings,
 * bold/italic/inline-code (safe around masked IOCs like 19****01), and verified official
 * hyperlinks while keeping untrusted external URLs and dangerous schemes strictly inert.
 */

export type SafeInlineToken =
  | { type: "text"; value: string }
  | { type: "bold"; value: string }
  | { type: "italic"; value: string }
  | { type: "code"; value: string }
  | { type: "link"; value: string; href: string; external: boolean };

export interface SafeMarkdownListItem {
  tokens: SafeInlineToken[];
  children: SafeMarkdownBlock[];
}

export type SafeMarkdownBlock =
  | { type: "heading"; level: 1 | 2 | 3; tokens: SafeInlineToken[] }
  | { type: "paragraph"; tokens: SafeInlineToken[] }
  | { type: "code_block"; language: string; code: string }
  | { type: "blockquote"; blocks: SafeMarkdownBlock[] }
  | { type: "ul"; items: SafeMarkdownListItem[] }
  | { type: "ol"; start: number; items: SafeMarkdownListItem[] };

const DANGEROUS_SCHEME_RE = /^(?:javascript|vbscript|data|file|blob):/i;
const INLINE_DANGEROUS_SCHEME_RE =
  /(?:javascript|vbscript|data|file|blob)\s*:[^\s)\]>'"]*/gi;
const TRAILING_LINK_TITLE_RE = /\s+(?:"[^"\n]*"|'[^'\n]*')\s*$/;
const HEADING_RE = /^(#{1,6})\s+(.+)$/;
const HORIZONTAL_RULE_RE = /^(?:[-*_]\s*){3,}$/;
const FENCE_OPEN_RE = /^(`{3,}|~{3,})([A-Za-z0-9_+-]{0,24})?\s*$/;
const UL_MARKER_RE = /^([-*•])[ \t]+(.*)$/;
const OL_MARKER_RE = /^(\d{1,9})([.)])[ \t]+(.*)$/;
const PARTIAL_OL_EOF_RE = /^\d{1,9}([.)])$/;
const SAFE_INTERNAL_ROUTE_RE =
  /^\/(?:radar|privacy|technical)?(?:[?#][A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]*)?$/;
const STRICT_ASCII_HOST_RE = /^[a-z0-9.-]+$/;

const VERIFIED_OFFICIAL_DOMAINS: readonly string[] = [
  "canhbao.khonggianmang.vn",
  "khonggianmang.vn",
  "napas.com.vn",
  "vietcombank.com.vn",
  "techcombank.com.vn",
  "bidv.com.vn",
  "mbbank.com.vn",
  "vietinbank.vn",
  "agribank.com.vn",
  "acb.com.vn",
  "vpbank.com.vn",
  "tpb.vn",
  "sacombank.com.vn",
  "hdbank.com.vn",
  "vib.com.vn",
  "shb.com.vn",
  "ocb.com.vn",
  "msb.com.vn",
  "seabank.com.vn",
  "evn.com.vn",
  "shopee.vn",
  "verishield.joiboi.app",
];

const MAX_LINK_LABEL_CHARS = 256;
const MAX_LINK_TARGET_CHARS = 1024;
const MAX_NESTED_BRACKETS = 8;
const MAX_NESTED_PARENS = 8;
const MAX_NEUTRALIZE_DEPTH = 4;
const MAX_BLOCK_DEPTH = 6;

function decodeNumericHtmlEntities(raw: string): string {
  return raw
    .replace(/&#x([0-9a-f]+);?/gi, (_m, hex: string) => {
      const code = Number.parseInt(hex, 16);
      return Number.isFinite(code) && code >= 0 && code <= 0x10ffff
        ? String.fromCodePoint(code)
        : "";
    })
    .replace(/&#(\d+);?/g, (_m, dec: string) => {
      const code = Number.parseInt(dec, 10);
      return Number.isFinite(code) && code >= 0 && code <= 0x10ffff
        ? String.fromCodePoint(code)
        : "";
    })
    .replace(/&colon;/gi, ":");
}

function extractLinkDestination(rawTarget: string): string {
  const trimmed = rawTarget.trim();
  if (trimmed.startsWith("<")) {
    const closeAngle = trimmed.indexOf(">");
    if (closeAngle > 0) {
      return trimmed.slice(1, closeAngle).trim();
    }
    return trimmed.slice(1).trim();
  }
  return trimmed.replace(TRAILING_LINK_TITLE_RE, "").trim();
}

function hasDangerousScheme(target: string): boolean {
  const decoded = decodeNumericHtmlEntities(target);
  const compact = decoded.replace(/[\u0000-\u0020\u007f]+/g, "");
  return DANGEROUS_SCHEME_RE.test(compact);
}

function stripResidualDangerousSchemes(text: string): string {
  const decoded = decodeNumericHtmlEntities(text);
  return decoded.replace(INLINE_DANGEROUS_SCHEME_RE, "");
}

function isOfficialHostname(hostname: string): boolean {
  if (!hostname || !STRICT_ASCII_HOST_RE.test(hostname)) return false;
  if (hostname.includes("..") || hostname.startsWith(".") || hostname.endsWith(".")) return false;
  const labels = hostname.split(".");
  if (labels.some((lbl) => !lbl || lbl.startsWith("xn--"))) return false;

  if (hostname.endsWith(".gov.vn") && labels.length >= 3) {
    return true;
  }
  return VERIFIED_OFFICIAL_DOMAINS.some(
    (allowed) => hostname === allowed || hostname.endsWith(`.${allowed}`),
  );
}

function resolveVerifiedSafeHref(
  destination: string,
): { href: string; external: boolean } | null {
  if (!destination || /[\u0000-\u0020\u007f\\]/.test(destination)) {
    return null;
  }
  if (destination.startsWith("/") && !destination.startsWith("//")) {
    if (SAFE_INTERNAL_ROUTE_RE.test(destination)) {
      return { href: destination, external: false };
    }
    return null;
  }
  if (!/^https:\/\//i.test(destination)) {
    return null;
  }
  try {
    const parsed = new URL(destination);
    if (
      parsed.protocol !== "https:" ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.port !== ""
    ) {
      return null;
    }
    const host = parsed.hostname.toLowerCase();
    if (!isOfficialHostname(host)) {
      return null;
    }
    return { href: parsed.toString(), external: true };
  } catch {
    return null;
  }
}

interface ParsedLinkSpan {
  endIndex: number;
  inertText: string;
  safeLink?: { label: string; href: string; external: boolean };
}

/**
 * Match a markdown link `[label](url)` or image `![alt](url)` starting at `startIndex`
 * with bounded lookahead & nesting limits (guaranteeing linear-time scanning).
 * Emits a safe hyperlink ONLY for verified official HTTPS domains or internal routes;
 * all other external URLs and dangerous schemes become strictly inert plain text.
 */
function tryConsumeMarkdownLinkOrImage(
  text: string,
  startIndex: number,
  lastCloseBracket: number,
  lastCloseParen: number,
  depth: number,
  allowSafeLink: boolean,
): ParsedLinkSpan | null {
  const isImage = text[startIndex] === "!" && text[startIndex + 1] === "[";
  const openBracket = isImage ? startIndex + 1 : startIndex;
  if (text[openBracket] !== "[") {
    return null;
  }
  if (lastCloseBracket <= openBracket || lastCloseParen <= openBracket + 2) {
    return null;
  }

  let bracketDepth = 1;
  let closeBracket = -1;
  const maxBracketScan = Math.min(
    text.length,
    openBracket + 1 + MAX_LINK_LABEL_CHARS,
    lastCloseBracket + 1,
  );
  for (let i = openBracket + 1; i < maxBracketScan; i += 1) {
    const ch = text[i];
    if (ch === "\n") return null;
    if (ch === "[") {
      bracketDepth += 1;
      if (bracketDepth > MAX_NESTED_BRACKETS) {
        return null;
      }
    } else if (ch === "]") {
      bracketDepth -= 1;
      if (bracketDepth === 0) {
        closeBracket = i;
        break;
      }
    }
  }
  if (closeBracket === -1 || text[closeBracket + 1] !== "(") {
    return null;
  }

  let parenDepth = 1;
  let closeParen = -1;
  const maxParenScan = Math.min(
    text.length,
    closeBracket + 2 + MAX_LINK_TARGET_CHARS,
    lastCloseParen + 1,
  );
  for (let i = closeBracket + 2; i < maxParenScan; i += 1) {
    const ch = text[i];
    if (ch === "\n") return null;
    if (ch === "(") {
      parenDepth += 1;
      if (parenDepth > MAX_NESTED_PARENS) {
        return null;
      }
    } else if (ch === ")") {
      parenDepth -= 1;
      if (parenDepth === 0) {
        closeParen = i;
        break;
      }
    }
  }
  if (closeParen === -1) {
    return null;
  }

  const rawLabel = text.slice(openBracket + 1, closeBracket).trim();
  const label = neutralizeLinksInPlainString(rawLabel, depth + 1).trim();
  const rawTarget = text.slice(closeBracket + 2, closeParen).trim();
  const destination = extractLinkDestination(rawTarget);

  if (hasDangerousScheme(destination) || hasDangerousScheme(rawTarget.replace(/^</, ""))) {
    return {
      endIndex: closeParen + 1,
      inertText: label,
    };
  }

  if (isImage) {
    return {
      endIndex: closeParen + 1,
      inertText: label,
    };
  }

  if (allowSafeLink && depth === 0) {
    const verified = resolveVerifiedSafeHref(destination);
    if (verified) {
      const displayLabel = label || destination;
      return {
        endIndex: closeParen + 1,
        inertText: displayLabel,
        safeLink: {
          label: displayLabel,
          href: verified.href,
          external: verified.external,
        },
      };
    }
  }

  if (!label) {
    return {
      endIndex: closeParen + 1,
      inertText: destination,
    };
  }
  if (!destination || label === destination) {
    return {
      endIndex: closeParen + 1,
      inertText: label,
    };
  }
  return {
    endIndex: closeParen + 1,
    inertText: `${label} (${destination})`,
  };
}

function neutralizeLinksInPlainString(input: string, depth = 0): string {
  if (!input) return "";
  if (depth > MAX_NEUTRALIZE_DEPTH) {
    return stripResidualDangerousSchemes(input);
  }
  const lastCloseBracket = input.lastIndexOf("]");
  const lastCloseParen = input.lastIndexOf(")");
  if (lastCloseBracket === -1 || lastCloseParen === -1) {
    return input;
  }

  let out = "";
  let i = 0;
  while (i < input.length) {
    if (input[i] === "[" || (input[i] === "!" && input[i + 1] === "[")) {
      const consumed = tryConsumeMarkdownLinkOrImage(
        input,
        i,
        lastCloseBracket,
        lastCloseParen,
        depth,
        false,
      );
      if (consumed) {
        out += consumed.inertText;
        i = consumed.endIndex;
        continue;
      }
    }
    out += input[i] ?? "";
    i += 1;
  }
  return out;
}

function pushToken(tokens: SafeInlineToken[], token: SafeInlineToken): void {
  if (token.type === "link") {
    if (!token.value || !token.href) return;
    tokens.push(token);
    return;
  }
  if (!token.value) return;
  const prev = tokens[tokens.length - 1];
  if (token.type === "text" && prev?.type === "text") {
    prev.value += token.value;
    return;
  }
  tokens.push(token);
}

function countCharRun(text: string, start: number, target: string): number {
  let end = start;
  while (end < text.length && text[end] === target) {
    end += 1;
  }
  return end - start;
}

function isWhitespaceChar(ch: string | undefined): boolean {
  return ch === undefined || /\s/.test(ch);
}

/**
 * Find closing `**` starting at `fromIndex` while skipping 3+ asterisk runs (such as masked
 * IOCs `19****01`) so masked numbers inside or beside bold spans never corrupt emphasis.
 */
function findClosingDoubleStar(input: string, fromIndex: number, lastDoubleStar: number): number {
  let j = fromIndex;
  while (j <= lastDoubleStar) {
    if (input[j] === "*") {
      const run = countCharRun(input, j, "*");
      if (run === 2 && j > fromIndex && !isWhitespaceChar(input[j - 1])) {
        return j;
      }
      j += run;
      continue;
    }
    j += 1;
  }
  return -1;
}

function findClosingSingleStar(input: string, fromIndex: number, lastSingleStar: number): number {
  let j = fromIndex;
  while (j <= lastSingleStar) {
    if (input[j] === "*") {
      const run = countCharRun(input, j, "*");
      if (run === 1 && j > fromIndex && !isWhitespaceChar(input[j - 1])) {
        return j;
      }
      j += run;
      continue;
    }
    j += 1;
  }
  return -1;
}

export function parseSafeInlineTokens(input: string): SafeInlineToken[] {
  const tokens: SafeInlineToken[] = [];
  const lastBacktick = input.lastIndexOf("`");
  const lastDoubleStar = input.lastIndexOf("**");
  const lastSingleStar = input.lastIndexOf("*");
  const lastCloseBracket = input.lastIndexOf("]");
  const lastCloseParen = input.lastIndexOf(")");
  let noBoldClose = false;
  let noItalicClose = false;
  let i = 0;

  while (i < input.length) {
    const ch = input[i];

    // 1. Inline code span: `...`
    if (ch === "`" && i < lastBacktick) {
      const closeTick = input.indexOf("`", i + 1);
      if (closeTick > i + 1) {
        const codeValue = input.slice(i + 1, closeTick);
        pushToken(tokens, { type: "code", value: codeValue });
        i = closeTick + 1;
        continue;
      }
    }

    // 2. Asterisk runs: preserve 3+ stars verbatim (e.g. masked IOCs 19****01),
    //    parse **bold** and *italic* safely in strict O(N) time.
    if (ch === "*") {
      const starRun = countCharRun(input, i, "*");
      if (starRun >= 3) {
        pushToken(tokens, { type: "text", value: input.slice(i, i + starRun) });
        i += starRun;
        continue;
      }

      if (starRun === 2 && !noBoldClose && i + 2 <= lastDoubleStar && !isWhitespaceChar(input[i + 2])) {
        const closeBold = findClosingDoubleStar(input, i + 2, lastDoubleStar);
        if (closeBold > i + 2) {
          const rawInner = input.slice(i + 2, closeBold);
          const safeInner = neutralizeLinksInPlainString(rawInner, 0);
          pushToken(tokens, { type: "bold", value: safeInner });
          i = closeBold + 2;
          continue;
        }
        noBoldClose = true;
      }

      if (
        starRun === 1 &&
        !noItalicClose &&
        i + 1 <= lastSingleStar &&
        !isWhitespaceChar(input[i + 1]) &&
        (i === 0 || !/[A-Za-z0-9]/.test(input[i - 1] ?? ""))
      ) {
        const closeItalic = findClosingSingleStar(input, i + 1, lastSingleStar);
        if (closeItalic > i + 1) {
          const rawInner = input.slice(i + 1, closeItalic);
          const safeInner = neutralizeLinksInPlainString(rawInner, 0);
          pushToken(tokens, { type: "italic", value: safeInner });
          i = closeItalic + 1;
          continue;
        }
        noItalicClose = true;
      }

      pushToken(tokens, { type: "text", value: input.slice(i, i + starRun) });
      i += starRun;
      continue;
    }

    // 3. Markdown link [label](url) or image ![alt](url)
    if (ch === "[" || (ch === "!" && input[i + 1] === "[")) {
      const consumed = tryConsumeMarkdownLinkOrImage(
        input,
        i,
        lastCloseBracket,
        lastCloseParen,
        0,
        true,
      );
      if (consumed) {
        if (consumed.safeLink) {
          pushToken(tokens, {
            type: "link",
            value: consumed.safeLink.label,
            href: consumed.safeLink.href,
            external: consumed.safeLink.external,
          });
        } else {
          pushToken(tokens, { type: "text", value: consumed.inertText });
        }
        i = consumed.endIndex;
        continue;
      }
    }

    pushToken(tokens, { type: "text", value: ch ?? "" });
    i += 1;
  }

  return tokens;
}

interface IndentInfo {
  indent: number;
  rest: string;
}

function measureIndent(line: string): IndentInfo {
  let col = 0;
  let idx = 0;
  while (idx < line.length) {
    const ch = line[idx];
    if (ch === " ") {
      col += 1;
      idx += 1;
    } else if (ch === "\t") {
      const step = 4 - (col % 4);
      col += step;
      idx += 1;
    } else {
      break;
    }
  }
  return { indent: col, rest: line.slice(idx) };
}

function stripIndentColumns(line: string, columnsToStrip: number): string {
  if (columnsToStrip <= 0 || !line) return line;
  let col = 0;
  let idx = 0;
  while (idx < line.length && col < columnsToStrip) {
    const ch = line[idx];
    if (ch === " ") {
      col += 1;
      idx += 1;
    } else if (ch === "\t") {
      const step = 4 - (col % 4);
      if (col + step > columnsToStrip) {
        const remaining = col + step - columnsToStrip;
        return " ".repeat(remaining) + line.slice(idx + 1);
      }
      col += step;
      idx += 1;
    } else {
      break;
    }
  }
  return line.slice(idx);
}

interface ListMarkerMatch {
  type: "ul" | "ol";
  indent: number;
  delimiter: string;
  number: number;
  contentIndent: number;
  content: string;
}

function matchListMarker(line: string): ListMarkerMatch | null {
  const { indent, rest } = measureIndent(line);
  if (!rest || HORIZONTAL_RULE_RE.test(rest.trim())) {
    return null;
  }

  const ulMatch = UL_MARKER_RE.exec(rest);
  if (ulMatch) {
    const marker = ulMatch[1] ?? "-";
    const content = ulMatch[2] ?? "";
    const markerPrefixLen = rest.length - content.length;
    return {
      type: "ul",
      indent,
      delimiter: marker,
      number: 1,
      contentIndent: indent + Math.max(2, markerPrefixLen),
      content,
    };
  }

  const olMatch = OL_MARKER_RE.exec(rest);
  if (olMatch) {
    const numStr = olMatch[1] ?? "1";
    const delim = olMatch[2] ?? ".";
    const content = olMatch[3] ?? "";
    const num = Number.parseInt(numStr, 10);
    const markerPrefixLen = rest.length - content.length;
    return {
      type: "ol",
      indent,
      delimiter: delim,
      number: Number.isFinite(num) && num >= 0 ? num : 1,
      contentIndent: indent + Math.max(3, markerPrefixLen),
      content,
    };
  }

  return null;
}

function isBlockStarter(trimmed: string): boolean {
  if (!trimmed) return false;
  if (HORIZONTAL_RULE_RE.test(trimmed)) return true;
  if (FENCE_OPEN_RE.test(trimmed)) return true;
  if (HEADING_RE.test(trimmed)) return true;
  if (trimmed.startsWith(">")) return true;
  return false;
}

function isClosingFence(trimmed: string, fenceChar: string, fenceLen: number): boolean {
  if (!trimmed || trimmed[0] !== fenceChar) return false;
  const run = countCharRun(trimmed, 0, fenceChar);
  return run >= fenceLen && trimmed.slice(run).trim() === "";
}

function isSameListSibling(
  marker: ListMarkerMatch,
  listType: "ul" | "ol",
  delimiter: string,
  baseIndent: number,
  childThreshold: number,
): boolean {
  if (marker.type !== listType) return false;
  if (listType === "ol" && marker.delimiter !== delimiter) return false;
  return marker.indent >= baseIndent && marker.indent < childThreshold;
}

function dedentBodyLines(rawBodyLines: string[], maxStrip: number): string[] {
  let minPositiveIndent = Number.POSITIVE_INFINITY;
  for (const line of rawBodyLines) {
    if (!line.trim()) continue;
    const { indent } = measureIndent(line);
    if (indent > 0 && indent < minPositiveIndent) {
      minPositiveIndent = indent;
    }
  }
  const stripCols = Number.isFinite(minPositiveIndent)
    ? Math.min(maxStrip, minPositiveIndent)
    : maxStrip;
  return rawBodyLines.map((line) => (line.trim() ? stripIndentColumns(line, stripCols) : ""));
}

function parseBlockLines(lines: string[], depth: number): SafeMarkdownBlock[] {
  const blocks: SafeMarkdownBlock[] = [];
  let paragraphLines: string[] = [];

  function flushParagraph(): void {
    if (paragraphLines.length === 0) return;
    const joined = paragraphLines.join(" ").trim();
    paragraphLines = [];
    if (!joined) return;
    const tokens = parseSafeInlineTokens(joined);
    if (tokens.length > 0) {
      blocks.push({ type: "paragraph", tokens });
    }
  }

  let i = 0;
  while (i < lines.length) {
    const rawLine = lines[i] ?? "";
    const { indent, rest } = measureIndent(rawLine);
    const trimmed = rest.trim();

    if (!trimmed) {
      flushParagraph();
      i += 1;
      continue;
    }

    // 1. Fenced code block (``` or ~~~)
    const fenceMatch = FENCE_OPEN_RE.exec(trimmed);
    if (fenceMatch) {
      flushParagraph();
      const fenceSeq = fenceMatch[1] ?? "```";
      const fenceChar = fenceSeq[0] ?? "`";
      const fenceLen = fenceSeq.length;
      const language = (fenceMatch[2] ?? "").trim();
      const codeLines: string[] = [];
      i += 1;
      while (i < lines.length) {
        const candidate = lines[i] ?? "";
        const candTrimmed = candidate.trim();
        if (isClosingFence(candTrimmed, fenceChar, fenceLen)) {
          i += 1;
          break;
        }
        codeLines.push(stripIndentColumns(candidate, indent));
        i += 1;
      }
      blocks.push({
        type: "code_block",
        language,
        code: codeLines.join("\n"),
      });
      continue;
    }

    // 2. Horizontal rule
    if (HORIZONTAL_RULE_RE.test(trimmed)) {
      flushParagraph();
      i += 1;
      continue;
    }

    // 3. Heading (#, ##, ###)
    const headingMatch = HEADING_RE.exec(trimmed);
    if (headingMatch) {
      flushParagraph();
      const hashCount = headingMatch[1]?.length ?? 1;
      const level = Math.min(3, Math.max(1, hashCount)) as 1 | 2 | 3;
      const headingText = headingMatch[2]?.trim() ?? "";
      const tokens = parseSafeInlineTokens(headingText);
      if (tokens.length > 0) {
        blocks.push({ type: "heading", level, tokens });
      }
      i += 1;
      continue;
    }

    // 4. Blockquote (> ...)
    if (trimmed.startsWith(">")) {
      flushParagraph();
      const quoteLines: string[] = [];
      while (i < lines.length) {
        const qLine = (lines[i] ?? "").trim();
        if (!qLine.startsWith(">")) break;
        quoteLines.push(qLine.replace(/^>[ \t]?/, ""));
        i += 1;
      }
      const innerBlocks =
        depth < MAX_BLOCK_DEPTH
          ? parseBlockLines(quoteLines, depth + 1)
          : quoteLines
              .filter((l) => l.trim())
              .map((l): SafeMarkdownBlock => ({
                type: "paragraph",
                tokens: parseSafeInlineTokens(l.trim()),
              }));
      if (innerBlocks.length > 0) {
        blocks.push({ type: "blockquote", blocks: innerBlocks });
      }
      continue;
    }

    // 5. Ordered or Unordered list (supports loose lists, nested lists, continuation blocks)
    const firstMarker = matchListMarker(rawLine);
    if (firstMarker && depth < MAX_BLOCK_DEPTH) {
      flushParagraph();
      const listType = firstMarker.type;
      const listDelimiter = firstMarker.delimiter;
      const baseIndent = firstMarker.indent;
      const listStart = firstMarker.number;
      const listItems: SafeMarkdownListItem[] = [];

      let currentMarker: ListMarkerMatch | null = firstMarker;
      while (currentMarker !== null) {
        const itemContentIndent = currentMarker.contentIndent;
        const childThreshold = Math.min(itemContentIndent, baseIndent + 2);
        const leadParagraphLines: string[] = [];
        if (currentMarker.content.trim()) {
          leadParagraphLines.push(currentMarker.content.trim());
        }
        const bodyLines: string[] = [];
        let collectingBody = false;
        let inBodyFence = false;
        let bodyFenceChar = "`";
        let bodyFenceLen = 3;
        i += 1;

        while (i < lines.length) {
          const line = lines[i] ?? "";
          const lineInfo = measureIndent(line);
          const lineTrimmed = lineInfo.rest.trim();

          // Keep lines inside an active nested code fence intact
          if (inBodyFence) {
            bodyLines.push(line);
            if (isClosingFence(lineTrimmed, bodyFenceChar, bodyFenceLen)) {
              inBodyFence = false;
            }
            i += 1;
            continue;
          }

          // Blank line lookahead: decides if list continues (loose list / indented child) or ends
          if (!lineTrimmed) {
            let nextIdx = i + 1;
            while (nextIdx < lines.length && !(lines[nextIdx] ?? "").trim()) {
              nextIdx += 1;
            }
            if (nextIdx >= lines.length) {
              i = nextIdx;
              break;
            }

            const nextLine = lines[nextIdx] ?? "";
            const nextInfo = measureIndent(nextLine);
            const nextTrimmed = nextInfo.rest.trim();

            // Streaming guard: incomplete trailing ordered marker like "2." at EOF
            if (
              listType === "ol" &&
              nextIdx === lines.length - 1 &&
              nextInfo.indent >= baseIndent &&
              nextInfo.indent < childThreshold
            ) {
              const partialMatch = PARTIAL_OL_EOF_RE.exec(nextTrimmed);
              if (partialMatch && partialMatch[1] === listDelimiter) {
                i = lines.length;
                break;
              }
            }

            const nextMarker = matchListMarker(nextLine);
            if (
              nextMarker &&
              isSameListSibling(nextMarker, listType, listDelimiter, baseIndent, childThreshold)
            ) {
              i = nextIdx;
              break;
            }

            if (nextInfo.indent >= childThreshold) {
              collectingBody = true;
              bodyLines.push("");
              i = nextIdx;
              continue;
            }

            // Unindented non-sibling block after blank line closes this item & list
            i = nextIdx;
            break;
          }

          // Streaming guard: incomplete trailing ordered marker directly at EOF
          if (
            listType === "ol" &&
            i === lines.length - 1 &&
            lineInfo.indent >= baseIndent &&
            lineInfo.indent < childThreshold
          ) {
            const partialMatch = PARTIAL_OL_EOF_RE.exec(lineTrimmed);
            if (partialMatch && partialMatch[1] === listDelimiter) {
              i = lines.length;
              break;
            }
          }

          const lineMarker = matchListMarker(line);

          // Sibling item of THIS list -> end current item so outer loop consumes it
          if (
            lineMarker &&
            isSameListSibling(lineMarker, listType, listDelimiter, baseIndent, childThreshold)
          ) {
            break;
          }

          // Indented content belonging to this list item
          if (lineInfo.indent >= childThreshold) {
            const innerFence = FENCE_OPEN_RE.exec(lineTrimmed);
            if (innerFence) {
              collectingBody = true;
              inBodyFence = true;
              const seq = innerFence[1] ?? "```";
              bodyFenceChar = seq[0] ?? "`";
              bodyFenceLen = seq.length;
              bodyLines.push(line);
              i += 1;
              continue;
            }

            if (
              !collectingBody &&
              !lineMarker &&
              !isBlockStarter(lineTrimmed) &&
              leadParagraphLines.length > 0
            ) {
              // Indented continuation of the item's opening paragraph (no blank line)
              leadParagraphLines.push(lineTrimmed);
              i += 1;
              continue;
            }

            collectingBody = true;
            bodyLines.push(line);
            i += 1;
            continue;
          }

          // Unindented different list or block starter ends this item and list
          if (lineMarker || isBlockStarter(lineTrimmed)) {
            break;
          }

          // Lazy continuation line (no blank line, plain text immediately following item text)
          if (!collectingBody && leadParagraphLines.length > 0) {
            leadParagraphLines.push(lineTrimmed);
            i += 1;
            continue;
          }

          // Unindented prose after a sub-block closes this list
          break;
        }

        const itemTokens =
          leadParagraphLines.length > 0
            ? parseSafeInlineTokens(leadParagraphLines.join(" "))
            : [];
        const itemChildren =
          bodyLines.length > 0
            ? parseBlockLines(dedentBodyLines(bodyLines, itemContentIndent), depth + 1)
            : [];

        if (itemTokens.length > 0 || itemChildren.length > 0) {
          listItems.push({ tokens: itemTokens, children: itemChildren });
        }

        // Check if the next line continues the SAME list
        if (i < lines.length) {
          const nextMarker = matchListMarker(lines[i] ?? "");
          if (
            nextMarker &&
            isSameListSibling(nextMarker, listType, listDelimiter, baseIndent, childThreshold)
          ) {
            currentMarker = nextMarker;
            continue;
          }
        }
        currentMarker = null;
      }

      if (listItems.length > 0) {
        if (listType === "ol") {
          blocks.push({ type: "ol", start: listStart, items: listItems });
        } else {
          blocks.push({ type: "ul", items: listItems });
        }
      }
      continue;
    }

    // 6. Regular paragraph line
    paragraphLines.push(trimmed);
    i += 1;
  }

  flushParagraph();
  return blocks;
}

export function parseSafeMarkdownBlocks(markdown: string): SafeMarkdownBlock[] {
  if (!markdown || !markdown.trim()) {
    return [];
  }
  const lines = markdown.replace(/\r\n?/g, "\n").split("\n");
  return parseBlockLines(lines, 0);
}
