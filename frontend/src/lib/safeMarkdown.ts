/**
 * Pure-TS Safe Markdown parser for "Trợ lý VeriShield" responses.
 * Zero React/JSX imports, zero HTML execution, and zero clickable link/image AST nodes.
 * Every raw HTML tag or markdown link is emitted strictly as inert text tokens in O(N) time.
 */

export type SafeInlineToken =
  | { type: "text"; value: string }
  | { type: "bold"; value: string }
  | { type: "code"; value: string };

export type SafeMarkdownBlock =
  | { type: "heading"; level: 1 | 2 | 3; tokens: SafeInlineToken[] }
  | { type: "paragraph"; tokens: SafeInlineToken[] }
  | { type: "ul"; items: SafeInlineToken[][] }
  | { type: "ol"; items: SafeInlineToken[][] };

const DANGEROUS_SCHEME_RE = /^(?:javascript|vbscript|data|file|blob):/i;
const INLINE_DANGEROUS_SCHEME_RE =
  /(?:javascript|vbscript|data|file|blob)\s*:[^\s)\]>'"]*/gi;
const TRAILING_LINK_TITLE_RE = /\s+(?:"[^"\n]*"|'[^'\n]*')\s*$/;
const HEADING_RE = /^(#{1,6})\s+(.+)$/;
const UNORDERED_ITEM_RE = /^\s*[-*•]\s+(.+)$/;
const ORDERED_ITEM_RE = /^\s*\d+[.)]\s+(.+)$/;
const HORIZONTAL_RULE_RE = /^\s*(?:[-*_]\s*){3,}$/;
const FENCE_RE = /^\s*```/;

const MAX_LINK_LABEL_CHARS = 256;
const MAX_LINK_TARGET_CHARS = 1024;
const MAX_NESTED_BRACKETS = 8;
const MAX_NESTED_PARENS = 8;
const MAX_NEUTRALIZE_DEPTH = 4;

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

interface ParsedLinkSpan {
  endIndex: number;
  inertText: string;
}

/**
 * Match a markdown link `[label](url)` or image `![alt](url)` starting at `startIndex`
 * with bounded lookahead & nesting limits (guaranteeing linear-time scanning) and
 * returning strictly safe inert text (never an href).
 */
function tryConsumeMarkdownLinkOrImage(
  text: string,
  startIndex: number,
  lastCloseBracket: number,
  lastCloseParen: number,
  depth: number,
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
  if (!token.value) return;
  const prev = tokens[tokens.length - 1];
  if (token.type === "text" && prev?.type === "text") {
    prev.value += token.value;
    return;
  }
  tokens.push(token);
}

export function parseSafeInlineTokens(input: string): SafeInlineToken[] {
  const tokens: SafeInlineToken[] = [];
  const lastBacktick = input.lastIndexOf("`");
  const lastDoubleStar = input.lastIndexOf("**");
  const lastCloseBracket = input.lastIndexOf("]");
  const lastCloseParen = input.lastIndexOf(")");
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

    // 2. Bold span: **...**
    if (ch === "*" && input[i + 1] === "*" && i + 1 < lastDoubleStar) {
      const closeBold = input.indexOf("**", i + 2);
      if (closeBold > i + 2) {
        const rawInner = input.slice(i + 2, closeBold);
        const safeInner = neutralizeLinksInPlainString(rawInner, 0);
        pushToken(tokens, { type: "bold", value: safeInner });
        i = closeBold + 2;
        continue;
      }
    }

    // 3. Markdown link [label](url) or image ![alt](url) -> strictly inert text
    if (ch === "[" || (ch === "!" && input[i + 1] === "[")) {
      const consumed = tryConsumeMarkdownLinkOrImage(
        input,
        i,
        lastCloseBracket,
        lastCloseParen,
        0,
      );
      if (consumed) {
        pushToken(tokens, { type: "text", value: consumed.inertText });
        i = consumed.endIndex;
        continue;
      }
    }

    pushToken(tokens, { type: "text", value: ch ?? "" });
    i += 1;
  }

  return tokens;
}

export function parseSafeMarkdownBlocks(markdown: string): SafeMarkdownBlock[] {
  if (!markdown || !markdown.trim()) {
    return [];
  }

  const lines = markdown.replace(/\r\n?/g, "\n").split("\n");
  const blocks: SafeMarkdownBlock[] = [];

  let paragraphLines: string[] = [];
  let ulItems: SafeInlineToken[][] = [];
  let olItems: SafeInlineToken[][] = [];
  let inCodeFence = false;

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

  function flushLists(): void {
    if (ulItems.length > 0) {
      blocks.push({ type: "ul", items: ulItems });
      ulItems = [];
    }
    if (olItems.length > 0) {
      blocks.push({ type: "ol", items: olItems });
      olItems = [];
    }
  }

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();

    if (FENCE_RE.test(trimmed)) {
      flushParagraph();
      flushLists();
      inCodeFence = !inCodeFence;
      continue;
    }

    if (inCodeFence) {
      if (trimmed) {
        blocks.push({ type: "paragraph", tokens: [{ type: "code", value: trimmed }] });
      }
      continue;
    }

    if (!trimmed) {
      flushParagraph();
      flushLists();
      continue;
    }

    if (HORIZONTAL_RULE_RE.test(trimmed)) {
      flushParagraph();
      flushLists();
      continue;
    }

    const headingMatch = HEADING_RE.exec(trimmed);
    if (headingMatch) {
      flushParagraph();
      flushLists();
      const hashCount = headingMatch[1]?.length ?? 1;
      const level = Math.min(3, Math.max(1, hashCount)) as 1 | 2 | 3;
      const headingText = headingMatch[2]?.trim() ?? "";
      const tokens = parseSafeInlineTokens(headingText);
      if (tokens.length > 0) {
        blocks.push({ type: "heading", level, tokens });
      }
      continue;
    }

    const ulMatch = UNORDERED_ITEM_RE.exec(rawLine);
    if (ulMatch) {
      flushParagraph();
      if (olItems.length > 0) {
        blocks.push({ type: "ol", items: olItems });
        olItems = [];
      }
      const itemTokens = parseSafeInlineTokens(ulMatch[1]?.trim() ?? "");
      if (itemTokens.length > 0) {
        ulItems.push(itemTokens);
      }
      continue;
    }

    const olMatch = ORDERED_ITEM_RE.exec(rawLine);
    if (olMatch) {
      flushParagraph();
      if (ulItems.length > 0) {
        blocks.push({ type: "ul", items: ulItems });
        ulItems = [];
      }
      const itemTokens = parseSafeInlineTokens(olMatch[1]?.trim() ?? "");
      if (itemTokens.length > 0) {
        olItems.push(itemTokens);
      }
      continue;
    }

    flushLists();
    // Strip leading markdown blockquote marker gracefully
    const cleanedLine = trimmed.replace(/^>\s?/, "");
    if (cleanedLine) {
      paragraphLines.push(cleanedLine);
    }
  }

  flushParagraph();
  flushLists();

  return blocks;
}
