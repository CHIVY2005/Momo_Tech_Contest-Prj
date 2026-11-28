"use client";

import { Check, Copy } from "lucide-react";
import { Fragment, memo, useEffect, useRef, useState } from "react";

import {
  parseSafeMarkdownBlocks,
  type SafeInlineToken,
  type SafeMarkdownBlock,
} from "@/lib/safeMarkdown";

interface SafeMarkdownProps {
  content: string;
  className?: string;
}

function SafeCodeBlock({ language, code }: { language: string; code: string }) {
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
      }
    };
  }, []);

  async function handleCopyCode() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
      timerRef.current = window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard API unavailable in restricted context
    }
  }

  return (
    <div className="overflow-hidden rounded-lg border border-border-subtle bg-surface-deep">
      <div className="flex items-center justify-between gap-2 border-b border-border-subtle/70 bg-surface-subtle/60 px-3 py-1 text-[10px]">
        <span className="font-mono font-medium uppercase tracking-wide text-ink-muted">
          {language || "văn bản"}
        </span>
        <button
          type="button"
          onClick={() => void handleCopyCode()}
          aria-label="Sao chép khối mã"
          className="inline-flex min-h-[24px] cursor-pointer items-center gap-1 rounded px-1.5 py-0.5 font-medium text-ink-secondary transition-colors hover:bg-surface-elevated hover:text-ink"
        >
          {copied ? (
            <>
              <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
              <span className="text-emerald-300">Đã sao chép</span>
            </>
          ) : (
            <>
              <Copy className="h-3 w-3" aria-hidden="true" />
              <span>Sao chép</span>
            </>
          )}
        </button>
      </div>
      <pre
        role="region"
        aria-label="Khối mã"
        tabIndex={0}
        className="overflow-x-auto px-3 py-2 font-mono text-[11px] leading-relaxed text-sky-200"
      >
        <code>{code}</code>
      </pre>
    </div>
  );
}

function renderInlineTokens(tokens: SafeInlineToken[], keyPrefix: string) {
  return tokens.map((token, idx) => {
    const key = `${keyPrefix}-${idx}`;
    if (token.type === "bold") {
      return (
        <strong key={key} className="font-semibold text-ink">
          {token.value}
        </strong>
      );
    }
    if (token.type === "italic") {
      return (
        <em key={key} className="italic text-ink">
          {token.value}
        </em>
      );
    }
    if (token.type === "code") {
      return (
        <code
          key={key}
          className="assistant-inline-code rounded border border-border-subtle bg-surface-deep px-1.5 font-mono text-[0.9em] text-sky-200"
        >
          {token.value}
        </code>
      );
    }
    if (token.type === "link") {
      return (
        <a
          key={key}
          href={token.href}
          target={token.external ? "_blank" : undefined}
          rel={token.external ? "noopener noreferrer" : undefined}
          className="font-medium text-sky-300 underline decoration-sky-400/60 underline-offset-2 transition-colors hover:text-sky-200"
        >
          {token.value}
        </a>
      );
    }
    return <Fragment key={key}>{token.value}</Fragment>;
  });
}

function renderBlocks(blocks: SafeMarkdownBlock[], keyPrefix: string, depth: number) {
  return blocks.map((block, blockIdx) => {
    const blockKey = `${keyPrefix}-b${blockIdx}`;

    if (block.type === "heading") {
      const headingClass =
        block.level <= 2
          ? "mt-3 first:mt-0 font-bold tracking-tight text-ink"
          : "mt-2 first:mt-0 font-semibold text-ink-secondary";
      return (
        <h4 key={blockKey} className={headingClass}>
          {renderInlineTokens(block.tokens, blockKey)}
        </h4>
      );
    }

    if (block.type === "code_block") {
      return <SafeCodeBlock key={blockKey} language={block.language} code={block.code} />;
    }

    if (block.type === "blockquote") {
      return (
        <blockquote
          key={blockKey}
          className="space-y-2 border-l-2 border-amber-400/60 pl-3 text-ink-secondary"
        >
          {renderBlocks(block.blocks, blockKey, depth + 1)}
        </blockquote>
      );
    }

    if (block.type === "ul") {
      const markerClass =
        depth === 0 ? "list-disc" : depth === 1 ? "list-[circle]" : "list-[square]";
      return (
        <ul
          key={blockKey}
          className={`${markerClass} space-y-1.5 ps-5 marker:text-amber-400/80`}
        >
          {block.items.map((item, itemIdx) => {
            const itemKey = `${blockKey}-ul-${itemIdx}`;
            return (
              <li key={itemKey}>
                {item.tokens.length > 0 && (
                  <span>{renderInlineTokens(item.tokens, itemKey)}</span>
                )}
                {item.children.length > 0 && (
                  <div className="mt-1.5 space-y-1.5">
                    {renderBlocks(item.children, `${itemKey}-c`, depth + 1)}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      );
    }

    if (block.type === "ol") {
      return (
        <ol
          key={blockKey}
          start={block.start !== 1 ? block.start : undefined}
          className="list-decimal space-y-1.5 ps-6 marker:font-mono marker:text-amber-300/90"
        >
          {block.items.map((item, itemIdx) => {
            const itemKey = `${blockKey}-ol-${itemIdx}`;
            return (
              <li key={itemKey}>
                {item.tokens.length > 0 && (
                  <span>{renderInlineTokens(item.tokens, itemKey)}</span>
                )}
                {item.children.length > 0 && (
                  <div className="mt-1.5 space-y-1.5">
                    {renderBlocks(item.children, `${itemKey}-c`, depth + 1)}
                  </div>
                )}
              </li>
            );
          })}
        </ol>
      );
    }

    return (
      <p key={blockKey}>
        {renderInlineTokens(block.tokens, blockKey)}
      </p>
    );
  });
}

/**
 * Pure React Markdown renderer with zero dangerouslySetInnerHTML, zero <img> tags,
 * strict official-domain-only hyperlink allowlist, and native semantic nested lists.
 */
export const SafeMarkdown = memo(function SafeMarkdown({ content, className }: SafeMarkdownProps) {
  const blocks = parseSafeMarkdownBlocks(content);
  if (blocks.length === 0) {
    return null;
  }

  return (
    <div className={`assistant-markdown min-w-0 space-y-3 text-[13px] leading-[1.7] text-ink-secondary ${className ?? ""}`}>
      {renderBlocks(blocks, "root", 0)}
    </div>
  );
});
