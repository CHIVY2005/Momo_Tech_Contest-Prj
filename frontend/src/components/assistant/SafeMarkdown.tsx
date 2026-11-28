"use client";

import { Fragment } from "react";

import {
  parseSafeMarkdownBlocks,
  type SafeInlineToken,
  type SafeMarkdownBlock,
} from "@/lib/safeMarkdown";

interface SafeMarkdownProps {
  content: string;
  className?: string;
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
          className="rounded border border-border-subtle bg-surface-deep px-1.5 py-0.5 font-mono text-[11px] text-sky-200 break-all"
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
          className="font-medium text-sky-300 underline decoration-sky-400/60 underline-offset-2 transition-colors hover:text-sky-200 break-words"
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
          ? "mt-2.5 first:mt-0 text-xs font-bold tracking-tight text-ink"
          : "mt-2 first:mt-0 text-xs font-semibold text-ink-secondary";
      return (
        <h4 key={blockKey} className={headingClass}>
          {renderInlineTokens(block.tokens, blockKey)}
        </h4>
      );
    }

    if (block.type === "code_block") {
      return (
        <pre
          key={blockKey}
          className="overflow-x-auto rounded-lg border border-border-subtle bg-surface-deep px-3 py-2 font-mono text-[11px] leading-relaxed text-sky-200"
        >
          <code>{block.code}</code>
        </pre>
      );
    }

    if (block.type === "blockquote") {
      return (
        <blockquote
          key={blockKey}
          className="space-y-1.5 border-l-2 border-amber-400/60 pl-3 text-xs leading-relaxed text-ink-secondary"
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
          className={`${markerClass} space-y-1.5 pl-5 text-xs leading-relaxed text-ink-secondary marker:text-amber-400/80`}
        >
          {block.items.map((item, itemIdx) => {
            const itemKey = `${blockKey}-ul-${itemIdx}`;
            return (
              <li key={itemKey} className="break-words">
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
          className="list-decimal space-y-1.5 pl-5 text-xs leading-relaxed text-ink-secondary marker:font-mono marker:text-amber-300/90"
        >
          {block.items.map((item, itemIdx) => {
            const itemKey = `${blockKey}-ol-${itemIdx}`;
            return (
              <li key={itemKey} className="break-words">
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
      <p key={blockKey} className="text-xs leading-relaxed text-ink-secondary break-words">
        {renderInlineTokens(block.tokens, blockKey)}
      </p>
    );
  });
}

/**
 * Pure React Markdown renderer with zero dangerouslySetInnerHTML, zero <img> tags,
 * strict official-domain-only hyperlink allowlist, and native semantic nested lists.
 */
export function SafeMarkdown({ content, className }: SafeMarkdownProps) {
  const blocks = parseSafeMarkdownBlocks(content);
  if (blocks.length === 0) {
    return null;
  }

  return (
    <div className={className ? `space-y-2 ${className}` : "space-y-2"}>
      {renderBlocks(blocks, "root", 0)}
    </div>
  );
}
