"use client";

import { Fragment } from "react";

import { parseSafeMarkdownBlocks, type SafeInlineToken } from "@/lib/safeMarkdown";

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
    return <Fragment key={key}>{token.value}</Fragment>;
  });
}

/**
 * Pure React Markdown renderer with zero dangerouslySetInnerHTML, zero <a> links, and zero <img> tags.
 */
export function SafeMarkdown({ content, className }: SafeMarkdownProps) {
  const blocks = parseSafeMarkdownBlocks(content);
  if (blocks.length === 0) {
    return null;
  }

  return (
    <div className={className ? `space-y-2 ${className}` : "space-y-2"}>
      {blocks.map((block, blockIdx) => {
        const blockKey = `b-${blockIdx}`;
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

        if (block.type === "ul") {
          return (
            <ul
              key={blockKey}
              className="list-disc space-y-1.5 pl-4 text-xs leading-relaxed text-ink-secondary marker:text-amber-400/80"
            >
              {block.items.map((itemTokens, itemIdx) => (
                <li key={`${blockKey}-ul-${itemIdx}`} className="break-words">
                  {renderInlineTokens(itemTokens, `${blockKey}-ul-${itemIdx}`)}
                </li>
              ))}
            </ul>
          );
        }

        if (block.type === "ol") {
          return (
            <ol
              key={blockKey}
              className="list-decimal space-y-1.5 pl-4 text-xs leading-relaxed text-ink-secondary marker:font-mono marker:text-amber-300/90"
            >
              {block.items.map((itemTokens, itemIdx) => (
                <li key={`${blockKey}-ol-${itemIdx}`} className="break-words">
                  {renderInlineTokens(itemTokens, `${blockKey}-ol-${itemIdx}`)}
                </li>
              ))}
            </ol>
          );
        }

        return (
          <p key={blockKey} className="text-xs leading-relaxed text-ink-secondary break-words">
            {renderInlineTokens(block.tokens, blockKey)}
          </p>
        );
      })}
    </div>
  );
}
