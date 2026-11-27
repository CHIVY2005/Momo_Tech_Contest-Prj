"use client";

import { ArrowUpRight, Send } from "lucide-react";
import { useEffect, useState } from "react";

import { fetchHealth } from "@/lib/api";

const ENV_TELEGRAM_URL = (process.env.NEXT_PUBLIC_TELEGRAM_BOT_URL ?? "").trim();

function isSafeTelegramUrl(raw: string | null | undefined): raw is string {
  return Boolean(raw && raw.startsWith("https://t.me/"));
}

let cachedTelegramUrl: string | null | undefined;
let inflightRequest: Promise<string | null> | null = null;

async function resolveTelegramUrl(): Promise<string | null> {
  if (isSafeTelegramUrl(ENV_TELEGRAM_URL)) {
    return ENV_TELEGRAM_URL;
  }
  if (cachedTelegramUrl !== undefined) {
    return cachedTelegramUrl;
  }
  if (!inflightRequest) {
    inflightRequest = fetchHealth()
      .then((health) => {
        const resolved = isSafeTelegramUrl(health.telegram_bot_url) ? health.telegram_bot_url : null;
        cachedTelegramUrl = resolved;
        return resolved;
      })
      .catch(() => {
        cachedTelegramUrl = null;
        return null;
      })
      .finally(() => {
        inflightRequest = null;
      });
  }
  return inflightRequest;
}

export function FooterTelegramLink() {
  const [url, setUrl] = useState<string | null>(() =>
    isSafeTelegramUrl(ENV_TELEGRAM_URL) ? ENV_TELEGRAM_URL : cachedTelegramUrl ?? null,
  );

  useEffect(() => {
    let active = true;
    void resolveTelegramUrl().then((resolved) => {
      if (active) setUrl(resolved);
    });
    return () => {
      active = false;
    };
  }, []);

  if (!url) {
    return null;
  }

  return (
    <li>
      <a
        href={url}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1.5 text-ink-secondary transition-colors hover:text-ink"
      >
        <Send className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
        <span>Telegram Bot</span>
        <ArrowUpRight className="h-3 w-3 text-ink-muted" aria-hidden="true" />
      </a>
    </li>
  );
}
