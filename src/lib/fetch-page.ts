import { assertUrlSafeForFetch } from "./url-security";

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
  "Mozilla/5.0 (compatible; Cloakbuster/1.0; +https://cloakbuster.com/)",
];

const MAX_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS = 8_000;
const MAX_REDIRECTS = 10;

export interface FetchedPage {
  html: string;
  finalUrl: string;
  status: number;
  contentType: string | null;
  server: string | null;
  wasRedirected: boolean;
  fetchMs: number;
}

function pickUserAgent(): string {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)]!;
}

function normalizeInputUrl(raw: string): URL {
  let trimmed = raw.trim();
  if (!trimmed) throw new Error("Empty URL");
  if (!/^https?:\/\//i.test(trimmed)) {
    trimmed = `https://${trimmed}`;
  }
  return new URL(trimmed);
}

/**
 * Plain HTTP fetch with manual redirect handling so every hop is SSRF-checked.
 */
export async function fetchPage(input: string): Promise<FetchedPage> {
  const started = Date.now();
  let current = normalizeInputUrl(input);

  if (!["http:", "https:"].includes(current.protocol)) {
    throw new Error("Only http(s) URLs are allowed");
  }

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);

  try {
    let wasRedirected = false;
    let res!: Response;

    for (let hop = 0; hop < MAX_REDIRECTS; hop++) {
      await assertUrlSafeForFetch(current.toString());

      res = await fetch(current.toString(), {
        method: "GET",
        redirect: "manual",
        signal: ac.signal,
        headers: {
          "User-Agent": pickUserAgent(),
          Accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9",
        },
      });

      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const loc = res.headers.get("location");
        if (!loc) throw new Error("Redirect without Location header");
        current = new URL(loc, current);
        wasRedirected = true;
        await res.arrayBuffer().catch(() => {});
        continue;
      }

      break;
    }

    if ([301, 302, 303, 307, 308].includes(res!.status)) {
      throw new Error("Too many redirects");
    }

    if (!(res!.status >= 200 && res!.status < 400)) {
      throw new Error(`HTTP ${res!.status}`);
    }

    const contentType = res!.headers.get("content-type");
    const server = res!.headers.get("server");
    const finalUrl = current.toString();

    const reader = res!.body?.getReader();
    if (!reader) {
      throw new Error("No response body");
    }

    const chunks: Uint8Array[] = [];
    let received = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        received += value.byteLength;
        if (received > MAX_BYTES) {
          reader.cancel().catch(() => {});
          throw new Error("Response too large (max 2MB)");
        }
        chunks.push(value);
      }
    }

    const buffer = Buffer.concat(chunks.map((c) => Buffer.from(c)));
    const charsetMatch = contentType?.match(/charset=([^;]+)/i);
    const charset =
      charsetMatch?.[1]?.trim().replace(/^["']|["']$/g, "") || "utf-8";
    let html: string;
    try {
      html = new TextDecoder(charset).decode(new Uint8Array(buffer));
    } catch {
      html = buffer.toString("utf8");
    }

    return {
      html,
      finalUrl,
      status: res!.status,
      contentType,
      server,
      wasRedirected,
      fetchMs: Date.now() - started,
    };
  } finally {
    clearTimeout(timer);
  }
}
