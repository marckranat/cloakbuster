import { NextResponse } from "next/server";
import { z } from "zod";
import { analyzeHtml } from "@/lib/scanner";
import { fetchPage } from "@/lib/fetch-page";
import { fetchPageWithPlaywright } from "@/lib/playwright-fetch";
import { checkRateLimit } from "@/lib/rate-limit";
import { assertUrlSafeForFetch } from "@/lib/url-security";
import type { ScanResult } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 60;

const bodySchema = z.object({
  url: z.string().min(4).max(2048),
  renderJs: z.boolean().optional().default(true),
});

function normalizeUrlParam(raw: string | null): string | null {
  if (!raw || typeof raw !== "string") return null;
  const t = raw.trim();
  return t.length >= 4 ? t : null;
}

function parseRenderJsParam(v: string | null): boolean {
  if (v === null) return true;
  const t = v.trim().toLowerCase();
  if (t === "false" || t === "0" || t === "no") return false;
  return true;
}

async function runScan(
  urlInput: string,
  headers: Headers,
  renderJs: boolean,
): Promise<NextResponse> {
  const rl = checkRateLimit(headers);
  if (!rl.ok) {
    return NextResponse.json(
      { error: "Rate limit exceeded", resetInMs: rl.resetInMs },
      {
        status: 429,
        headers: {
          "Retry-After": String(Math.ceil(rl.resetInMs / 1000)),
          "X-RateLimit-Remaining": "0",
        },
      },
    );
  }

  let requestedDisplay = urlInput.trim();
  if (!/^https?:\/\//i.test(requestedDisplay)) {
    requestedDisplay = `https://${requestedDisplay}`;
  }

  try {
    await assertUrlSafeForFetch(requestedDisplay);
  } catch (e) {
    const message = e instanceof Error ? e.message : "Blocked URL";
    return NextResponse.json({ error: message }, { status: 400 });
  }

  let page;
  let renderEngine: ScanResult["renderEngine"] = "fetch";
  let renderNote: string | null = null;

  try {
    if (renderJs) {
      try {
        page = await fetchPageWithPlaywright(urlInput);
        renderEngine = "playwright";
      } catch (e) {
        renderNote =
          e instanceof Error ? e.message : "Playwright render failed";
        page = await fetchPage(urlInput);
        renderEngine = "fetch";
      }
    } else {
      page = await fetchPage(urlInput);
      renderEngine = "fetch";
      renderNote = "JS rendering disabled for this scan";
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : "Could not fetch URL";
    return NextResponse.json({ error: message }, { status: 502 });
  }

  if (!page.contentType?.toLowerCase().includes("text/html")) {
    return NextResponse.json(
      {
        error: "URL did not return HTML",
        contentType: page.contentType,
        status: page.status,
      },
      { status: 415 },
    );
  }

  const result: ScanResult = {
    ...analyzeHtml(page.html, requestedDisplay, page.finalUrl, {
      status: page.status,
      contentType: page.contentType,
      server: page.server,
      wasRedirected: page.wasRedirected,
      fetchMs: page.fetchMs,
    }),
    renderEngine,
    renderNote: renderNote ?? undefined,
  };

  return NextResponse.json(result, {
    headers: {
      "X-RateLimit-Remaining": String(rl.remaining),
    },
  });
}

export async function POST(req: Request) {
  try {
    const json = await req.json();
    const parsed = bodySchema.safeParse(json);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid body", details: parsed.error.flatten() },
        { status: 400 },
      );
    }
    return runScan(parsed.data.url, req.headers, parsed.data.renderJs);
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
}

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const url = normalizeUrlParam(searchParams.get("url"));
  if (!url) {
    return NextResponse.json(
      { error: "Missing or invalid `url` query parameter" },
      { status: 400 },
    );
  }
  const renderJs = parseRenderJsParam(searchParams.get("renderJs"));
  return runScan(url, req.headers, renderJs);
}
