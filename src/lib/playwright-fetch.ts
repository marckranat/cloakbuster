import type { FetchedPage } from "./fetch-page";
import { assertUrlSafeForFetch } from "./url-security";

const TIMEOUT_MS = 22_000;
const POST_NAV_WAIT_MS = 1_500;

function pickUserAgent(): string {
  const agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
  ];
  return agents[Math.floor(Math.random() * agents.length)]!;
}

/**
 * Renders the page in headless Chromium so dynamically injected DOM/JS is visible.
 * All navigations & subresources are filtered through {@link assertUrlSafeForFetch} to reduce SSRF/fan-out risk.
 */
export async function fetchPageWithPlaywright(
  input: string,
): Promise<FetchedPage> {
  if (process.env.PLAYWRIGHT_DISABLE === "1") {
    throw new Error("Playwright disabled via PLAYWRIGHT_DISABLE=1");
  }

  let trimmed = input.trim();
  if (!/^https?:\/\//i.test(trimmed)) trimmed = `https://${trimmed}`;
  const startUrl = await assertUrlSafeForFetch(trimmed);

  const { chromium } = await import("playwright");
  const started = Date.now();

  const browser = await chromium.launch({
    headless: true,
    args: [
      "--disable-dev-shm-usage",
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-background-networking",
      "--disable-breakpad",
      "--disable-component-extensions-with-background-pages",
      "--disable-extensions",
      "--disable-features=TranslateUI",
      "--disable-sync",
      "--metrics-recording-only",
      "--mute-audio",
    ],
  });

  try {
    const context = await browser.newContext({
      userAgent: pickUserAgent(),
      javaScriptEnabled: true,
      ignoreHTTPSErrors: false,
      bypassCSP: false,
      reducedMotion: "reduce",
    });

    try {
      await context.route("**/*", async (route) => {
        try {
          await assertUrlSafeForFetch(route.request().url());
          await route.continue();
        } catch {
          await route.abort();
        }
      });

      const page = await context.newPage();
      await page.goto(startUrl.toString(), {
        waitUntil: "domcontentloaded",
        timeout: TIMEOUT_MS,
      });

      await new Promise((r) => setTimeout(r, POST_NAV_WAIT_MS));

      const finalUrl = page.url();
      await assertUrlSafeForFetch(finalUrl);

      const html = await page.content();
      const fetchMs = Date.now() - started;

      return {
        html,
        finalUrl,
        status: 200,
        contentType: "text/html; charset=utf-8",
        server: null,
        wasRedirected:
          finalUrl.replace(/\/$/, "") !== startUrl.toString().replace(/\/$/, ""),
        fetchMs,
      };
    } finally {
      await context.close().catch(() => {});
    }
  } finally {
    await browser.close().catch(() => {});
  }
}
