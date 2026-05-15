"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type {
  ScanFinding,
  ScanResult,
  Verdict,
  DetectionConfidence,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Skull,
} from "lucide-react";

const CONFIDENCE_LABEL: Record<DetectionConfidence, string> = {
  low: "Low",
  medium: "Moderate",
  high: "High",
  very_high: "Very high",
};

/** 100 = best (cleaner), 0 = worst (more flags). */
function safetyScoreTier(score: number): {
  label: string;
  hint: string;
  badgeClassName: string;
} {
  if (score >= 85) {
    return {
      label: "Excellent",
      hint: "No or minimal concern under these rules.",
      badgeClassName: "border-verdict-clean/50 bg-verdict-clean/15 text-verdict-clean",
    };
  }
  if (score >= 65) {
    return {
      label: "Good",
      hint: "Mostly fine — still skim the findings.",
      badgeClassName: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
    };
  }
  if (score >= 40) {
    return {
      label: "Fair",
      hint: "Notable issues — investigate.",
      badgeClassName:
        "border-verdict-warning/45 bg-verdict-warning/15 text-verdict-warning",
    };
  }
  return {
    label: "Poor",
    hint: "Many signals — assume risk until ruled out.",
    badgeClassName:
      "border-verdict-infected/45 bg-verdict-infected/15 text-verdict-infected",
  };
}

const HISTORY_KEY = "cloakbuster-scan-history";
const LEGACY_HISTORY_KEY = "parasite-unmasker-history";

const verdictCopy: Record<
  Verdict,
  { label: string; Icon: typeof ShieldCheck; className: string }
> = {
  clean: {
    label: "Clean",
    Icon: ShieldCheck,
    className: "bg-verdict-clean/15 text-verdict-clean border-verdict-clean/30",
  },
  warning: {
    label: "Suspicious",
    Icon: AlertTriangle,
    className:
      "bg-verdict-warning/15 text-verdict-warning border-verdict-warning/30",
  },
  infected: {
    label: "Infected",
    Icon: Skull,
    className:
      "bg-verdict-infected/15 text-verdict-infected border-verdict-infected/30",
  },
};

function groupByCategory(findings: ScanFinding[]) {
  const map = new Map<string, ScanFinding[]>();
  for (const f of findings) {
    const arr = map.get(f.category) || [];
    arr.push(f);
    map.set(f.category, arr);
  }
  return map;
}

const categoryLabels: Record<string, string> = {
  hidden_links: "Hidden links",
  cloaked_links: "Cloaked / vague links",
  iframes: "Iframes",
  redirects: "Redirects",
  scripts: "Scripts & obfuscation",
  malware_patterns: "Spam / malware patterns",
  resources: "External resources",
};

function severityBadge(sev: ScanFinding["severity"]) {
  if (sev === "medium") {
    return (
      <Badge className="border border-verdict-warning/50 bg-verdict-warning/15 text-verdict-warning">
        Medium
      </Badge>
    );
  }
  return (
    <Badge variant="secondary" className="text-muted-foreground">
      Low
    </Badge>
  );
}

export function ScannerApp() {
  const [url, setUrl] = useState("");
  const [renderJs, setRenderJs] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [rawOpen, setRawOpen] = useState(false);
  const [history, setHistory] = useState<string[]>([]);

  const grouped = useMemo(
    () => (result ? groupByCategory(result.findings) : null),
    [result],
  );

  useEffect(() => {
    try {
      let raw = localStorage.getItem(HISTORY_KEY);
      if (!raw) {
        raw = localStorage.getItem(LEGACY_HISTORY_KEY);
        if (raw) {
          localStorage.setItem(HISTORY_KEY, raw);
          localStorage.removeItem(LEGACY_HISTORY_KEY);
        }
      }
      if (raw) setHistory(JSON.parse(raw) as string[]);
    } catch {
      /* ignore */
    }
    const sp = new URLSearchParams(window.location.search);
    const q = sp.get("url");
    if (q) {
      try {
        setUrl(decodeURIComponent(q));
      } catch {
        setUrl(q);
      }
    }
  }, []);

  const runScan = useCallback(async () => {
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, renderJs }),
      });
      const data = (await res.json()) as { error?: string } & Partial<ScanResult>;
      if (!res.ok) {
        setError(data.error || `Scan failed (${res.status})`);
        return;
      }
      const scan = data as ScanResult;
      setResult(scan);
      setHistory((prev) => {
        const next = [scan.url, ...prev.filter((x) => x !== scan.url)];
        try {
          localStorage.setItem(
            HISTORY_KEY,
            JSON.stringify(next.slice(0, 8)),
          );
        } catch {
          /* ignore */
        }
        return next.slice(0, 8);
      });
    } catch {
      setError("Network error — try again in a moment.");
    } finally {
      setLoading(false);
    }
  }, [url, renderJs]);

  const verdict = result ? verdictCopy[result.verdict] : null;
  const VerdictIcon = verdict?.Icon;
  const safetyTier = result !== null ? safetyScoreTier(result.score) : null;

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-10 px-4 py-12 sm:px-6 lg:px-8">
      <header className="space-y-4 text-center sm:text-left">
        <div className="inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 text-xs text-muted-foreground">
          <ShieldAlert className="h-3.5 w-3.5 text-accent" aria-hidden />
          Cloaked links, hidden injections, sketchy scripts
        </div>
        <h1 className="text-balance font-semibold tracking-tight text-4xl sm:text-5xl">
          <span className="bg-gradient-to-r from-accent to-teal-300 bg-clip-text text-transparent">
            Cloak
          </span>
          buster
        </h1>
        <p className="max-w-2xl text-pretty text-base text-muted-foreground sm:text-lg">
          Free scanner at{" "}
          <a
            href="https://cloakbuster.com/"
            className="text-accent underline-offset-2 hover:underline"
          >
            cloakbuster.com
          </a>
          — paste a URL, we fetch it safely on the server (optionally with headless
          Chromium), parse the DOM, and flag cloaked links, parasite-style injections,
          and other red flags. No installs, no account.
        </p>
      </header>

      <Card className="border-border/80 bg-card/60 shadow-xl shadow-black/30 backdrop-blur">
        <CardHeader>
          <CardTitle className="text-lg">Scan a page</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <form
            className="flex flex-col gap-3 sm:flex-row"
            onSubmit={(e) => {
              e.preventDefault();
              void runScan();
            }}
          >
            <label className="sr-only" htmlFor="url-input">
              Page URL
            </label>
            <Input
              id="url-input"
              name="url"
              type="text"
              inputMode="url"
              autoComplete="url"
              placeholder="example.com or https://example.com/page"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="h-12 flex-1 border-border bg-background/80 text-base"
            />
            <Button
              type="submit"
              size="lg"
              className="h-12 shrink-0 bg-accent text-accent-foreground hover:bg-accent/90"
              disabled={loading || url.trim().length < 4}
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
                  Scanning…
                </>
              ) : (
                "Scan"
              )}
            </Button>
          </form>
          <div className="flex items-start gap-2 rounded-md border border-border/60 bg-muted/20 px-3 py-2">
            <input
              id="render-js"
              type="checkbox"
              className="mt-1 h-4 w-4 rounded border-border accent-accent"
              checked={renderJs}
              onChange={(e) => setRenderJs(e.target.checked)}
            />
            <label htmlFor="render-js" className="text-sm leading-snug text-muted-foreground">
              <span className="font-medium text-foreground">Render JavaScript</span>{" "}
              (headless Chromium via Playwright). Turn off for a faster static-only pull — same
              SSRF checks apply either way.
            </label>
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            Rate limit: 5 scans / minute / IP. We do not persist full page HTML —
            only a short excerpt for your report.
          </p>
        </CardContent>
      </Card>

      {history.length > 0 && (
        <section aria-labelledby="recent-heading" className="space-y-2">
          <h2
            id="recent-heading"
            className="text-sm font-medium text-muted-foreground"
          >
            Recent scans (this browser)
          </h2>
          <ul className="flex flex-wrap gap-2">
            {history.map((h) => (
              <li key={h}>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="border-border text-xs"
                  onClick={() => setUrl(h)}
                >
                  {h.replace(/^https?:\/\//, "")}
                </Button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {result && verdict && VerdictIcon && safetyTier && (
        <div className="space-y-8">
          <section className="grid gap-4 md:grid-cols-[1.2fr_minmax(0,1fr)]">
            <Card className="border-border/80">
              <CardContent className="flex flex-col gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
                <div className="space-y-1">
                  <p className="text-xs uppercase tracking-wider text-muted-foreground">
                    Verdict
                  </p>
                  <div className="flex flex-wrap items-center gap-3">
                    <VerdictIcon className="h-8 w-8" aria-hidden />
                    <span className="text-2xl font-semibold">{verdict.label}</span>
                    <span
                      className={`inline-flex items-center rounded-full border px-3 py-1 text-sm font-semibold tabular-nums ${safetyTier.badgeClassName}`}
                      title={`Safety score: ${result.score}/100 (${safetyTier.label}). 100 = best, 0 = worst.`}
                    >
                      {result.score}/100 · {safetyTier.label}
                    </span>
                  </div>
                  <p className="text-xs font-medium text-foreground">
                    <span className="text-verdict-clean">100</span>
                    <span className="text-muted-foreground font-normal">
                      {" "}
                      = best (cleaner page) ·{" "}
                    </span>
                    <span className="text-verdict-infected">0</span>
                    <span className="text-muted-foreground font-normal">
                      {" "}
                      = worst (more red flags)
                    </span>
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {safetyTier.hint}{" "}
                    <span className="text-foreground font-medium">Heuristic signal strength:</span>{" "}
                    {CONFIDENCE_LABEL[result.detectionConfidence]}
                    {" — "}
                    higher means the match is stronger, not “more malware.”
                  </p>
                  <p className="break-all text-sm text-muted-foreground">
                    <span className="font-medium text-foreground">Requested:</span>{" "}
                    {result.url}
                  </p>
                  {result.finalUrl !== result.url && (
                    <p className="break-all text-sm text-muted-foreground">
                      <span className="font-medium text-foreground">Final URL:</span>{" "}
                      {result.finalUrl}
                    </p>
                  )}
                </div>
                <dl className="grid grid-cols-2 gap-3 text-sm sm:text-right">
                  <div>
                    <dt className="text-muted-foreground">HTTP status</dt>
                    <dd className="font-mono">{result.response.status}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Fetch time</dt>
                    <dd className="font-mono">{result.fetchMs} ms</dd>
                  </div>
                  <div className="col-span-2">
                    <dt className="text-muted-foreground">Scanned at</dt>
                    <dd className="font-mono text-xs sm:text-sm">
                      {new Date(result.scannedAt).toLocaleString()}
                    </dd>
                  </div>
                  {(result.renderEngine || result.renderNote) && (
                    <div className="col-span-2 space-y-1 text-left text-xs text-muted-foreground sm:text-right">
                      {result.renderEngine && (
                        <p>
                          <span className="text-foreground">Render engine:</span>{" "}
                          {result.renderEngine === "playwright"
                            ? "Playwright (JS on)"
                            : "HTTP fetch (JS off or fallback)"}
                        </p>
                      )}
                      {result.renderNote && (
                        <p className="text-verdict-warning">{result.renderNote}</p>
                      )}
                    </div>
                  )}
                </dl>
              </CardContent>
            </Card>

            <Card className="border-border/80">
              <CardHeader>
                <CardTitle className="text-base">Summary</CardTitle>
              </CardHeader>
              <CardContent className="grid grid-cols-2 gap-3 text-sm">
                <SummaryCell label="Hidden links" value={result.summary.hiddenLinks} />
                <SummaryCell label="Cloaked links" value={result.summary.cloakedLinks} />
                <SummaryCell label="Iframes" value={result.summary.suspiciousIframes} />
                <SummaryCell label="Redirects" value={result.summary.redirects} />
                <SummaryCell label="Scripts" value={result.summary.suspiciousScripts} />
                <SummaryCell
                  label="Spam patterns"
                  value={result.summary.malwarePatterns}
                />
                <SummaryCell
                  label="External resources"
                  value={result.summary.unusualResources}
                />
              </CardContent>
            </Card>
          </section>

          <section className="space-y-4">
            <h2 className="text-lg font-semibold">Findings</h2>
            {result.findings.length === 0 ? (
              <Card className="border-dashed border-verdict-clean/40 bg-verdict-clean/5">
                <CardContent className="flex items-center gap-3 p-6 text-verdict-clean">
                  <CheckCircle2 className="h-6 w-6 shrink-0" aria-hidden />
                  <p className="text-sm sm:text-base">
                    No obvious compromise patterns in the HTML we analyzed
                    {result.renderEngine === "playwright"
                      ? " (including post-JS DOM from Playwright)"
                      : ""}
                    . That still is not a guarantee — attackers can hide in WebSockets,
                    service workers, or payloads only reachable behind auth.
                  </p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-8">
                {grouped &&
                  Array.from(grouped.entries()).map(([cat, items]) => (
                    <div key={cat} className="space-y-3">
                      <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                        {categoryLabels[cat] || cat}
                      </h3>
                      <ul className="space-y-3">
                        {items.map((f) => (
                          <li key={f.id}>
                            <Card className="border-border/80">
                              <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0 pb-2">
                                <CardTitle className="text-base font-medium">
                                  {f.title}
                                </CardTitle>
                                {severityBadge(f.severity)}
                              </CardHeader>
                              <CardContent className="space-y-3 text-sm">
                                <p className="text-muted-foreground">{f.description}</p>
                                <p>
                                  <span className="font-medium text-foreground">
                                    Fix:
                                  </span>{" "}
                                  {f.remediation}
                                </p>
                                <pre className="max-h-48 overflow-auto rounded-md border border-border bg-muted/40 p-3 text-xs leading-relaxed text-foreground">
                                  {f.evidence}
                                </pre>
                              </CardContent>
                            </Card>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
              </div>
            )}
          </section>

          <section className="space-y-2">
            <button
              type="button"
              className="flex items-center gap-2 text-sm font-medium text-accent hover:underline"
              onClick={() => setRawOpen((o) => !o)}
              aria-expanded={rawOpen}
            >
              <ChevronDown
                className={`h-4 w-4 transition-transform ${rawOpen ? "rotate-180" : ""}`}
                aria-hidden
              />
              Raw HTML excerpt (truncated)
            </button>
            {rawOpen && (
              <pre className="max-h-96 overflow-auto rounded-lg border border-border bg-black/40 p-4 text-xs text-muted-foreground">
                {result.htmlSnippet}
              </pre>
            )}
          </section>

          <section className="rounded-xl border border-border bg-muted/20 p-6">
            <h2 className="mb-2 text-base font-semibold">Recommendations</h2>
            <ul className="list-disc space-y-2 pl-5 text-sm text-muted-foreground">
              <li>Compare flagged snippets with known-good backups or version control.</li>
              <li>Rotate admin passwords, review plugins/themes, and check file integrity.</li>
              <li>Add a strict Content-Security-Policy and Subresource Integrity on scripts.</li>
              <li>Use JS rendering (Playwright) when auditing SPAs or late-injected DOM.</li>
            </ul>
          </section>
        </div>
      )}

      <section className="rounded-xl border border-dashed border-border bg-card/40 p-6">
        <h2 className="mb-2 text-base font-semibold">Bookmarklet</h2>
        <p className="mb-3 text-sm text-muted-foreground">
          Drag this link to your bookmarks bar, then click it on any page to open
          Cloakbuster with that URL filled in.
        </p>
        <BookmarkletLink />
      </section>

      <footer className="border-t border-border pt-8 text-center text-xs text-muted-foreground sm:text-left">
        <p>
          Open source under the MIT License — heuristic scanner, not a warranty.{" "}
          <a
            className="text-accent underline-offset-4 hover:underline"
            href="https://github.com/marckranat/cloakbuster"
          >
            Source on GitHub
          </a>
          {" · "}
          <a
            className="text-accent underline-offset-4 hover:underline"
            href="/api/scan?url=https://example.com"
          >
            JSON API example
          </a>
        </p>
      </footer>
    </div>
  );
}

function SummaryCell({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-border/60 bg-background/40 px-3 py-2">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function BookmarkletLink() {
  const [href, setHref] = useState("#");

  useEffect(() => {
    const origin =
      typeof window !== "undefined" ? window.location.origin : "";
    const code = `javascript:(function(){var u=encodeURIComponent(location.href);window.open('${origin}/?url='+u,'_blank');})();`;
    setHref(code);
  }, []);

  return (
    <a
      href={href}
      className="inline-flex rounded-md border border-accent/50 bg-accent/10 px-4 py-2 text-sm font-medium text-accent hover:bg-accent/20"
    >
      Scan with Cloakbuster
    </a>
  );
}
