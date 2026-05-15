import * as cheerio from "cheerio";
import type {
  DetectionConfidence,
  ScanFinding,
  ScanResult,
  ScanSummary,
  Severity,
  Verdict,
} from "./types";

const SPAM_KEYWORD_RE =
  /\b(viagra|cialis|tramadol|xanax|casino|poker|porn|xxx|pharmacy|replica\s*watch|seo\s*service|backlink|click\s*here\s*to\s*win)\b/i;

/** Multi-word / brand strings common in parasite & gambling SEO injections (footer spam). Tiered to limit false positives. */
const GAMBLING_SEO_SPAM_HIGH_CONFIDENCE = [
  "slot thailand",
  "toto 4d",
  "toto 4 d",
  "toto4d",
  "pandawa4d",
  "pandawa 4d",
  "saldoku777",
  "saldoku 777",
  "deneme bonusu veren siteler",
];

/**
 * Common in Asian gambling SEO parasites; only match when the link is **off-site**
 * (injected links on unrelated victim domains).
 */
const GAMBLING_SEO_SPAM_OFFSITE_ONLY = [
  "link alternatif",
  "situs slot",
  "slot gacor",
  "rtp slot",
  "bonus new member",
  "deposit pulsa",
  "situs judi",
  "judi slot",
  "agen slot",
  "daftar slot",
  "rtp live",
  "live casino online",
  "slot maxwin",
  "maxwin slot",
  "mahjong ways",
  "mahjong way",
  "sweet bonanza",
  "starlight princess",
  "zeus slot",
  "olympus slot",
  "pragmatic play demo",
  "gates of olympus",
];

/** Pharma / pills spam often injected as parasite links — off-site only. */
const PHARMA_PARASITE_LINK_OFFSITE = [
  "cheap viagra",
  "buy viagra",
  "buy cialis",
  "cialis online",
  "viagra online",
  "xanax for sale",
  "tramadol online",
  "hydrocodone online",
  "buy ambien online",
  "generic levitra",
  "kamagra",
  "propecia online",
  "no prescription needed",
];

/** Shorter tokens: only count if link is off-site or hidden (reduces random word hits). */
const GAMBLING_SEO_SPAM_CONTEXT_ONLY = ["gamdom"];

function normalizeAnchorText(t: string): string {
  return t.replace(/\s+/g, " ").trim().toLowerCase();
}

function parasiteAnchorPhraseLevel(
  textJoined: string,
  ctx: { offSite: boolean; visuallyHidden: boolean },
): "high" | "context" | null {
  const n = normalizeAnchorText(textJoined);
  if (!n) return null;

  for (const p of GAMBLING_SEO_SPAM_HIGH_CONFIDENCE) {
    if (n.includes(p)) return "high";
  }

  if (ctx.offSite) {
    for (const p of PHARMA_PARASITE_LINK_OFFSITE) {
      if (n.includes(p)) return "high";
    }
    for (const p of GAMBLING_SEO_SPAM_OFFSITE_ONLY) {
      if (n.includes(p)) return "high";
    }
  }

  if (ctx.offSite || ctx.visuallyHidden) {
    for (const p of GAMBLING_SEO_SPAM_CONTEXT_ONLY) {
      if (n.includes(p)) return "context";
    }
  }
  return null;
}

const SUSPICIOUS_HOST_SUBSTR = [
  ".tk",
  ".ml",
  ".ga",
  ".gq",
  ".cf",
  "bit.ly",
  "tinyurl",
  "goo.gl",
  "t.co/",
  "redirect",
  "affiliate",
];

type Internal = "high" | "medium" | "low";

type InternalRow = Omit<ScanFinding, "id" | "severity"> & { internal: Internal };

function truncate(s: string, max = 400): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

function parseStyle(style: string | undefined): Record<string, string> {
  if (!style) return {};
  const out: Record<string, string> = {};
  for (const part of style.split(";")) {
    const [k, ...rest] = part.split(":");
    if (!k?.trim()) continue;
    out[k.trim().toLowerCase()] = rest.join(":").trim().toLowerCase();
  }
  return out;
}

function isHiddenByStyles(styles: Record<string, string>): boolean {
  if (styles.display === "none") return true;
  if (styles.visibility === "hidden" || styles.visibility === "collapse")
    return true;
  if (styles.opacity === "0" || styles.opacity === "0.0") return true;
  if (styles["font-size"]) {
    const m = styles["font-size"].match(/^([\d.]+)px/);
    if (m && parseFloat(m[1]!) < 2) return true;
  }
  if (styles["text-indent"] && styles["text-indent"].includes("-999")) return true;
  if (styles.position === "absolute" || styles.position === "fixed") {
    const l = styles.left || "";
    const t = styles.top || "";
    if (/^-?\d{3,}/.test(l) || /^-?\d{3,}/.test(t)) return true;
  }
  const w = styles.width;
  const h = styles.height;
  if ((w === "0" || w === "0px") && (h === "0" || h === "0px")) return true;
  return false;
}

function collectAncestorStyles($: cheerio.CheerioAPI, el: unknown): {
  combined: Record<string, string>;
  hidden: boolean;
} {
  const chain: unknown[] = [];
  let cur: unknown = el;
  while (cur) {
    chain.push(cur);
    const parent = $(cur as never).parent()[0];
    cur = parent;
    if (chain.length > 25) break;
  }
  const combined: Record<string, string> = {};
  let hidden = false;
  for (const node of chain) {
    const $node = $(node as never);
    const st = $node.attr("style");
    const parsed = parseStyle(st);
    Object.assign(combined, parsed);
    if ($node.attr("hidden") !== undefined) hidden = true;
    if (isHiddenByStyles(parsed)) hidden = true;
  }
  if (isHiddenByStyles(combined)) hidden = true;
  return { combined, hidden };
}

function hostnameOf(href: string, base: URL): string | null {
  try {
    return new URL(href, base).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Google IMA / AdSense / GAM, major social widgets, Bing UET, etc. often use
 * hidden or 1×1 iframes — not parasite indicators.
 */
function isBenignAdOrSocialIframeHost(hostname: string): boolean {
  const h = hostname.replace(/\.$/, "").toLowerCase();
  if (!h) return false;

  const exact = new Set([
    "imasdk.googleapis.com",
    "tpc.googlesyndication.com",
    "pagead2.googlesyndication.com",
    "www.googletagmanager.com",
    "www.google.com",
    "www.youtube.com",
    "www.youtube-nocookie.com",
    "player.vimeo.com",
    "platform.twitter.com",
    "syndication.twitter.com",
    "cdn.syndication.twimg.com",
    "connect.facebook.net",
    "www.facebook.com",
    "staticxx.facebook.com",
    "bat.bing.com",
    "www.reddit.com",
    "www.redditmedia.com",
    "accounts.google.com",
    "fundingchoicesmessages.google.com",
  ]);
  if (exact.has(h)) return true;

  const suffixOk = [
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "googletagservices.com",
    "2mdn.net",
    "bing.com",
    "facebook.com",
    "fbcdn.net",
    "twimg.com",
    "linkedin.com",
    "licdn.com",
    "instagram.com",
    "tiktok.com",
    "youtube.com",
    "snapchat.com",
    "amazon-adsystem.com",
    "ads-twitter.com",
  ];
  for (const s of suffixOk) {
    if (h === s || h.endsWith(`.${s}`)) return true;
  }

  return false;
}

/** Minified vendor widgets (Sucuri, Jetpack, WP emoji, etc.) trip crude regexes — skip those scripts. */
function isLikelyBenignWidgetScript(inline: string): boolean {
  const s = inline.slice(0, 4000).toLowerCase();
  return (
    s.includes("sucuri") ||
    s.includes("sitecheck") ||
    s.includes("wp-emoji") ||
    s.includes("wp-includes/js") ||
    s.includes("speed optimizer") ||
    s.includes("stats.wp.com") ||
    s.includes("jetpack") ||
    s.includes("woocommerce") ||
    s.includes("google-analytics") ||
    s.includes("googletagmanager")
  );
}

function hasDangerousLocationAssign(inline: string): boolean {
  return (
    /(?:^|[^\w$])(?:window|top|self|frames|parent)\.location(?:\.href)?\s*=\s*['"]https?:\/\//im.test(
      inline,
    ) ||
    /(?:^|[^\w$])document\.location(?:\.href)?\s*=\s*['"]https?:\/\//im.test(
      inline,
    )
  );
}

function finalizeFindings(rows: InternalRow[]): ScanFinding[] {
  const seen = new Set<string>();
  const out: ScanFinding[] = [];
  let seq = 0;
  for (const r of rows) {
    const severity: Severity | null =
      r.internal === "high" ? "medium" : r.internal === "medium" ? "low" : null;
    if (!severity) continue;
    const key = `${r.category}|${r.title}|${r.evidence.slice(0, 160)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    seq += 1;
    out.push({
      id: `f-${seq}`,
      severity,
      category: r.category,
      title: r.title,
      description: r.description,
      remediation: r.remediation,
      evidence: r.evidence,
    });
  }
  return out;
}

function scoreFromFindings(findings: ScanFinding[]): {
  verdict: Verdict;
  score: number;
  detectionConfidence: DetectionConfidence;
} {
  /** Cap so dozens of identical spam links do not pin the UI at 0/100 (misread as “no detection”). */
  const MAX_SAFETY_PENALTY = 68;

  const groups = new Map<string, ScanFinding[]>();
  for (const f of findings) {
    const k = `${f.category}\0${f.title}`;
    const arr = groups.get(k) ?? [];
    arr.push(f);
    groups.set(k, arr);
  }

  let penalty = 0;
  let totalMedium = 0;
  for (const arr of groups.values()) {
    const med = arr.filter((x) => x.severity === "medium").length;
    const low = arr.filter((x) => x.severity === "low").length;
    totalMedium += med;
    if (med > 0) {
      penalty += 20;
      penalty += Math.min(med - 1, 14) * 3;
    }
    if (low > 0) {
      penalty += 5;
      penalty += Math.min(low - 1, 15) * 2;
    }
  }

  penalty = Math.min(MAX_SAFETY_PENALTY, penalty);
  const score = Math.max(0, 100 - penalty);

  let verdict: Verdict = "clean";
  if (totalMedium >= 2 || score < 42) verdict = "infected";
  else if (findings.length > 0 || score < 80) verdict = "warning";

  const malwareCount = findings.filter((f) => f.category === "malware_patterns").length;
  const hiddenCount = findings.filter((f) => f.category === "hidden_links").length;

  let detectionConfidence: DetectionConfidence = "low";
  if (verdict === "infected") {
    if (malwareCount >= 10 || findings.length >= 18 || (malwareCount >= 6 && hiddenCount >= 4)) {
      detectionConfidence = "very_high";
    } else {
      detectionConfidence = "high";
    }
  } else if (verdict === "warning") {
    detectionConfidence = findings.length >= 6 ? "high" : "medium";
  }

  return { verdict, score, detectionConfidence };
}

function summarize(findings: ScanFinding[]): ScanSummary {
  const s: ScanSummary = {
    hiddenLinks: 0,
    cloakedLinks: 0,
    suspiciousIframes: 0,
    redirects: 0,
    suspiciousScripts: 0,
    malwarePatterns: 0,
    unusualResources: 0,
  };
  for (const f of findings) {
    switch (f.category) {
      case "hidden_links":
        s.hiddenLinks += 1;
        break;
      case "cloaked_links":
        s.cloakedLinks += 1;
        break;
      case "iframes":
        s.suspiciousIframes += 1;
        break;
      case "redirects":
        s.redirects += 1;
        break;
      case "scripts":
        s.suspiciousScripts += 1;
        break;
      case "malware_patterns":
        s.malwarePatterns += 1;
        break;
      case "resources":
        s.unusualResources += 1;
        break;
      default:
        break;
    }
  }
  return s;
}

export function analyzeHtml(
  html: string,
  requestedUrl: string,
  finalUrl: string,
  fetchMeta: {
    status: number;
    contentType: string | null;
    server: string | null;
    wasRedirected: boolean;
    fetchMs: number;
  },
): ScanResult {
  const rows: InternalRow[] = [];
  const base = new URL(finalUrl);

  const $ = cheerio.load(html, { xml: false });

  $("meta[http-equiv]").each((_, el) => {
    const equiv = ($(el).attr("http-equiv") || "").toLowerCase();
    if (equiv !== "refresh") return;
    const content = $(el).attr("content") || "";
    const m = content.match(/url\s*=\s*([^;]+)/i);
    const target = m?.[1]?.trim() || content;
    const host = hostnameOf(target, base);
    const pageHost = base.hostname;
    const internal: Internal =
      host && host !== pageHost.replace(/^www\./, "") && !host.endsWith(pageHost)
        ? "high"
        : "medium";
    rows.push({
      category: "redirects",
      internal,
      title: "Meta refresh redirect",
      description:
        "A meta refresh can send visitors (and bots) to another URL, sometimes injected by attackers.",
      remediation:
        "Remove unauthorized meta refresh tags or replace with server-side redirects you control.",
      evidence: truncate($.html(el)),
    });
  });

  if (fetchMeta.wasRedirected) {
    try {
      const orig = new URL(requestedUrl).hostname.replace(/^www\./, "");
      const fin = base.hostname.replace(/^www\./, "");
      if (orig !== fin) {
        rows.push({
          category: "redirects",
          internal: "medium",
          title: "Cross-domain HTTP redirect",
          description: `The initial host (${orig}) redirected to a different host (${fin}).`,
          remediation:
            "Verify this redirect is intentional (CDN, www canonical). Unexpected hops can indicate hijacking.",
          evidence: `${requestedUrl} → ${finalUrl}`,
        });
      }
    } catch {
      /* ignore */
    }
  }

  $("a[href]").each((_, el) => {
    const $a = $(el);
    const href = $a.attr("href") || "";
    const text = $a.text().replace(/\s+/g, " ").trim();

    const titleAttr = ($a.attr("title") || "").replace(/\s+/g, " ").trim();
    const linkLabel = [text, titleAttr].filter(Boolean).join(" ");

    const { hidden } = collectAncestorStyles($, el);
    const selfStyles = parseStyle($a.attr("style"));
    const selfHidden = isHiddenByStyles(selfStyles) || hidden;
    const ariaHidden = $a.attr("aria-hidden") === "true";

    if (selfHidden || ariaHidden) {
      rows.push({
        category: "hidden_links",
        internal: href.startsWith("http") ? "high" : "medium",
        title: "Hidden or suppressed link",
        description:
          "Link is styled or marked in a way that often hides it from visitors while keeping it in the DOM.",
        remediation:
          "Audit theme/plugins; remove unknown links; search codebase for injected HTML.",
        evidence: truncate(`href=${href} text="${text}" ${$.html(el)}`),
      });
    }

    if (/^javascript:/i.test(href)) {
      rows.push({
        category: "scripts",
        internal: "high",
        title: "javascript: URL in anchor",
        description:
          "javascript: links can run code on click and are a common obfuscation trick.",
        remediation: "Replace with standard https links or controlled event handlers.",
        evidence: truncate($.html(el)),
      });
    }

    const h = hostnameOf(href, base);
    const pageH = base.hostname.replace(/^www\./, "");
    if (h && h !== pageH && !h.endsWith(`.${pageH}`)) {
      const generic =
        !text ||
        /^[\d\s]+$/.test(text) ||
        /^(click|here|read more|more)$/i.test(text);
      if (generic) {
        const hasMedia = $a.find("img, svg, picture, video").length > 0;
        const label = (($a.attr("aria-label") || "") + ($a.attr("title") || "")).trim();
        const suspiciousHost = SUSPICIOUS_HOST_SUBSTR.some((frag) => h.includes(frag));
        if (!hasMedia && label.length < 3 && (hidden || suspiciousHost)) {
          rows.push({
            category: "cloaked_links",
            internal: "medium",
            title: "External link with vague anchor text",
            description:
              "Off-site link with little visible text while hidden or using a frequently abused host — common in SEO spam injections.",
            remediation:
              "Confirm legitimacy; remove unknown injections; disavow spam links if needed.",
            evidence: truncate(`href=${href} text="${text}"`),
          });
        }
      }
    }

    if (h) {
      for (const frag of SUSPICIOUS_HOST_SUBSTR) {
        if (h.includes(frag)) {
          rows.push({
            category: "malware_patterns",
            internal: "low",
            title: "Suspicious URL shortener / TLD pattern",
            description: `Host contains a commonly abused pattern: "${frag}".`,
            remediation: "Validate destination; attackers often chain cheap redirects.",
            evidence: truncate(href),
          });
          break;
        }
      }
    }

    if (SPAM_KEYWORD_RE.test(`${linkLabel} ${href}`) && (selfHidden || ariaHidden)) {
      rows.push({
        category: "malware_patterns",
        internal: "high",
        title: "Spam keywords in hidden context",
        description: "Hidden or aria-hidden link/URL matches spam/pharma-style vocabulary.",
        remediation: "Treat as compromise indicator — scan filesystem & DB, rotate creds.",
        evidence: truncate(`${linkLabel} | ${href}`),
      });
    }

    const offSite = !!(h && h !== pageH && !h.endsWith(`.${pageH}`));
    const visuallyHidden = selfHidden || ariaHidden || hidden;
    const spamLevel = parasiteAnchorPhraseLevel(linkLabel, {
      offSite,
      visuallyHidden,
    });
    if (spamLevel) {
      rows.push({
        category: "malware_patterns",
        internal: spamLevel === "high" ? "high" : "medium",
        title: "Parasite spam (anchor / title text)",
        description:
          "Visible or hidden link label/title matches phrases common in hacked footer injections (gambling SEO, pill spam, or similar). Destination is often an unrelated third-party site.",
        remediation:
          "Search theme, plugins, database options, and server files for this HTML; rotate CMS credentials; review recent admin logins.",
        evidence: truncate(`label="${linkLabel}" href=${href} ${$.html(el)}`),
      });
    }
  });

  $("iframe[src],iframe[data-src]").each((_, el) => {
    const $i = $(el);
    const src = $i.attr("src") || $i.attr("data-src") || "";
    const ih = hostnameOf(src, base);
    const benignEmbed = ih !== null && isBenignAdOrSocialIframeHost(ih);
    const w = parseFloat($i.attr("width") || "600") || 0;
    const h = parseFloat($i.attr("height") || "400") || 0;
    const st = parseStyle($i.attr("style"));
    const tiny =
      (w <= 2 && h <= 2) ||
      st.width === "0" ||
      st.height === "0" ||
      st.opacity === "0" ||
      st.display === "none";

    if ((tiny || st.visibility === "hidden") && !benignEmbed) {
      rows.push({
        category: "iframes",
        internal: "high",
        title: "Invisible or near-zero iframe",
        description:
          "Tiny or hidden iframes are a classic way to load ads, exploits, or click-fraud.",
        remediation: "Remove unknown iframes; inspect server & admin users for injections.",
        evidence: truncate($.html(el)),
      });
    }

    const pageIframe = base.hostname.replace(/^www\./, "");
    if (
      ih &&
      ih.replace(/^www\./, "") !== pageIframe &&
      !ih.endsWith(`.${pageIframe}`) &&
      !benignEmbed
    ) {
      rows.push({
        category: "resources",
        internal: "medium",
        title: "Cross-origin iframe",
        description: "Loads third-party content in an iframe — verify it is authorized.",
        remediation: "Check CSP, remove unknown embeds, review recent theme/plugin changes.",
        evidence: truncate(src),
      });
    }
  });

  $("script").each((_, el) => {
    const inline = $(el).html() || "";
    if (!inline.trim()) return;
    if (isLikelyBenignWidgetScript(inline)) return;

    if (/\beval\s*\(/i.test(inline)) {
      rows.push({
        category: "scripts",
        internal: "high",
        title: "Suspicious pattern: eval() usage",
        description: "eval() is a strong indicator of dynamic code execution or obfuscation.",
        remediation: "Compare against known-good bundles; prefer static modules and integrity hashes.",
        evidence: truncate(inline),
      });
    }

    if (/\bFunction\s*\(/i.test(inline)) {
      const compound =
        /\beval\s*\(/i.test(inline) ||
        (/\batob\s*\(/i.test(inline) && /\bfromCharCode\s*\(/i.test(inline));
      if (compound) {
        rows.push({
          category: "scripts",
          internal: "high",
          title: "Suspicious pattern: Function constructor (compound)",
          description:
            "Function constructor combined with other obfuscation primitives is uncommon in benign first-party code.",
          remediation: "Audit the script source; search the filesystem for unauthorized additions.",
          evidence: truncate(inline),
        });
      }
    }

    if (/\batob\s*\(/i.test(inline) || /\bfromCharCode\s*\(/i.test(inline)) {
      rows.push({
        category: "scripts",
        internal: "medium",
        title: "Suspicious pattern: atob / fromCharCode obfuscation helpers",
        description:
          "These APIs are often chained to unpack hidden strings — common in packed malware (and occasionally in benign minified code).",
        remediation: "Compare against a known-good bundle; look for nested encoding.",
        evidence: truncate(inline),
      });
    }

    if (/document\.write\s*\(/i.test(inline)) {
      rows.push({
        category: "scripts",
        internal: "medium",
        title: "Suspicious pattern: document.write",
        description: "document.write is rare in modern apps and sometimes used by injected ads.",
        remediation: "Verify provenance; prefer DOM APIs over document.write.",
        evidence: truncate(inline),
      });
    }

    if (/unescape\s*\(/i.test(inline)) {
      rows.push({
        category: "scripts",
        internal: "medium",
        title: "Suspicious pattern: unescape()",
        description: "Legacy unescape chains show up in older malware packers.",
        remediation: "Treat as worth manual review if not from a known vendor bundle.",
        evidence: truncate(inline),
      });
    }

    if (hasDangerousLocationAssign(inline)) {
      rows.push({
        category: "scripts",
        internal: "medium",
        title: "Suspicious pattern: hard-coded location redirect",
        description:
          "Assigning window/document.location to an absolute http(s) URL can hijack navigation.",
        remediation: "Confirm the redirect is intentional; look for unauthorized injections.",
        evidence: truncate(inline),
      });
    }
  });

  const htmlSample = html.slice(0, 120_000);
  const b64Attr = htmlSample.match(/base64,[A-Za-z0-9+/=]{200,}/g);
  if (b64Attr && b64Attr.length) {
    rows.push({
      category: "malware_patterns",
      internal: "medium",
      title: "Large inline base64 data URI",
      description: "Very large data: URIs can hide payloads or spam assets.",
      remediation: "Decode in a sandbox if needed; confirm the asset is legitimate.",
      evidence: truncate(b64Attr[0]!),
    });
  }

  const findings = finalizeFindings(rows);
  const { verdict, score, detectionConfidence } = scoreFromFindings(findings);
  const summary = summarize(findings);

  const snippet = truncate($.root().html() || "", 8000);

  return {
    url: requestedUrl,
    finalUrl,
    scannedAt: new Date().toISOString(),
    fetchMs: fetchMeta.fetchMs,
    verdict,
    detectionConfidence,
    score,
    summary,
    findings,
    htmlSnippet: snippet,
    response: {
      status: fetchMeta.status,
      contentType: fetchMeta.contentType,
      server: fetchMeta.server,
      wasRedirected: fetchMeta.wasRedirected,
    },
  };
}
