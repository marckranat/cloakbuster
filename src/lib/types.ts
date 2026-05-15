export type Severity = "medium" | "low";

export type Verdict = "clean" | "warning" | "infected";

export type FindingCategory =
  | "hidden_links"
  | "cloaked_links"
  | "iframes"
  | "redirects"
  | "scripts"
  | "malware_patterns"
  | "resources";

export interface ScanFinding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  evidence: string;
}

export interface ScanSummary {
  hiddenLinks: number;
  cloakedLinks: number;
  suspiciousIframes: number;
  redirects: number;
  suspiciousScripts: number;
  malwarePatterns: number;
  unusualResources: number;
}

export interface ScanResult {
  url: string;
  finalUrl: string;
  scannedAt: string;
  fetchMs: number;
  verdict: Verdict;
  score: number;
  summary: ScanSummary;
  findings: ScanFinding[];
  /** Short HTML excerpt for debugging — not full page (privacy) */
  htmlSnippet: string;
  response: {
    status: number;
    contentType: string | null;
    server: string | null;
    wasRedirected: boolean;
  };
  /** How HTML was obtained — Playwright executes page JS (preferred when installed). */
  renderEngine?: "playwright" | "fetch";
  /** Present when Playwright was requested but not used or failed early. */
  renderNote?: string | null;
}
