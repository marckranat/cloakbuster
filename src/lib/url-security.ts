import dns from "node:dns/promises";
import net from "node:net";

const BLOCKED_HOSTNAMES = new Set(
  [
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "metadata.google.internal",
    "metadata.google.internal.",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
  ].map((h) => h.toLowerCase()),
);

function normalizeHost(hostname: string): string {
  return hostname.replace(/\.$/, "").toLowerCase();
}

/** Strip IPv4-mapped IPv6 prefix */
function normalizeIp(addr: string): string {
  const a = addr.toLowerCase();
  if (a.startsWith("::ffff:")) return a.slice(7);
  return a;
}

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map((x) => Number(x));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255))
    return true;
  const [a, b] = parts;
  if (a === undefined || b === undefined) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a >= 224 && a <= 239) return true;
  return false;
}

function isPrivateIpv6(ip: string): boolean {
  const i = ip.toLowerCase();
  if (i === "::1") return true;
  if (i.startsWith("fc") || i.startsWith("fd")) return true;
  if (i.startsWith("fe80:")) return true;
  if (i.startsWith("::ffff:")) {
    const v4 = i.slice(7);
    return net.isIPv4(v4) && isPrivateIpv4(v4);
  }
  return false;
}

function isBlockedIp(ip: string): boolean {
  const n = normalizeIp(ip);
  if (net.isIPv4(n)) return isPrivateIpv4(n);
  if (net.isIPv6(n)) return isPrivateIpv6(n);
  return true;
}

function assertHostnameShape(hostname: string): void {
  const h = normalizeHost(hostname);
  if (!h || h.length > 253) throw new Error("Invalid hostname");
  if (BLOCKED_HOSTNAMES.has(h)) throw new Error("Blocked hostname");
  if (h.endsWith(".localhost") || h.endsWith(".local")) {
    throw new Error("Blocked hostname suffix");
  }
}

/**
 * Reject characters that show up in SSRF gadgets, header smuggling, or log/UI oddities.
 * We intentionally do **not** recursively percent-decode strings — decoding is handled once
 * by the WHATWG `URL` parser inside {@link assertUrlSafeForFetch}.
 */
export function assertUrlStringHygiene(raw: string): void {
  const t = raw.trim();
  if (!t.length) throw new Error("Empty URL");
  if (t.length > 2048) throw new Error("URL too long");
  if (/[\u0000-\u001f\u007f]/.test(t)) {
    throw new Error("URL contains control characters");
  }
  if (/\s/.test(t)) {
    throw new Error("URL contains whitespace");
  }
  if (t.includes("\\")) {
    throw new Error("URL must not contain backslashes");
  }
}

/**
 * Validates URL shape + resolves DNS — call before any outbound HTTP or browser navigation.
 */
export async function assertUrlSafeForFetch(urlString: string): Promise<URL> {
  assertUrlStringHygiene(urlString);

  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    throw new Error("Invalid URL");
  }

  if (url.username || url.password) {
    throw new Error("URLs with credentials are not allowed");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    if (url.protocol === "blob:") {
      return url;
    }
    if (url.protocol === "data:") {
      const p = urlString.slice(0, 64).toLowerCase();
      if (
        p.startsWith("data:image/") ||
        p.startsWith("data:font/") ||
        p.startsWith("data:application/font") ||
        p.startsWith("data:application/x-font-ttf") ||
        p.startsWith("data:application/vnd.ms-fontobject")
      ) {
        return url;
      }
      throw new Error("Blocked data: URL (non-font/image)");
    }
    throw new Error("Only http(s) URLs are allowed");
  }

  const hostname = url.hostname;
  assertHostnameShape(hostname);

  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) throw new Error("Blocked IP literal in URL");
    return url;
  }

  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length) throw new Error("Host could not be resolved");

  for (const r of records) {
    if (isBlockedIp(r.address)) {
      throw new Error("Host resolves to a non-public address");
    }
  }

  return url;
}
