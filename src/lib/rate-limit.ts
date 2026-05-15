const WINDOW_MS = 60_000;
const MAX_REQUESTS = 5;

type Bucket = { count: number; resetAt: number };

const buckets = new Map<string, Bucket>();

function getClientIp(headers: Headers): string {
  const forwarded = headers.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0]?.trim() || "unknown";
  }
  const realIp = headers.get("x-real-ip");
  if (realIp) return realIp.trim();
  return "unknown";
}

export function checkRateLimit(headers: Headers): {
  ok: boolean;
  remaining: number;
  resetInMs: number;
} {
  const ip = getClientIp(headers);
  const now = Date.now();
  let b = buckets.get(ip);
  if (!b || now > b.resetAt) {
    b = { count: 0, resetAt: now + WINDOW_MS };
    buckets.set(ip, b);
  }
  if (b.count >= MAX_REQUESTS) {
    return { ok: false, remaining: 0, resetInMs: Math.max(0, b.resetAt - now) };
  }
  b.count += 1;
  return {
    ok: true,
    remaining: MAX_REQUESTS - b.count,
    resetInMs: Math.max(0, b.resetAt - now),
  };
}
