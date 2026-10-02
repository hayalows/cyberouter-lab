// Best-effort in-memory rate limiting for API routes.
// Per-isolate and per-instance only; a determined distributed attacker is not
// stopped by this. It bounds accidental abuse and obvious scripted hammering
// from a single source on the shared hosted deployment.

const buckets = new Map();
const SWEEP_INTERVAL_MS = 60_000;
const MAX_BUCKETS = 10_000;

let lastSweep = Date.now();

function sweep(now) {
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt <= now) buckets.delete(key);
  }
}

export function clientKey(request) {
  const forwarded = request.headers.get("x-forwarded-for") || "";
  const ip = forwarded.split(",")[0].trim() || request.headers.get("x-real-ip")?.trim() || "unknown";
  return ip.slice(0, 64);
}

/**
 * Returns { ok, retryAfterSeconds } and mutates the bucket for `key`.
 * `limit` requests per `windowMs`. Extra headers for 429 responses on success.
 */
export function rateLimit(request, { name, limit, windowMs }) {
  const now = Date.now();
  if (now - lastSweep > SWEEP_INTERVAL_MS) {
    sweep(now);
    lastSweep = now;
    if (buckets.size > MAX_BUCKETS) buckets.clear();
  }

  const key = `${name}:${clientKey(request)}`;
  let bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + windowMs };
    buckets.set(key, bucket);
  }
  bucket.count += 1;

  if (bucket.count > limit) {
    return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)) };
  }
  return { ok: true };
}

/** Standard JSON 429 response with Retry-After. */
export function rateLimitResponse(retryAfterSeconds) {
  return new Response(JSON.stringify({ error: "Too many requests. Wait a moment and try again." }), {
    status: 429,
    headers: {
      "Content-Type": "application/json",
      "Retry-After": String(retryAfterSeconds),
      "Cache-Control": "no-store, max-age=0",
    },
  });
}
