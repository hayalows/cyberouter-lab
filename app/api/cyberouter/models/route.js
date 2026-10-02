import { NextResponse } from "next/server";
import { cyberouterFetch, errorMessage, keyFromRequest } from "@/lib/cyberouter";
import { rateLimit, rateLimitResponse } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const limited = rateLimit(request, { name: "models", limit: 30, windowMs: 60_000 });
  if (!limited.ok) return rateLimitResponse(limited.retryAfterSeconds);

  const key = keyFromRequest(request);
  const result = await cyberouterFetch("/models", { key });

  return NextResponse.json(result.ok ? result.data : {
    error: errorMessage(result.data),
    upstreamStatus: result.status,
  }, {
    status: result.ok ? 200 : result.status,
    headers: { "Cache-Control": "no-store, max-age=0" },
  });
}
