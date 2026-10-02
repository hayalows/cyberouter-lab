import { NextResponse } from "next/server";
import { auditPublicSite } from "@/lib/site-audit";
import { cyberouterFetch, errorMessage, keyFromRequest } from "@/lib/cyberouter";
import { rateLimit, rateLimitResponse } from "@/lib/rate-limit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function POST(request) {
  const limited = rateLimit(request, { name: "site-audit", limit: 8, windowMs: 60_000 });
  if (!limited.ok) return rateLimitResponse(limited.retryAfterSeconds);

  const key = keyFromRequest(request);

  const auth = await cyberouterFetch("/models", { key });
  if (!auth.ok) {
    return NextResponse.json(
      { error: errorMessage(auth.data, "Connect a valid Cyberouter API key before using the hosted website scanner.") },
      { status: 401, headers: { "Cache-Control": "no-store, max-age=0" } },
    );
  }

  let payload;
  try {
    payload = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const target = String(payload?.target || "").trim();
  const mode = payload?.mode === "active" ? "active" : "passive";
  const authorizationToken = String(payload?.authorizationToken || "");
  const authorized = payload?.authorized === true;

  if (!target || target.length > 2000) {
    return NextResponse.json({ error: "Enter a valid website URL." }, { status: 400 });
  }

  try {
    const result = await auditPublicSite(target, { mode, authorizationToken, authorized });
    return NextResponse.json(result, {
      headers: { "Cache-Control": "no-store, max-age=0" },
    });
  } catch (error) {
    return NextResponse.json(
      { error: error?.message || "Website audit failed." },
      { status: 400, headers: { "Cache-Control": "no-store, max-age=0" } },
    );
  }
}
