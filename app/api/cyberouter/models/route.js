import { NextResponse } from "next/server";
import { cyberouterFetch, errorMessage, keyFromRequest } from "@/lib/cyberouter";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
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
