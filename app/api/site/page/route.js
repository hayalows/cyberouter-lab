import { NextResponse } from "next/server";
import { auditOwnedPage } from "@/lib/site-audit";
import { cyberouterFetch, keyFromRequest, errorMessage } from "@/lib/cyberouter";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;
export async function POST(request) {
  const json = (data, status = 200) => NextResponse.json(data, { status, headers: { "Cache-Control": "no-store" } });
  let payload; try { payload = await request.json(); } catch { return json({ error: "Use valid JSON." }, 400); }
  if (typeof payload?.target !== "string" || payload.target.length > 2000 || typeof payload?.page !== "string" || payload.page.length > 2000 || payload.authorized !== true || !/^cyberouter-[a-z0-9-]{16,120}$/i.test(payload.authorizationToken || "")) return json({ error: "An extended crawl needs a target, same-host page, ownership token and explicit authorization." }, 400);
  const auth = await cyberouterFetch("/models", { key: keyFromRequest(request), timeoutMs: 15000 });
  if (!auth.ok) return json({ error: errorMessage(auth.data, "Connect a valid Cyberouter key first.") }, 401);
  try { return json(await auditOwnedPage(payload.target, payload.page, payload)); }
  catch (error) { return json({ error: error?.message || "Owned page assessment failed." }, 400); }
}
