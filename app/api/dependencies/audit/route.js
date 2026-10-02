import { NextResponse } from "next/server";
import { MAX_PACKAGES, validPackage } from "@/lib/dependency-audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;
const OSV = "https://api.osv.dev/v1/query";
const response = (body, status = 200) => NextResponse.json(body, { status, headers: { "Cache-Control": "no-store, max-age=0" } });
function advisory(vuln, packageName) {
  const severity = String(vuln.database_specific?.severity || "").toLowerCase().replace("moderate", "medium");
  const fixed = [...new Set((vuln.affected || []).filter(a => a.package?.ecosystem === "npm" && a.package?.name === packageName).flatMap(a => (a.ranges || []).flatMap(r => (r.events || []).map(e => e.fixed).filter(Boolean))))].slice(0, 15);
  return { id: String(vuln.id || "").slice(0, 150), summary: String(vuln.summary || vuln.id || "Advisory").slice(0, 1000), aliases: (vuln.aliases || []).slice(0, 10), severity: ["critical", "high", "medium", "low"].includes(severity) ? severity : "", cwe: (vuln.database_specific?.cwe_ids || []).find(c => /^CWE-\d{1,5}$/.test(c)) || "", fixed, url: `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id || "")}` };
}
async function audit(packages) {
  if (!Array.isArray(packages) || !packages.length || packages.length > MAX_PACKAGES || packages.some(p => !validPackage(p))) return response({ error: `Supply 1–${MAX_PACKAGES} npm packages with exact resolved versions.` }, 400);
  const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 40_000);
  const results = [];
  try {
    for (let i = 0; i < packages.length; i += 5) {
      results.push(...await Promise.all(packages.slice(i, i + 5).map(async pkg => {
        const base = { name: pkg.name, version: pkg.version, path: typeof pkg.path === "string" ? pkg.path.slice(0, 1000) : "package-lock.json" };
        try {
          const upstream = await fetch(OSV, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ package: { name: pkg.name, ecosystem: "npm" }, version: pkg.version }), signal: controller.signal, cache: "no-store" });
          if (!upstream.ok) return { ...base, error: `Advisory service returned HTTP ${upstream.status}.`, advisories: [] };
          const data = await upstream.json();
          if (data.vulns !== undefined && !Array.isArray(data.vulns)) return { ...base, error: "Advisory service returned an unsupported response.", advisories: [] };
          const active = (data.vulns || []).filter(v => !v.withdrawn);
          return { ...base, advisories: active.slice(0, 25).map(v => advisory(v, pkg.name)), truncated: active.length > 25 };
        } catch { return { ...base, error: controller.signal.aborted ? "Advisory lookup timed out. Retry this package." : "Could not reach the advisory service. Retry later.", advisories: [] }; }
      })));
      if (controller.signal.aborted) {
        results.push(...packages.slice(i + 5).map(p => ({ name: p.name, version: p.version, path: p.path, error: "Skipped after lookup deadline. Retry this package.", advisories: [] })));
        break;
      }
    }
    return response({ source: "OSV.dev", checkedAt: new Date().toISOString(), results });
  } finally { clearTimeout(timeout); }
}
export async function POST(request) {
  const body = await request.text();
  if (body.length > 160_000) return response({ error: "Inventory request is too large." }, 413);
  let data; try { data = JSON.parse(body); } catch { return response({ error: "Use a valid JSON inventory." }, 400); }
  return audit(data?.packages);
}
// A single-package read path permits public inspection without uploading a lockfile.
export async function GET(request) {
  const query = new URL(request.url).searchParams;
  return audit([{ name: query.get("name"), version: query.get("version") }]);
}
