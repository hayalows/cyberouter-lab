import { NextResponse } from "next/server";
import { githubJson, githubError, githubTokenFromRequest } from "@/lib/github";
import { rateLimit, rateLimitResponse } from "@/lib/rate-limit";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;
async function publicJSON(url, byteLimit = 8_000_000) {
  const r = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(15000), headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`Source returned HTTP ${r.status}.`);
  const reader = r.body.getReader(); const chunks = []; let count = 0;
  try { while (true) { const { value, done } = await reader.read(); if (done) break; count += value.byteLength; if (count > byteLimit) throw new Error("Source response exceeded the bounded feed size."); chunks.push(value); } }
  finally { await reader.cancel().catch(() => {}); }
  const all = new Uint8Array(count); let offset = 0; for (const c of chunks) { all.set(c, offset); offset += c.length; }
  return JSON.parse(new TextDecoder().decode(all));
}
export async function GET(request) {
  const limited = rateLimit(request, { name: "intel", limit: 12, windowMs: 60_000 });
  if (!limited.ok) return rateLimitResponse(limited.retryAfterSeconds);
  const q = new URL(request.url).searchParams; const kind = q.get("kind");
  const json = (data, status = 200) => NextResponse.json(data, { status, headers: { "Cache-Control": "no-store" } });
  if (kind === "repo") {
    const owner = q.get("owner"), repo = q.get("repo");
    if (!/^[A-Za-z0-9_.-]+$/.test(owner || "") || !/^[A-Za-z0-9_.-]+$/.test(repo || "")) return json({ error: "Use a valid GitHub owner and repository." }, 400);
    try {
      const token = githubTokenFromRequest(request); const base = `/repos/${owner}/${repo}`;
      const metadata = await githubJson(base, { token }); if (!metadata.ok) return json({ error: githubError(metadata) }, metadata.status === 404 ? 404 : 502);
      const branch = metadata.data.default_branch;
      const results = await Promise.allSettled([
        githubJson(`${base}/commits?per_page=5`, { token }),
        githubJson(`${base}/contents/SECURITY.md?ref=${encodeURIComponent(branch)}`, { token }),
        githubJson(`${base}/contents/.github/SECURITY.md?ref=${encodeURIComponent(branch)}`, { token }),
        githubJson(`${base}/branches/${encodeURIComponent(branch)}`, { token }),
      ]);
      const unwrap = i => results[i].status === "fulfilled" ? results[i].value : { ok: false, status: 0 };
      const commits = unwrap(0), security = [unwrap(1), unwrap(2)], protection = unwrap(3);
      return json({ source: "GitHub repository metadata", checkedAt: new Date().toISOString(), repository: { fullName: metadata.data.full_name, url: metadata.data.html_url, archived: Boolean(metadata.data.archived), fork: Boolean(metadata.data.fork), defaultBranch: branch, license: metadata.data.license?.spdx_id || "Not declared", pushedAt: metadata.data.pushed_at, stars: metadata.data.stargazers_count, securityPolicy: security.some(r => r.ok) ? "Located at a standard path" : security.every(r => r.status === 404) ? "Not found at the two standard paths" : "Could not verify", protectedBranch: protection.ok ? Boolean(protection.data.protected) : null, commit: protection.ok ? protection.data.commit?.sha : null, recentCommits: commits.ok && Array.isArray(commits.data) ? commits.data.map(c => ({ sha: c.sha, date: c.commit?.committer?.date, subject: c.commit?.message?.split("\n")[0]?.slice(0, 300) })) : [], gaps: [!commits.ok && "Recent commits unavailable", !protection.ok && "Branch protection metadata unavailable", !security.some(r => r.ok) && !security.every(r => r.status === 404) && "Security policy lookup incomplete"].filter(Boolean) }, note: "Maintenance, popularity and policy metadata are context, not a security rating or assurance of code quality." });
    } catch { return json({ error: "Repository intelligence could not be loaded. Check GitHub access and retry." }, 502); }
  }
  if (kind === "cve") {
    const cve = (q.get("cve") || "").toUpperCase();
    if (!/^CVE-\d{4}-\d{4,9}$/.test(cve)) return json({ error: "Use a CVE ID, such as CVE-2021-44228." }, 400);
    const sources = await Promise.allSettled([
      publicJSON("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
      publicJSON(`https://api.first.org/data/v1/epss?cve=${cve}`, 1_000_000),
      publicJSON(`https://api.osv.dev/v1/vulns/${cve}`, 2_000_000),
    ]);
    const result = { cve, checkedAt: new Date().toISOString(), sources: [] };
    const kev = sources[0];
    if (kev.status === "fulfilled" && Array.isArray(kev.value.vulnerabilities)) { const item = kev.value.vulnerabilities.find(v => v.cveID === cve); result.sources.push({ id: "cisa-kev", name: "CISA Known Exploited Vulnerabilities", status: "ok", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", catalogDate: kev.value.dateReleased, listed: Boolean(item), ...(item ? { vendor: item.vendorProject, product: item.product, title: item.vulnerabilityName, description: item.shortDescription, action: item.requiredAction, ransomware: item.knownRansomwareCampaignUse, dateAdded: item.dateAdded } : {}), note: "Presence is evidence that CISA records exploitation in the wild. Absence is not evidence of no exploitation or no risk." }); }
    else result.sources.push({ id: "cisa-kev", name: "CISA KEV", status: "error", error: "CISA catalog unavailable or invalid. Exploitation status remains unknown." });
    const epss = sources[1]; const score = epss.status === "fulfilled" && Array.isArray(epss.value.data) ? epss.value.data.find(d => d.cve === cve) : null;
    result.sources.push(score ? { id: "first-epss", name: "FIRST EPSS", status: "ok", url: `https://www.first.org/epss/`, date: score.date, probability: Number(score.epss), percentile: Number(score.percentile), note: "A model estimate of exploitation probability in the next 30 days, not proof of exploitability or application exposure." } : { id: "first-epss", name: "FIRST EPSS", status: epss.status === "fulfilled" ? "not-found" : "error", error: "No current EPSS estimate could be verified for this ID." });
    const osv = sources[2];
    result.sources.push(osv.status === "fulfilled" ? { id: "osv", name: "OSV vulnerability record", status: "ok", url: `https://osv.dev/vulnerability/${encodeURIComponent(osv.value.id || cve)}`, summary: osv.value.summary || "", withdrawn: osv.value.withdrawn || null, aliases: (osv.value.aliases || []).slice(0, 20), packages: (osv.value.affected || []).map(a => ({ ecosystem: a.package?.ecosystem, name: a.package?.name })).slice(0, 50), note: "OSV records do not cover every CVE. Check package ranges in the original record before selecting a fix." } : { id: "osv", name: "OSV vulnerability record", status: "unavailable", error: "No OSV record was returned; this does not invalidate the CVE." });
    return json(result);
  }
  return json({ error: "Choose a supported intelligence type: repo or cve." }, 400);
}
