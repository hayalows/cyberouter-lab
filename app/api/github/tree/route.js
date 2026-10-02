import { NextResponse } from "next/server";
import { githubJson, githubError, githubTokenFromRequest } from "@/lib/github";
import { rateLimit, rateLimitResponse } from "@/lib/rate-limit";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export async function GET(request) {
  const limited = rateLimit(request, { name: "gh-tree", limit: 60, windowMs: 60_000 });
  if (!limited.ok) return rateLimitResponse(limited.retryAfterSeconds);
  const q = new URL(request.url).searchParams; const owner = q.get("owner"), repo = q.get("repo"), sha = q.get("sha");
  const json = (data, status = 200) => NextResponse.json(data, { status, headers: { "Cache-Control": "no-store" } });
  if (!/^[A-Za-z0-9_.-]+$/.test(owner || "") || !/^[A-Za-z0-9_.-]+$/.test(repo || "") || !/^[a-f0-9]{40}$/.test(sha || "")) return json({ error: "Supply a repository and immutable tree SHA." }, 400);
  const result = await githubJson(`/repos/${owner}/${repo}/git/trees/${sha}`, { token: githubTokenFromRequest(request) });
  if (!result.ok) return json({ error: githubError(result), upstreamStatus: result.status }, result.status === 403 || result.status === 429 ? 429 : 502);
  if (result.data.truncated) return json({ error: "GitHub truncated this directory listing. Coverage cannot be marked complete." }, 422);
  return json({ entries: (result.data.tree || []).map(e => ({ path: e.path, sha: e.sha, size: e.size || 0, mode: e.mode, type: e.type })), rate: result.rate });
}
