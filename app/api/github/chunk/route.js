import { NextResponse } from "next/server";
import { decodeBase64Content, githubError, githubJson, githubTokenFromRequest } from "@/lib/github";
import { DEEP_FILE_BYTES, exclusionReason, nextChunk, sourceFacts } from "@/lib/deep-audit";
import { redactSensitiveText } from "@/lib/sensitive-content";
import { scanLocalRules } from "@/lib/security-casebook";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 60;
const json = (data, status = 200) => NextResponse.json(data, { status, headers: { "Cache-Control": "no-store, max-age=0" } });
export async function GET(request) {
  const q = new URL(request.url).searchParams; const owner = q.get("owner"), repo = q.get("repo"), commit = q.get("commit"), path = q.get("path"), offset = Number(q.get("offset") || 0);
  if (!/^[A-Za-z0-9_.-]+$/.test(owner || "") || !/^[A-Za-z0-9_.-]+$/.test(repo || "") || !/^[a-f0-9]{40}$/.test(commit || "") || !path || path.length > 1000 || path.startsWith("/") || path.split("/").some(p => p === ".." || !p) || !Number.isInteger(offset) || offset < 0 || offset > 2_000_000) return json({ error: "Supply a repository, pinned commit, relative file path and valid offset." }, 400);
  const result = await githubJson(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${commit}`, { token: githubTokenFromRequest(request) });
  if (!result.ok) return json({ error: githubError(result), upstreamStatus: result.status }, result.status === 404 ? 404 : result.status === 403 || result.status === 429 ? 429 : 502);
  if (result.data.type !== "file" || result.data.submodule_git_url || result.data.target) return json({ error: "Only ordinary repository files are supported." }, 400);
  const reason = exclusionReason({ path, size: result.data.size, type: "blob" });
  if (reason || result.data.size > DEEP_FILE_BYTES) return json({ error: reason || "File exceeds 1 MB." }, 413);
  if (result.data.encoding !== "base64") return json({ error: "GitHub did not provide decodable source content." }, 422);
  const source = decodeBase64Content(result.data.content || "");
  if (source.includes("\u0000") || source.includes("\uFFFD")) return json({ error: "Binary or non-UTF-8 content is not supported." }, 422);
  const safe = redactSensitiveText(source);
  try {
    const chunk = nextChunk(safe.text, offset);
    const local = offset === 0 ? scanLocalRules([{ path, content: source }]) : null;
    return json({ path, sha: result.data.sha, ...chunk, lines: source ? source.split("\n").length - Number(source.endsWith("\n")) : 0, redactions: safe.redactionCount, ...(offset === 0 ? { facts: sourceFacts(safe.text, path), localFindings: local.findings, localCapped: local.capped } : {}), rate: result.rate });
  } catch (error) { return json({ error: error.message }, 400); }
}
