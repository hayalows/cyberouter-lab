import { NextResponse } from "next/server";
import {
  decodeBase64Content,
  githubError,
  githubJson,
  githubTokenFromRequest,
  isReviewablePath,
} from "@/lib/github";
import { rateLimit, rateLimitResponse } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 60;

function encodePath(path) {
  return path.split("/").map(encodeURIComponent).join("/");
}

async function readFile({ owner, repo, ref, path, token }) {
  const result = await githubJson(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodePath(path)}?ref=${encodeURIComponent(ref)}`,
    { token },
  );

  if (!result.ok) return { path, error: githubError(result), status: result.status };
  if (result.data.type !== "file") return { path, error: "Not a file." };
  if (!isReviewablePath(path, result.data.size || 0)) return { path, error: "Skipped by source-file policy." };

  const decoded = result.data.encoding === "base64" ? decodeBase64Content(result.data.content || "") : "";
  if (!decoded) return { path, error: "Could not decode file content." };

  return {
    path,
    size: result.data.size || decoded.length,
    sha: result.data.sha,
    content: decoded.slice(0, 90_000),
    truncated: decoded.length > 90_000,
  };
}

export async function POST(request) {
  const limited = rateLimit(request, { name: "gh-files", limit: 20, windowMs: 60_000 });
  if (!limited.ok) return rateLimitResponse(limited.retryAfterSeconds);

  const token = githubTokenFromRequest(request);
  let payload;
  try {
    payload = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const { owner, repo, ref, paths } = payload || {};
  const valid = /^[A-Za-z0-9_.-]+$/;
  if (!valid.test(owner || "") || !valid.test(repo || "") || !ref || !Array.isArray(paths)) {
    return NextResponse.json({ error: "Repository, ref, and file paths are required." }, { status: 400 });
  }

  const unique = [...new Set(paths.filter((p) => typeof p === "string" && p.length <= 500))].slice(0, 24);
  const files = [];
  for (let i = 0; i < unique.length; i += 6) {
    const group = unique.slice(i, i + 6);
    const results = await Promise.all(group.map((path) => readFile({ owner, repo, ref, path, token })));
    files.push(...results);
  }

  let total = 0;
  const bounded = [];
  for (const file of files) {
    if (!file.content) {
      bounded.push(file);
      continue;
    }
    if (total + file.content.length > 700_000) {
      bounded.push({ path: file.path, error: "Skipped because this request reached the content-size limit." });
      continue;
    }
    total += file.content.length;
    bounded.push(file);
  }

  return NextResponse.json({
    files: bounded,
    totalChars: total,
  }, {
    headers: { "Cache-Control": "no-store, max-age=0" },
  });
}
