import { NextResponse } from "next/server";
import { githubError, githubJson, githubTokenFromRequest, rankTree } from "@/lib/github";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const url = new URL(request.url);
  const owner = url.searchParams.get("owner")?.trim();
  const repo = url.searchParams.get("repo")?.trim();
  const requestedRef = url.searchParams.get("ref")?.trim();
  const valid = /^[A-Za-z0-9_.-]+$/;

  if (!owner || !repo || !valid.test(owner) || !valid.test(repo)) {
    return NextResponse.json({ error: "Use a valid GitHub owner and repository name." }, { status: 400 });
  }

  const token = githubTokenFromRequest(request);
  const metadata = await githubJson(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, { token });

  if (!metadata.ok) {
    return NextResponse.json(
      { error: githubError(metadata, "Could not load the repository."), upstreamStatus: metadata.status },
      { status: metadata.status === 404 ? 404 : 502 },
    );
  }

  const ref = requestedRef || metadata.data.default_branch;
  const tree = await githubJson(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(ref)}?recursive=1`,
    { token },
  );

  if (!tree.ok) {
    return NextResponse.json(
      { error: githubError(tree, "Could not read the repository tree."), upstreamStatus: tree.status },
      { status: tree.status === 404 ? 404 : 502 },
    );
  }

  const candidates = rankTree(tree.data.tree || []);
  const directories = new Set(candidates.map((item) => item.path.split("/").slice(0, -1).join("/")).filter(Boolean));

  return NextResponse.json({
    repository: {
      owner,
      name: repo,
      fullName: metadata.data.full_name,
      private: Boolean(metadata.data.private),
      defaultBranch: metadata.data.default_branch,
      ref,
      description: metadata.data.description || "",
      htmlUrl: metadata.data.html_url,
      pushedAt: metadata.data.pushed_at,
      sizeKb: metadata.data.size,
    },
    tree: {
      truncated: Boolean(tree.data.truncated),
      reviewableFiles: candidates.length,
      directories: directories.size,
      candidates: candidates.slice(0, 320),
    },
    auth: { usingToken: Boolean(token) },
    rate: tree.rate,
  }, {
    headers: { "Cache-Control": "no-store, max-age=0" },
  });
}
