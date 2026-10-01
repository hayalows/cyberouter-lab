import { NextResponse } from "next/server";
import { githubError, githubJson, githubText, githubTokenFromRequest } from "@/lib/github";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const url = new URL(request.url);
  const owner = url.searchParams.get("owner")?.trim();
  const repo = url.searchParams.get("repo")?.trim();
  const number = Number(url.searchParams.get("number"));
  const valid = /^[A-Za-z0-9_.-]+$/;

  if (!valid.test(owner || "") || !valid.test(repo || "") || !Number.isInteger(number) || number < 1) {
    return NextResponse.json({ error: "Use a valid repository and pull request number." }, { status: 400 });
  }

  const token = githubTokenFromRequest(request);
  const base = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls/${number}`;
  const [details, diff] = await Promise.all([
    githubJson(base, { token }),
    githubText(base, { token, accept: "application/vnd.github.v3.diff" }),
  ]);

  if (!details.ok) {
    return NextResponse.json(
      { error: githubError(details, "Could not load the pull request."), upstreamStatus: details.status },
      { status: details.status === 404 ? 404 : 502 },
    );
  }
  if (!diff.ok) {
    return NextResponse.json({ error: "Could not load the pull request diff." }, { status: 502 });
  }

  return NextResponse.json({
    pullRequest: {
      number,
      title: details.data.title,
      htmlUrl: details.data.html_url,
      state: details.data.state,
      author: details.data.user?.login,
      base: details.data.base?.ref,
      head: details.data.head?.ref,
      changedFiles: details.data.changed_files,
      additions: details.data.additions,
      deletions: details.data.deletions,
    },
    diff: diff.text.slice(0, 500_000),
    truncated: diff.text.length > 500_000,
  }, {
    headers: { "Cache-Control": "no-store, max-age=0" },
  });
}
