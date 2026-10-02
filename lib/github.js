const API = "https://api.github.com";
const USER_AGENT = "cyberouter-lab";

export function githubTokenFromRequest(request) {
  return request.headers.get("x-github-token")?.trim() || "";
}

export function parseRepository(input = "") {
  let value = String(input).trim().replace(/\.git$/i, "");
  value = value.replace(/^https?:\/\/github\.com\//i, "").replace(/^github\.com\//i, "");
  const [owner, repo] = value.split("/").filter(Boolean);
  const valid = /^[A-Za-z0-9_.-]+$/;
  if (!owner || !repo || !valid.test(owner) || !valid.test(repo)) return null;
  return { owner, repo };
}

export async function githubJson(path, { token = "", accept = "application/vnd.github+json" } = {}) {
  const response = await fetch(`${API}${path}`, {
    headers: {
      Accept: accept,
      "User-Agent": USER_AGENT,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    cache: "no-store",
    signal: AbortSignal.timeout(20000),
  });

  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { message: text || `GitHub returned HTTP ${response.status}` };
  }

  return {
    ok: response.ok,
    status: response.status,
    data,
    rate: {
      remaining: response.headers.get("x-ratelimit-remaining"),
      reset: response.headers.get("x-ratelimit-reset"),
    },
  };
}

export async function githubText(path, { token = "", accept = "application/vnd.github.v3.diff" } = {}) {
  const response = await fetch(`${API}${path}`, {
    headers: {
      Accept: accept,
      "User-Agent": USER_AGENT,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    cache: "no-store",
    signal: AbortSignal.timeout(20000),
  });
  return {
    ok: response.ok,
    status: response.status,
    text: await response.text(),
  };
}

const SOURCE_EXTENSIONS = new Set([
  ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
  ".py", ".go", ".rs", ".java", ".kt", ".kts", ".php", ".rb",
  ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift",
  ".sql", ".graphql", ".gql", ".sh", ".bash", ".ps1",
  ".yaml", ".yml", ".toml", ".json", ".xml",
]);

const IMPORTANT_FILES = [
  "dockerfile", "docker-compose.yml", "docker-compose.yaml",
  "package.json", "requirements.txt", "pyproject.toml", "poetry.lock",
  "go.mod", "cargo.toml", "gemfile", "composer.json",
  "vercel.json", "next.config.js", "next.config.mjs", "next.config.ts",
  "middleware.js", "middleware.ts", ".env.example",
];

const SKIP_PARTS = [
  "node_modules/", ".next/", "dist/", "build/", "vendor/", ".git/",
  "coverage/", "public/", "static/", "__snapshots__/", ".turbo/",
];

function extension(path) {
  const name = path.toLowerCase();
  const idx = name.lastIndexOf(".");
  return idx >= 0 ? name.slice(idx) : "";
}

export function isReviewablePath(path, size = 0) {
  const lower = path.toLowerCase();
  if (size > 250_000) return false;
  if (SKIP_PARTS.some((part) => lower.includes(part))) return false;
  if (/\.(min\.js|min\.css|map|png|jpe?g|gif|webp|svg|ico|pdf|zip|gz|tar|woff2?|ttf|eot|mp4|mov|mp3)$/i.test(lower)) return false;
  const base = lower.split("/").pop();
  if (IMPORTANT_FILES.includes(base)) return true;
  if (/^(migration|schema|seed).*\.(sql|js|ts|py)$/i.test(base)) return true;
  return SOURCE_EXTENSIONS.has(extension(lower));
}

export function securityScore(path = "") {
  const p = path.toLowerCase();
  let score = 0;
  const high = [
    ["auth", 14], ["login", 12], ["session", 12], ["permission", 12], ["role", 10],
    ["middleware", 11], ["api/", 10], ["server", 7], ["route.", 9], ["controller", 8],
    ["database", 8], ["db/", 8], ["query", 8], ["sql", 10], ["migration", 7],
    ["supabase", 12], ["neon", 10], ["rls", 15], ["policy", 10], ["admin", 10],
    ["upload", 10], ["file", 5], ["webhook", 11], ["oauth", 13], ["callback", 8],
    ["payment", 10], ["stripe", 10], ["secret", 12], ["token", 10], ["crypto", 10],
    ["password", 12], ["reset", 9], ["cors", 9], ["proxy", 8], ["worker", 5],
    ["vercel.json", 8], ["next.config", 6], ["docker", 6], [".github/workflows", 8],
    ["package.json", 6], ["requirements", 6], ["pyproject", 6],
  ];
  for (const [needle, weight] of high) if (p.includes(needle)) score += weight;
  if (/\/app\/api\//.test(p) || /\/pages\/api\//.test(p)) score += 12;
  if (/\.(sql|yml|yaml|toml)$/.test(p)) score += 3;
  if (/test|spec|fixture|mock/.test(p)) score -= 4;
  return score;
}

export function rankTree(tree = []) {
  return tree
    .filter((item) => item?.type === "blob" && isReviewablePath(item.path, item.size || 0))
    .map((item) => ({ path: item.path, size: item.size || 0, score: securityScore(item.path) }))
    .sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
}

export function githubError(result, fallback = "GitHub request failed.") {
  return result?.data?.message || fallback;
}

export function decodeBase64Content(value = "") {
  try {
    return Buffer.from(value.replace(/\n/g, ""), "base64").toString("utf8");
  } catch {
    return "";
  }
}
