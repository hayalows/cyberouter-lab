import { normalizeFinding } from "./security-casebook";

export const MAX_PACKAGES = 80;
const NPM_NAME = /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
export function validPackage(p) { return p && typeof p.name === "string" && p.name.length <= 214 && NPM_NAME.test(p.name) && typeof p.version === "string" && p.version.length <= 100 && VERSION.test(p.version); }

/** Use resolved lockfile versions; do not guess a version from semver ranges. */
export function parseNpmInventory(text, includeDev = false) {
  if (new TextEncoder().encode(text).length > 4_000_000) throw new Error("Use a manifest or lockfile smaller than 4 MB.");
  let data;
  try { data = JSON.parse(text); } catch { throw new Error("This file is not valid JSON. Use package-lock.json, npm-shrinkwrap.json or package.json."); }
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Use an npm manifest or lockfile object.");
  const unique = new Map(); let skipped = 0;
  const add = (name, entry, path) => {
    if (!entry || typeof entry !== "object" || (entry.dev && !includeDev)) return;
    const pkg = { name, version: entry.version, path, dev: Boolean(entry.dev) };
    if (!validPackage(pkg)) { skipped++; return; }
    const key = `${name}@${pkg.version}`;
    const old = unique.get(key);
    unique.set(key, old ? { ...old, dev: old.dev && pkg.dev } : pkg);
  };
  let format;
  if (data.packages && [2, 3].includes(data.lockfileVersion)) {
    format = `npm lockfile v${data.lockfileVersion}`;
    for (const [path, entry] of Object.entries(data.packages)) {
      if (!path) continue;
      const name = entry?.name || path.split("node_modules/").at(-1);
      if (!path.includes("node_modules/") && !entry?.name) { skipped++; continue; }
      add(name, entry, path);
    }
  } else if (data.lockfileVersion === 1 && data.dependencies) {
    format = "npm lockfile v1";
    let nodes = 0;
    const visit = (deps, parent = "", depth = 0) => {
      if (depth > 30) throw new Error("Lockfile nesting exceeds the supported limit.");
      for (const [name, entry] of Object.entries(deps || {})) {
        if (++nodes > 20000) throw new Error("Lockfile contains too many entries.");
        const path = `${parent}node_modules/${name}`; add(name, entry, path); visit(entry?.dependencies, `${path}/`, depth + 1);
      }
    };
    visit(data.dependencies);
  } else if (!data.lockfileVersion && (data.dependencies || data.devDependencies)) {
    format = "package.json · exact versions only";
    for (const [name, version] of Object.entries(data.dependencies || {})) add(name, { version }, "package.json");
    if (includeDev) for (const [name, version] of Object.entries(data.devDependencies || {})) add(name, { version, dev: true }, "package.json");
  } else throw new Error("Unsupported npm file. Use a package-lock/shrinkwrap v1–v3 or a package.json with dependencies.");
  const packages = [...unique.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return { name: typeof data.name === "string" ? data.name : "npm project", format, packages, skipped, includeDev };
}

export function advisoryFindings(results) {
  return results.flatMap(result => (result.advisories || []).map(a => normalizeFinding({
    ruleId: a.id, title: `${result.name}@${result.version} · ${a.summary || a.id}`,
    source: "advisory", severity: ["critical", "high", "medium", "low"].includes(a.severity) ? a.severity : "medium", confidence: "medium",
    path: result.path || "package-lock.json", cwe: a.cwe || "",
    evidence: `OSV matched the declared npm version ${result.name}@${result.version} to ${a.id}. ${a.aliases?.join(", ") || ""}\n${a.url}${a.severity ? `\nAdvisory severity: ${a.severity}.` : "\nAdvisory severity unavailable; Medium is a provisional triage value."}`,
    preconditions: "A package/version advisory match is not proof of exploitability. Verify the resolved production inventory, affected feature, runtime reachability and advisory range.",
    impact: a.summary || "Read the advisory to evaluate impact in this application.",
    remediation: a.fixed?.length ? `Check the advisory's affected ranges and supported upgrade paths. Listed fixed versions (may belong to different branches): ${a.fixed.join(", ")}. ${a.url}` : `Review the advisory for a fixed version or mitigation. Do not assume a patch is available. ${a.url}`,
    verification: "Update the lockfile, run application checks in an owned environment, and repeat the inventory audit. Confirm the resolved affected version is no longer deployed.",
  })));
}
