import { redactSensitiveText } from "./sensitive-content";

export const DEEP_VERSION = 1;
export const DEEP_FILE_BYTES = 1_000_000;
export const DEEP_CHUNK_CHARS = 24_000;
export const MAX_MANIFEST = 20_000;
export const MAX_CHECKPOINT_BYTES = 32_000_000;
const TEXT_EXT = /\.(?:[cm]?[jt]sx?|py|go|rs|java|kt|kts|php|rb|cs|[ch]|cc|cpp|hpp|swift|sql|graphql|gql|sh|bash|ps1|ya?ml|toml|json|xml|html?|css|scss|sass|less|md|mdx|txt|csv|proto|tf|hcl|vue|svelte|dart|ex|exs|erl|hrl|clj|cljs|scala|pl|r|lock|ini|cfg|conf|properties)$/i;
export function exclusionReason(entry) {
  if (entry.type === "tree") return "directory";
  if (entry.type !== "blob") return "Submodule or unsupported Git object; audit its repository separately";
  if (entry.mode === "120000") return "Symbolic link; target is not read";
  if (entry.size > DEEP_FILE_BYTES) return "Exceeds the 1 MB per-file hosted limit";
  const base = entry.path.split("/").at(-1).toLowerCase();
  if (/^\.env(?:\..*)?$/.test(base) && !/example|sample|template/.test(base)) return "Credential configuration; excluded from hosted model review";
  if (/^(?:\.npmrc|\.netrc|id_rsa|id_ed25519)$/.test(base) || /\.(?:pem|key|p12|pfx)$/i.test(base)) return "Credential or key material; excluded from hosted model review";
  if (TEXT_EXT.test(base) || /^(?:dockerfile|makefile|jenkinsfile|gemfile|procfile|cmakelists\.txt|\.gitignore|\.dockerignore|\.env\.example)$/.test(base)) return "";
  return "Binary or unsupported text format";
}
export function buildManifest(entries) {
  const files = [], exclusions = [];
  for (const e of entries) {
    const reason = exclusionReason(e);
    if (reason === "directory") continue;
    const record = { path: e.path, sha: e.sha, size: e.size || 0, mode: e.mode || "100644", type: e.type || "blob" };
    if (reason) exclusions.push({ ...record, reason }); else files.push(record);
  }
  files.sort((a, b) => a.path.localeCompare(b.path)); exclusions.sort((a, b) => a.path.localeCompare(b.path));
  return { files, exclusions };
}
export function nextChunk(text, offset = 0) {
  if (!Number.isInteger(offset) || offset < 0 || offset > text.length) throw new Error("Chunk offset is outside this file.");
  let end = Math.min(text.length, offset + DEEP_CHUNK_CHARS);
  let cursor = offset;
  for (let lines = 0; lines < 400; lines++) {
    const newline = text.indexOf("\n", cursor);
    if (newline < 0 || newline >= end) break;
    cursor = newline + 1;
    if (lines === 399) end = cursor;
  }
  if (end < text.length) { const newline = text.lastIndexOf("\n", end - 1); if (newline >= offset) end = newline + 1; }
  // Very long lines are split without dropping any characters.
  const content = text.slice(offset, end);
  const startLine = text.slice(0, offset).split("\n").length;
  const endLine = text.slice(0, Math.max(offset, end - (content.endsWith("\n") ? 1 : 0))).split("\n").length;
  return { content, offset, nextOffset: end, totalChars: text.length, startLine, endLine, done: end === text.length, splitLine: (offset > 0 && text[offset - 1] !== "\n") || (end < text.length && text[end - 1] !== "\n") };
}
export function sourceFacts(content, path) {
  const imports = [];
  const pattern = /(?:\b(?:import|export)\s+(?:[^;\n]*?\sfrom\s*)?["']([^"']+)["']|\b(?:require|import)\s*\(\s*["']([^"']+)["']\s*\))/g;
  const matches = [...content.matchAll(pattern)];
  for (const match of matches.slice(0, 200)) imports.push({ specifier: (match[1] || match[2]).slice(0, 500), line: content.slice(0, match.index).split("\n").length });
  const routes = content.split(/\r?\n/).flatMap((line, i) => /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)|\b(?:app|router)\.(?:get|post|put|delete|patch)\s*\(/.test(line) ? [{ line: i + 1, observation: "HTTP handler declaration", path }] : []).slice(0, 100);
  return { imports, routes, capped: matches.length > 200, lines: content ? content.split("\n").length - Number(content.endsWith("\n")) : 0 };
}
export function importGraph(files) {
  const paths = new Set(files.map(f => f.path)); const edges = [], unresolved = [];
  for (const file of files) for (const item of file.facts?.imports || []) {
    if (!item.specifier.startsWith(".")) continue;
    const segments = file.path.split("/").slice(0, -1);
    for (const segment of item.specifier.split("/")) { if (segment === "..") segments.pop(); else if (segment && segment !== ".") segments.push(segment); }
    const base = segments.join("/");
    const resolved = [base, ...[".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", "/index.js", "/index.ts", "/index.tsx"].map(ext => base + ext)].find(p => paths.has(p));
    const reference = { from: file.path, to: resolved || item.specifier, line: item.line };
    if (resolved) edges.push(reference); else unresolved.push(reference);
  }
  return { edges, unresolved };
}
export function newAudit(repo, model, manifest) {
  return { schema: "cyberouter-deep-audit", version: DEEP_VERSION, id: crypto.randomUUID(), createdAt: new Date().toISOString(), repository: { owner: repo.owner, name: repo.name, fullName: repo.fullName, ref: repo.ref, commitSha: repo.commitSha, treeSha: repo.treeSha }, model, phase: manifest.incomplete ? "discover" : "review", manifestComplete: !manifest.incomplete, directories: manifest.incomplete ? [{ sha: repo.treeSha, prefix: "" }] : [], discovered: manifest.incomplete ? [] : [...manifest.files, ...manifest.exclusions], files: manifest.incomplete ? [] : manifest.files.map(f => ({ ...f, offset: 0, totalChars: null, lines: 0, state: "pending", chunks: [], facts: null, error: "", redactions: 0 })), exclusions: manifest.incomplete ? [] : manifest.exclusions, localFindings: [], localCapped: false, synthesis: null, summary: "", assessment: "", status: "ready", completedAt: null };
}
export function coverage(job) {
  const completed = job.files.filter(f => f.state === "reviewed");
  return { files: job.files.length, completed: completed.length, chunks: job.files.reduce((n, f) => n + f.chunks.length, 0), lines: job.files.reduce((n, f) => n + (f.chunks.at(-1)?.endLine || 0), 0), totalKnownLines: job.files.reduce((n, f) => n + (f.lines || 0), 0), failed: job.files.filter(f => f.error).length, excluded: job.exclusions.length, full: job.manifestComplete && completed.length === job.files.length && !job.files.some(f => f.error) };
}
const clean = (text, limit) => redactSensitiveText(typeof text === "string" ? text : "").text.slice(0, limit);
export function parseCheckpoint(text) {
  if (new TextEncoder().encode(text).length > MAX_CHECKPOINT_BYTES) throw new Error("Checkpoint exceeds 32 MB.");
  let j; try { j = JSON.parse(text); } catch { throw new Error("Checkpoint is not valid JSON."); }
  if (j?.schema !== "cyberouter-deep-audit" || j.version !== DEEP_VERSION || !Array.isArray(j.files) || !Array.isArray(j.exclusions) || j.files.length + j.exclusions.length > MAX_MANIFEST || !/^[a-f0-9]{40}$/.test(j.repository?.commitSha || "") || !/^[a-f0-9]{40}$/.test(j.repository?.treeSha || "")) throw new Error("Use a version 1 Cyberouter deep-audit checkpoint with a pinned commit and valid manifest.");
  if (!/^[A-Za-z0-9_.-]+$/.test(j.repository.owner || "") || !/^[A-Za-z0-9_.-]+$/.test(j.repository.name || "")) throw new Error("Checkpoint repository is invalid.");
  const seen = new Set();
  const files = j.files.map(f => {
    if (!f || typeof f.path !== "string" || !f.path || f.path.length > 1000 || seen.has(f.path) || !Number.isInteger(f.offset) || f.offset < 0 || !Array.isArray(f.chunks) || f.chunks.length > 10000) throw new Error("Checkpoint contains an invalid file ledger.");
    seen.add(f.path);
    let offset = 0; const chunks = f.chunks.map(c => { if (c.offset !== offset || !Number.isInteger(c.nextOffset) || c.nextOffset <= c.offset || !Number.isInteger(c.startLine) || !Number.isInteger(c.endLine) || c.startLine < 1 || c.endLine < c.startLine) throw new Error("Checkpoint coverage has a gap or invalid range."); offset = c.nextOffset; return { offset: c.offset, nextOffset: c.nextOffset, startLine: c.startLine, endLine: c.endLine, splitLine: Boolean(c.splitLine), note: clean(c.note, 20000) }; });
    if (offset !== f.offset || (f.totalChars !== null && (!Number.isInteger(f.totalChars) || f.totalChars < offset || f.totalChars > 2_000_000))) throw new Error("Checkpoint coverage totals are inconsistent.");
    return { path: f.path, sha: /^[a-f0-9]{40}$/.test(f.sha || "") ? f.sha : "", size: Number(f.size) || 0, mode: "100644", type: "blob", offset, totalChars: f.totalChars, lines: Number(f.lines) || 0, state: f.state === "reviewed" && f.totalChars === offset ? "reviewed" : f.state === "skipped" ? "skipped" : "pending", chunks, facts: f.facts && typeof f.facts === "object" ? { imports: (Array.isArray(f.facts.imports) ? f.facts.imports : []).slice(0, 200).map(i => ({ specifier: clean(i.specifier, 500), line: Number(i.line) || 1 })), routes: [], capped: Boolean(f.facts.capped), lines: Number(f.lines) || 0 } : null, error: f.state === "skipped" ? "Skipped in imported checkpoint; prior reason: " + clean(f.error, 500) : "", redactions: Number(f.redactions) || 0 };
  });
  // Imported review notes are untrusted; a checkpoint is continuity data, not verified proof of review.
  const exclusions = j.exclusions.map(f => ({ path: clean(f.path, 1000), reason: clean(f.reason, 400) }));
  const manifestComplete = j.manifestComplete === true;
  if (!Array.isArray(j.directories) || j.directories.length > MAX_MANIFEST || !Array.isArray(j.discovered) || j.discovered.length > MAX_MANIFEST) throw new Error("Discovery checkpoint exceeds the manifest limit.");
  const directories = j.directories.map(d => { if (!/^[a-f0-9]{40}$/.test(d.sha || "") || typeof d.prefix !== "string" || d.prefix.length > 1000) throw new Error("Checkpoint has an invalid directory."); return { sha: d.sha, prefix: d.prefix }; });
  const discovered = j.discovered.map(e => { if (!e || typeof e.path !== "string" || e.path.length > 1000 || !/^[a-f0-9]{40}$/.test(e.sha || "")) throw new Error("Checkpoint has an invalid tree entry."); return { path: e.path, sha: e.sha, size: Number(e.size) || 0, type: e.type === "commit" ? "commit" : "blob", mode: String(e.mode || "100644") }; });
  return { ...newAudit(j.repository, clean(j.model, 200), { files: [], exclusions: [], incomplete: !manifestComplete }), createdAt: clean(j.createdAt, 100), context: clean(j.context, 16000), repository: { owner: j.repository.owner, name: j.repository.name, fullName: `${j.repository.owner}/${j.repository.name}`, commitSha: j.repository.commitSha, treeSha: j.repository.treeSha, ref: clean(j.repository.ref, 200) }, model: clean(j.model, 200), files, exclusions, directories, discovered, localFindings: [], synthesis: null, summary: "", assessment: "", phase: manifestComplete ? "review" : "discover", status: "paused", imported: true, manifestComplete };
}
export function checkpointJSON(job) { const text = JSON.stringify(job, null, 2); if (new TextEncoder().encode(text).length > MAX_CHECKPOINT_BYTES) throw new Error("This checkpoint exceeds 32 MB. Download the report and coverage ledger; keep this tab open to continue."); return text; }
export function fullAuditMarkdown(job) {
  const c = coverage(job); const g = importGraph(job.files);
  return `# Deep audit · ${job.repository.fullName}\n\nCommit: ${job.repository.commitSha}\nModel: ${job.model}\n\n## Coverage receipt\n\n${c.completed}/${c.files} supported text files reviewed; ${c.chunks} chunks; ${c.lines} lines sent through review after common credential redaction. ${c.excluded} excluded files; ${c.failed} read/review errors. Manifest ${job.manifestComplete ? "complete" : "incomplete"}.\n\nCoverage records successful requests, not a guarantee that a model understood every line or found every vulnerability. Imported checkpoints contain unverified prior review notes.\n\n## Consolidated assessment\n\n${job.assessment || job.summary || "Not consolidated yet."}\n\n## Relative import references (${g.edges.length})\n\n${g.edges.map(e => `- ${e.from}:${e.line} → ${e.to}`).join("\n")}\n\n## Per-file review notes\n\n` + job.files.map(f => `### ${f.path}\n\nState: ${f.state}; ${f.offset}/${f.totalChars ?? "unknown"} redacted characters; ${f.lines} known lines.${f.error ? ` Error: ${f.error}` : ""}\n\n${f.chunks.map(c => `#### Lines ${c.startLine}–${c.endLine}${c.splitLine ? " (long line split)" : ""}\n\n${c.note}`).join("\n\n")}`).join("\n\n") + `\n\n## Excluded files\n\n${job.exclusions.map(e => `- ${e.path}: ${e.reason}`).join("\n")}\n`;
}
