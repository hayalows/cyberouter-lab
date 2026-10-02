import { redactSensitiveText, detectSensitiveSignals } from "./sensitive-content";

export const CASEBOOK_VERSION = 1;
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const STATUSES = ["open", "investigating", "resolved", "accepted", "false-positive"];
export const CONFIDENCES = ["high", "medium", "low"];
export const MAX_CASES = 30;
export const MAX_FINDINGS = 250;
export const MAX_IMPORT_BYTES = 4_000_000;
export const uid = () => globalThis.crypto.randomUUID();
const safe = (value, max = 6000) => redactSensitiveText(typeof value === "string" ? value.slice(0, max) : "").text;
const choice = (value, list, fallback) => list.includes(String(value).toLowerCase()) ? String(value).toLowerCase() : fallback;
const date = (value) => /^\d{4}-\d{2}-\d{2}$/.test(value || "") && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value ? value : "";
const validId = (value) => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
const iso = (value) => typeof value === "string" && !Number.isNaN(Date.parse(value)) ? new Date(value).toISOString() : new Date().toISOString();

export function normalizeFinding(input = {}, { imported = false } = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input) || !String(input.title || "").trim()) throw new Error("Each finding needs a title.");
  if (imported && (!STATUSES.includes(input.status) || !SEVERITIES.includes(input.severity) || !CONFIDENCES.includes(input.confidence))) throw new Error("A finding has an unsupported status, severity or confidence.");
  if (imported && !validId(input.id)) throw new Error("A finding has an invalid ID. Use an unmodified casebook export.");
  const status = imported ? input.status : "open";
  const finding = {
    id: imported && typeof input.id === "string" ? safe(input.id, 100) : uid(),
    ruleId: safe(input.ruleId, 150) || "manual-review",
    title: safe(input.title, 300), severity: choice(input.severity, SEVERITIES, "medium"),
    confidence: choice(input.confidence, CONFIDENCES, "low"),
    source: choice(input.source, ["local-rule", "web-check", "model", "manual", "threat-model", "advisory"], "manual"),
    path: safe(input.path, 1000), line: Number.isInteger(input.line) && input.line > 0 && input.line < 10_000_000 ? input.line : null,
    cwe: /^CWE-\d{1,5}$/.test(input.cwe || "") ? input.cwe : "",
    evidence: safe(input.evidence), preconditions: safe(input.preconditions), impact: safe(input.impact),
    remediation: safe(input.remediation), verification: safe(input.verification), status,
    owner: imported ? safe(input.owner, 200) : "", due: imported ? date(input.due) : "",
    disposition: imported ? safe(input.disposition) : "", retest: imported ? safe(input.retest) : "",
    updatedAt: iso(input.updatedAt),
  };
  if (status === "resolved" && (!finding.retest.trim() || !finding.owner.trim())) throw new Error("Resolved findings need a reviewer and retest evidence.");
  if (["accepted", "false-positive"].includes(status) && (!finding.disposition.trim() || !finding.owner.trim())) throw new Error("Accepted or false-positive findings need a reviewer and rationale.");
  return finding;
}

export function createCase(input = {}) {
  if (!Array.isArray(input.findings || [] ) || (input.findings || []).length > MAX_FINDINGS) throw new Error(`Use at most ${MAX_FINDINGS} findings per case. Split larger assessments.`);
  return {
    id: uid(), title: safe(input.title, 300) || "Untitled assessment", target: safe(input.target, 1000),
    kind: safe(input.kind, 100) || "manual", ref: safe(input.ref, 200), commit: safe(input.commit, 100),
    createdAt: new Date().toISOString(), model: safe(input.model, 200), report: safe(input.report, 120_000),
    scope: safe(input.scope, 12000), paths: [...new Set((input.paths || []).filter(p => typeof p === "string").map(p => safe(p, 1000)))].sort().slice(0, 1000),
    findings: (input.findings || []).map(f => normalizeFinding(f)),
    reviewNote: "", reviewer: "", policy: "high", events: [], architecture: { system: "", assets: "", actors: "", boundaries: "" }, threats: [],
  };
}

export function parseModelFindings(text) {
  const value = String(text || "").trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  let payload;
  try { payload = JSON.parse(value); } catch { throw new Error("The model did not return valid finding JSON. Your report is preserved. Retry or add findings manually."); }
  if (!payload || !Array.isArray(payload.findings) || payload.findings.length > MAX_FINDINGS) throw new Error("The model returned an unsupported finding list. Retry with a smaller report.");
  return payload.findings.map(f => {
    if (!f || !SEVERITIES.includes(f.severity) || !CONFIDENCES.includes(f.confidence)) throw new Error("The model returned an invalid severity or confidence. Retry extraction or add findings manually.");
    return normalizeFinding({ ...f, source: "model" });
  });
}

// Match identity uses the full canonical key; it does not rely on a short hash or line numbers.
export function findingKey(f) { return [f.ruleId, f.path, f.title.toLowerCase().replace(/\s+/g, " ").trim()].join("\u001f"); }
function fingerprint(value) { let h = 2166136261; for (const c of value) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return (h >>> 0).toString(16).padStart(8, "0"); }
export function compareCases(current, baseline) {
  const remaining = new Map();
  for (const finding of baseline.findings) {
    const key = findingKey(finding);
    remaining.set(key, [...(remaining.get(key) || []), finding]);
  }
  const added = [], existing = [], changed = [];
  for (const finding of current.findings) {
    const matches = remaining.get(findingKey(finding));
    const prior = matches?.shift();
    if (!prior) added.push(finding);
    else {
      existing.push(finding);
      if (finding.severity !== prior.severity || finding.confidence !== prior.confidence) changed.push(finding);
    }
  }
  const comparable = Boolean(current.target && current.target === baseline.target && current.kind === baseline.kind && current.paths.length && JSON.stringify(current.paths) === JSON.stringify(baseline.paths));
  return { comparable, added, existing, changed, absent: [...remaining.values()].flat() };
}
export function releaseReview(item) {
  const threshold = SEVERITIES.indexOf(item.policy);
  const blockers = item.findings.filter(f => ["open", "investigating"].includes(f.status) && SEVERITIES.indexOf(f.severity) <= threshold);
  const missingEvidence = item.findings.filter(f => ["open", "investigating"].includes(f.status) && !f.evidence.trim());
  const reviewed = Boolean(item.reviewNote.trim() && item.reviewer.trim() && item.target.trim());
  return { blockers, missingEvidence, verdict: blockers.length ? "Policy blockers" : !reviewed || missingEvidence.length ? "Review required" : "No policy blockers" };
}

export function parseCasebook(text) {
  if (new TextEncoder().encode(text).length > MAX_IMPORT_BYTES) throw new Error("Import is too large. Use a casebook smaller than 4 MB.");
  let data;
  try { data = JSON.parse(text); } catch { throw new Error("This file is not valid JSON. Import a Cyberouter casebook export."); }
  if (data?.schema !== "cyberouter-casebook" || data.version !== CASEBOOK_VERSION || !Array.isArray(data.cases) || data.cases.length > MAX_CASES) throw new Error(`Use a version 1 Cyberouter casebook with at most ${MAX_CASES} cases.`);
  const ids = new Set();
  return data.cases.map(input => {
    if (!input || !Array.isArray(input.findings) || !Array.isArray(input.paths) || input.paths.length > 1000 || input.paths.some(p => typeof p !== "string")) throw new Error("Each case needs a finding list and an observed-path list.");
    if (!Array.isArray(input.threats) || input.threats.length > 48 || !Array.isArray(input.events) || input.events.length > 200) throw new Error("Threat or activity records exceed the supported casebook limits.");
    const item = createCase(input);
    if (!validId(input.id) || ids.has(input.id)) throw new Error("Case IDs must be present and unique.");
    ids.add(input.id); item.id = safe(input.id, 100); item.createdAt = iso(input.createdAt);
    item.findings = input.findings.map(f => normalizeFinding(f, { imported: true }));
    if (new Set(item.findings.map(f => f.id)).size !== item.findings.length) throw new Error("Finding IDs must be unique within a case.");
    item.reviewNote = safe(input.reviewNote, 12000); item.reviewer = safe(input.reviewer, 200); item.policy = choice(input.policy, SEVERITIES, "high");
    for (const key of Object.keys(item.architecture)) item.architecture[key] = safe(input.architecture?.[key], 3000);
    item.threats = input.threats.map(t => { if (!t || !validId(t.id)) throw new Error("A threat has an invalid ID."); return normalizeThreat(t); });
    if (new Set(item.threats.map(t => t.id)).size !== item.threats.length) throw new Error("Threat IDs must be unique within a case.");
    item.events = (Array.isArray(input.events) ? input.events : []).slice(-200).map(e => ({ at: iso(e.at), text: safe(e.text, 1000) }));
    return item;
  });
}
export function casebookJSON(cases) { return JSON.stringify({ schema: "cyberouter-casebook", version: CASEBOOK_VERSION, exportedAt: new Date().toISOString(), cases }, null, 2); }
export function recordEvent(item, text) { return [...item.events, { at: new Date().toISOString(), text: safe(text, 1000) }].slice(-200); }

const RULES = [
  { id: "CODE-EVAL", title: "Dynamic code execution requires review", severity: "high", cwe: "CWE-95", pattern: /\b(?:eval|exec)\s*\(/, remediation: "Remove dynamic evaluation or strictly constrain input and execution privileges.", verification: "Trace every argument to its origin; prove untrusted values cannot reach execution." },
  { id: "CODE-HTML", title: "Raw HTML rendering requires a trust check", severity: "medium", cwe: "CWE-79", pattern: /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=/, remediation: "Use text rendering or a maintained HTML sanitizer with a narrow allowlist.", verification: "Trace input origins and sanitizer configuration; verify unsafe markup is rejected." },
  { id: "CODE-TLS", title: "TLS certificate verification is disabled", severity: "high", cwe: "CWE-295", pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|verify\s*=\s*False/, remediation: "Restore certificate verification and configure a trusted CA for private certificates.", verification: "Confirm invalid and untrusted certificates fail in the deployed environment." },
  { id: "CODE-YAML", title: "Potentially unsafe YAML deserialization", severity: "high", cwe: "CWE-502", pattern: /\byaml\.(?:load|unsafe_load)\s*\(/, remediation: "Use safe_load or a restricted safe loader; do not deserialize untrusted objects.", verification: "Inspect the loader argument and input origin. yaml.load with a SafeLoader may be safe." },
  { id: "CODE-SHELL", title: "Shell execution needs input tracing", severity: "high", cwe: "CWE-78", pattern: /shell\s*(?::|=)\s*(?:true|True)|\bos\.system\s*\(|\bchild_process\.exec\s*\(/, remediation: "Use an argument array with shell disabled; validate inputs and constrain privileges.", verification: "Verify user-controlled input cannot change command structure or executable." },
  { id: "CODE-HASH", title: "Weak hash needs a security-use check", severity: "medium", cwe: "CWE-328", pattern: /createHash\s*\(\s*["'](?:md5|sha1)["']|hashlib\.(?:md5|sha1)\s*\(/, remediation: "Use an appropriate modern hash for integrity and a password hashing function for passwords.", verification: "Determine whether this is security-sensitive; cache keys and non-security checksums may be acceptable." },
  { id: "CODE-CORS", title: "Wildcard origin needs a data exposure check", severity: "medium", cwe: "CWE-942", pattern: /["']Access-Control-Allow-Origin["']\s*[:,]\s*["']\*["']/, remediation: "Restrict origins for sensitive endpoints; document intentionally public resources.", verification: "Check authentication, response sensitivity and browser behavior. A public anonymous API may be intentional." },
  { id: "CODE-DEBUG", title: "Debug configuration needs environment review", severity: "medium", cwe: "CWE-489", pattern: /\bDEBUG\s*=\s*True|\bdebug\s*(?::|=)\s*(?:true|True)/, remediation: "Disable debug behavior in production and verify deployment configuration.", verification: "Determine which runtime consumes this setting and whether production overrides it." },
];
export const RULE_CATALOG = RULES.map(({ pattern, ...rule }) => rule);

export function scanLocalRules(files) {
  const findings = [];
  let capped = false;
  const add = (item) => { if (findings.length >= MAX_FINDINGS) { capped = true; return; } findings.push(normalizeFinding(item)); };
  for (const file of files) {
    if (!file.content) continue;
    for (const hit of detectSensitiveSignals(file.content)) add({ ruleId: "CODE-SECRET", title: "Possible embedded credential", path: file.path, line: hit.line, severity: "high", confidence: "low", source: "local-rule", cwe: "CWE-798", evidence: `${hit.kind} at line ${hit.line}. Matched value withheld.`, preconditions: "Check whether the value is a live credential, a placeholder, or public test data.", remediation: "If live, revoke or rotate the credential, remove it from source and history, and use a secret manager.", verification: "Confirm revocation and inspect repository history. Do not paste the matched credential into this case." });
    file.content.split(/\r?\n/).forEach((line, index) => {
      if (/^\s*(?:\/\/|#|\*|<!--)/.test(line)) return;
      for (const rule of RULES) if (rule.pattern.test(line)) add({ ruleId: rule.id, title: rule.title, severity: rule.severity, confidence: "low", source: "local-rule", path: file.path, line: index + 1, cwe: rule.cwe, evidence: safe(line.trim(), 1500), preconditions: "Pattern observation only. Confirm reachability, input trust and runtime configuration before claiming a vulnerability.", remediation: rule.remediation, verification: rule.verification });
    });
  }
  return { findings, capped };
}

export const STRIDE = [
  ["Spoofing", "Can an untrusted actor impersonate a user or service?", "Verify identities at every entry point; bind sessions to authenticated principals.", "Try access with a missing, expired or wrong-audience identity."],
  ["Tampering", "Can input or a message be modified across this boundary?", "Validate schemas and authorization on the receiving side; authenticate sensitive messages.", "Verify modified identifiers and unsigned events are rejected."],
  ["Repudiation", "Can a sensitive action occur without reliable attribution?", "Record actor, action and outcome without logging secrets; protect access to logs.", "Check that sensitive actions create attributable records and unauthorized actors cannot alter them."],
  ["Information disclosure", "Can private data cross into a less trusted context?", "Minimize responses, enforce object-level access and encrypt transport and sensitive storage.", "Verify one actor cannot read another actor's data or secret-bearing logs."],
  ["Denial of service", "Can an actor exhaust a limited resource?", "Bound requests, timeouts, concurrency, uploads and costly work; apply rate limits.", "Check documented limits with safe bounded requests in an owned test environment."],
  ["Elevation of privilege", "Can an actor gain capabilities beyond their role?", "Enforce least privilege and authorization at each operation; separate privileged identities.", "Verify low-privilege actors cannot perform administrator operations."],
];
export function normalizeThreat(t) {
  return { id: safe(t.id, 100) || uid(), category: safe(t.category, 100), boundary: safe(t.boundary, 400), question: safe(t.question, 2000), mitigation: safe(t.mitigation, 3000), verification: safe(t.verification, 3000), likelihood: [1, 2, 3].includes(Number(t.likelihood)) ? Number(t.likelihood) : 1, impact: [1, 2, 3].includes(Number(t.impact)) ? Number(t.impact) : 2, status: choice(t.status, ["unreviewed", "mitigated", "needs-action", "not-applicable"], "unreviewed"), notes: safe(t.notes, 3000) };
}
export function generateThreats(architecture) {
  const boundaries = architecture.boundaries.split(/\r?\n/).map(s => s.trim()).filter(Boolean).slice(0, 8);
  if (!architecture.system.trim() || !architecture.assets.trim() || !boundaries.length) throw new Error("Describe the system, assets and at least one trust boundary first.");
  return boundaries.flatMap(boundary => STRIDE.map(([category, question, mitigation, verification]) => normalizeThreat({ id: uid(), category, boundary, question, mitigation, verification })));
}

function md(value) { return String(value || "").replace(/[\r\n]+/g, " ").replace(/([\\`*_{}\[\]<>|])/g, "\\$1"); }
export function markdownHandoff(item) {
  const gate = releaseReview(item);
  return `# ${md(item.title)}\n\nTarget: ${md(item.target)}\nRef: ${md(item.ref)}\nCommit: ${md(item.commit || "Not pinned")}\nCreated: ${item.createdAt}\n\n## Scope\n\n${item.scope}\n\nReviewer: ${md(item.reviewer || "Not recorded")}\nScope review: ${item.reviewNote || "Not reviewed"}\n\n## Release review\n\n${gate.verdict}; threshold: ${item.policy}. ${gate.blockers.length} unresolved blockers. This is a local policy decision, not a security certification.\n\n## Findings (${item.findings.length})\n\n` + item.findings.map((f, i) => `### ${i + 1}. ${md(f.title)}\n\nSeverity: ${f.severity} · Confidence: ${f.confidence} · Status: ${f.status} · Source: ${f.source}\nLocation: ${md(f.path || "Unspecified")}${f.line ? `:${f.line}` : ""}\n${f.cwe ? `${f.cwe}\n` : ""}Owner: ${md(f.owner || "Unassigned")} · Due: ${f.due || "Unset"}\n\nEvidence:\n${f.evidence || "Missing"}\n\nPreconditions:\n${f.preconditions || "Not recorded"}\n\nImpact:\n${f.impact || "Not recorded"}\n\nRemediation:\n${f.remediation || "Not recorded"}\n\nVerification plan:\n${f.verification || "Not recorded"}\n\nDisposition:\n${f.disposition || "None"}\n\nRetest evidence:\n${f.retest || "None"}\n`).join("\n") + `\n## Architecture\n\n${Object.entries(item.architecture).map(([k, v]) => `**${k}**: ${md(v)}`).join("\n\n")}\n\n## Threat review\n\n${item.threats.map(t => `- ${md(t.category)} / ${md(t.boundary)}: ${t.status}; likelihood ${t.likelihood}/3 × impact ${t.impact}/3. ${md(t.notes)} Mitigation: ${md(t.mitigation)} Verification: ${md(t.verification)}`).join("\n")}\n\n## Local activity\n\n${item.events.map(e => `- ${e.at}: ${md(e.text)}`).join("\n")}\n\nLocal activity is editable browser data, not an immutable audit log. Review all content for secrets before sharing.\n`;
}

export function sarifExport(item) {
  const rules = [...new Map(item.findings.map(f => [f.ruleId, { id: f.ruleId, shortDescription: { text: f.title }, ...(f.cwe ? { properties: { tags: [f.cwe] } } : {}) }])).values()];
  const locations = (f) => {
    // Only relative repository paths and HTTP(S) URLs are emitted as locations.
    const path = f.path;
    if (!path || /^(?:\/|[A-Za-z]:)|(?:^|\/)\.\.(?:\/|$)/.test(path)) return [];
    if (/^[a-z][\w+.-]*:/i.test(path) && !/^https?:\/\//i.test(path)) return [];
    const uri = /^https?:\/\//i.test(path) ? path : path.split("/").map(encodeURIComponent).join("/");
    return [{ physicalLocation: { artifactLocation: { uri }, ...(f.line ? { region: { startLine: f.line } } : {}) } }];
  };
  return { $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs: [{ tool: { driver: { name: "Cyberouter Lab", informationUri: "https://cyberouter-lab.vercel.app", version: "2.0.0", rules } }, automationDetails: { id: `case/${item.id}/` }, results: item.findings.map(f => ({ ruleId: f.ruleId, ...(f.status === "resolved" ? { kind: "pass" } : {}), level: f.status === "resolved" ? "none" : ["critical", "high"].includes(f.severity) ? "error" : f.severity === "medium" ? "warning" : "note", message: { text: `${f.title}\n${f.evidence}\nRemediation: ${f.remediation}` }, locations: locations(f), partialFingerprints: { "cyberouter/v1": fingerprint(findingKey(f)) }, ...( ["accepted", "false-positive"].includes(f.status) ? { suppressions: [{ kind: "external", justification: f.disposition, status: "accepted" }] } : {}), properties: { severity: f.severity, confidence: f.confidence, status: f.status, source: f.source, owner: f.owner, retest: f.retest } })) }] };
}
