import { createCase } from "./security-casebook";
export const MAX_SCANNER_BYTES = 8_000_000;
export function importSarif(text, target) {
  if (new TextEncoder().encode(text).length > MAX_SCANNER_BYTES) throw new Error("Scanner report exceeds 8 MB. Split the report into smaller files.");
  let data; try { data = JSON.parse(text); } catch { throw new Error("Scanner report is not valid JSON."); }
  if (data.version !== "2.1.0" || !Array.isArray(data.runs) || data.runs.length > 30) throw new Error("Use a SARIF 2.1.0 report from a supported scanner export.");
  if (!target.trim()) throw new Error("Name the target project before importing scanner evidence.");
  const cases = []; let total = 0, ignored = 0;
  for (const run of data.runs) {
    if (!run || (run.results !== undefined && !Array.isArray(run.results)) || (run.results || []).length > 10000) throw new Error("Each SARIF run needs a bounded result list (at most 10,000 results).");
    const tool = String(run.tool?.driver?.name || "External scanner").slice(0, 150);
    const rules = new Map((run.tool?.driver?.rules || []).map((r, i) => [r.id || String(i), r]));
    const findings = [];
    for (const result of run.results || []) {
      if (!result || ["pass", "notApplicable", "informational"].includes(result.kind)) { ignored++; continue; }
      const rule = rules.get(result.ruleId) || run.tool?.driver?.rules?.[result.ruleIndex];
      const location = result.locations?.[0]?.physicalLocation;
      const artifact = location?.artifactLocation;
      const uri = artifact?.uri || run.artifacts?.[artifact?.index]?.location?.uri || "";
      const score = Number(rule?.properties?.["security-severity"]);
      const severity = Number.isFinite(score) && score > 0 && score <= 10 ? score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low" : result.level === "error" ? "high" : result.level === "note" || result.level === "none" ? "info" : "medium";
      const message = result.message?.text || result.message?.markdown || rule?.shortDescription?.text;
      if (typeof message !== "string" || !message.trim()) throw new Error("A SARIF result has no readable message. No report was imported.");
      findings.push({ ruleId: `${tool}:${result.ruleId || rule?.id || "unspecified-rule"}`, title: rule?.shortDescription?.text || message.split("\n")[0], severity, confidence: "low", source: "external-scanner", path: String(uri), line: location?.region?.startLine || null, evidence: `${tool} reported:\n${message}\n${location?.region?.snippet?.text ? `Scanner excerpt:\n${location.region.snippet.text}` : ""}`, preconditions: `Imported scanner output is unverified evidence. Check the source location, scanner configuration, reachable input and false-positive conditions.${result.suppressions?.length ? " The source report contains suppression metadata; no risk-acceptance decision was automatically imported." : ""}`, remediation: rule?.help?.text || "Review the scanner rule and choose the smallest safe fix after verifying applicability.", verification: "Re-run the original scanner at a pinned revision after remediation; record runtime or source evidence before resolution." });
    }
    total += findings.length;
    for (let offset = 0; offset < findings.length; offset += 250) {
      const part = findings.slice(offset, offset + 250);
      cases.push(createCase({ title: `${tool} · imported findings${findings.length > 250 ? ` · part ${Math.floor(offset / 250) + 1}` : ""}`, target, kind: "external-sarif", paths: [...new Set(part.map(f => f.path).filter(Boolean))], scope: `External SARIF 2.1.0 evidence from ${tool}. ${part.length} results in this case out of ${findings.length} actionable results in this run. Scanner source, configuration, revision and completeness are unverified. Only the first location per result is mapped; original reports may contain additional traces. All findings start open with Low confidence; external suppressions do not become local risk decisions.`, findings: part }));
      if (cases.length > 30) throw new Error("This report needs more than 30 cases. Split the report before import.");
    }
  }
  return { cases, findings: total, ignored };
}
