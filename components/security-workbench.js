"use client";

import { importSarif, MAX_SCANNER_BYTES } from "@/lib/scanner-import";
import DependencyAudit from "@/components/dependency-audit";
import { useEffect, useMemo, useRef, useState } from "react";
import { CASEBOOK_VERSION, SEVERITIES, STATUSES, CONFIDENCES, MAX_CASES, MAX_FINDINGS, MAX_IMPORT_BYTES, createCase, normalizeFinding, normalizeThreat, uid, parseCasebook, casebookJSON, findingKey, compareCases, releaseReview, recordEvent, generateThreats, markdownHandoff, sarifExport, scanLocalRules, RULE_CATALOG } from "@/lib/security-casebook";
import { redactSensitiveText } from "@/lib/sensitive-content";

const STORAGE = "cyberouter_casebook_v1";
const STATUS_LABEL = { open: "Open", investigating: "Investigating", resolved: "Resolved", accepted: "Risk accepted", "false-positive": "False positive" };
const safeText = (value) => redactSensitiveText(value).text;
const stamp = (value) => new Date(value).toLocaleString();
function download(text, name, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a"); link.href = url; link.download = name; document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
}
function Field({ label, value, onChange, multiline = false, ...props }) {
  return <label className="field"><span>{label}</span>{multiline ? <textarea rows={3} value={value || ""} onChange={e => onChange(e.target.value)} {...props} /> : <input value={value || ""} onChange={e => onChange(e.target.value)} {...props} />}</label>;
}
function Select({ label, value, onChange, options }) {
  return <label className="field"><span>{label}</span><select value={value} onChange={e => onChange(e.target.value)}>{options.map(o => <option key={typeof o === "string" ? o : o[0]} value={typeof o === "string" ? o : o[0]}>{typeof o === "string" ? o : o[1]}</option>)}</select></label>;
}

export default function SecurityWorkbench({ visible, incoming, onNavigate }) {
  const [cases, setCases] = useState([]);
  const [activeId, setActiveId] = useState("");
  const [persist, setPersist] = useState(false);
  const [ready, setReady] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [view, setView] = useState("findings");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("active");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [selected, setSelected] = useState("");
  const [draft, setDraft] = useState(null);
  const [baselineId, setBaselineId] = useState("");
  const [undo, setUndo] = useState(null);
  const [newCase, setNewCase] = useState(false);
  const [title, setTitle] = useState("");
  const [target, setTarget] = useState("");
  const [localPath, setLocalPath] = useState("snippet.js");
  const [localCode, setLocalCode] = useState("");
  const importRef = useRef(null);
  const scannerRef = useRef(null);
  const [scannerTarget, setScannerTarget] = useState("");
  const [scannerImportOpen, setScannerImportOpen] = useState(false);
  const incomingRef = useRef(null);
  const [issueCopied, setIssueCopied] = useState(false);
  const [editorError, setEditorError] = useState("");

  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE);
      if (saved) { const loaded = parseCasebook(saved); setCases(loaded); setActiveId(loaded[0]?.id || ""); setPersist(true); }
    } catch { setError("Saved casebook could not be read. Export current work before replacing saved data. Browser storage may be unavailable or damaged."); }
    setReady(true);
  }, []);
  useEffect(() => {
    if (!ready || !incoming || incomingRef.current === incoming.id) return;
    if (cases.length >= MAX_CASES) { setError(`The casebook holds ${MAX_CASES} cases. Export and remove an older case; the pending assessment will open automatically.`); return; }
    incomingRef.current = incoming.id;
    setCases(items => [incoming, ...items]);
    if (!dirty) { setActiveId(incoming.id); setView("findings"); setDraft(null); setSelected(""); }
    setMessage(dirty ? "Assessment captured in the list. Your unsaved finding edits remain open." : "Assessment captured. Review the evidence before assigning or closing findings.");
  }, [incoming, ready, cases.length]);
  useEffect(() => {
    if (!ready || !persist) return;
    try { const data = casebookJSON(cases); if (new TextEncoder().encode(data).length > MAX_IMPORT_BYTES) throw new Error(); localStorage.setItem(STORAGE, data); }
    catch { setError("Saving to this device failed or exceeded 4 MB. Your current work is still in memory. Export a JSON backup now."); }
  }, [cases, persist, ready]);

  const item = cases.find(c => c.id === activeId);
  const baseline = cases.find(c => c.id === baselineId && c.id !== activeId);
  const comparison = item && baseline ? compareCases(item, baseline) : null;
  const review = item ? releaseReview(item) : null;
  const filtered = useMemo(() => (item?.findings || []).filter(f => {
    const status = statusFilter === "all" || (statusFilter === "active" ? ["open", "investigating"].includes(f.status) : f.status === statusFilter);
    return status && (severityFilter === "all" || severityFilter === f.severity) && `${f.title} ${f.path} ${f.owner} ${f.cwe}`.toLowerCase().includes(query.toLowerCase());
  }).sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.title.localeCompare(b.title)), [item, query, statusFilter, severityFilter]);
  const metrics = item ? { active: item.findings.filter(f => ["open", "investigating"].includes(f.status)).length, overdue: item.findings.filter(f => ["open", "investigating"].includes(f.status) && f.due && f.due < new Date().toISOString().slice(0, 10)).length, assigned: item.findings.filter(f => f.owner.trim()).length, resolved: item.findings.filter(f => f.status === "resolved").length } : null;

  function updateCase(patch, event) {
    setCases(items => items.map(c => c.id === activeId ? { ...c, ...patch, ...(event ? { events: recordEvent(c, event) } : {}) } : c));
  }
  function discardAllowed() { return !dirty || window.confirm("Discard unsaved finding edits? Saved evidence remains in the casebook."); }
  function switchCase(id) { if (!discardAllowed()) return; setActiveId(id); setDraft(null); setSelected(""); setBaselineId(""); setError(""); setEditorError(""); }
  function addCase(input) {
    if (cases.length >= MAX_CASES) throw new Error(`Export and remove a case first. Maximum ${MAX_CASES}.`);
    const c = createCase(input); setCases(items => [c, ...items]); switchCase(c.id); setView("findings"); setNewCase(false); setTitle(""); setTarget(""); setMessage("Case created. Add evidence or run local checks.");
  }
  function editFinding(f) { if (!discardAllowed()) return; setSelected(f.id); setDraft({ ...f }); setEditorError(""); setIssueCopied(false); }
  function startFinding() { if (!discardAllowed()) return; setSelected(""); setDraft(normalizeFinding({ title: "New finding", source: "manual", severity: "medium", confidence: "low" })); setEditorError(""); }
  function saveFinding(e) {
    e.preventDefault();
    try {
      const clean = normalizeFinding({ ...draft, updatedAt: new Date().toISOString() }, { imported: true });
      const exists = item.findings.some(f => f.id === clean.id);
      if (!exists && item.findings.length >= MAX_FINDINGS) throw new Error(`This case holds ${MAX_FINDINGS} findings. Create a second case.`);
      updateCase({ findings: exists ? item.findings.map(f => f.id === clean.id ? clean : f) : [...item.findings, clean] }, `${exists ? "Updated" : "Added"} ${clean.title}: ${STATUS_LABEL[clean.status]}${clean.owner ? `; reviewer/owner ${clean.owner}` : ""}`);
      setDraft(clean); setSelected(clean.id); setEditorError(""); setMessage("Finding saved. Evidence and disposition are included in exports.");
    } catch (err) { setEditorError(err.message); }
  }
  function removeCase() {
    if (!discardAllowed()) return;
    setUndo(item); setCases(items => items.filter(c => c.id !== activeId)); setActiveId(cases.find(c => c.id !== activeId)?.id || ""); setDraft(null); setMessage("Case removed. Use Undo to restore it during this session.");
  }
  async function importFile(e) {
    const file = e.target.files?.[0]; e.target.value = "";
    if (!file) return;
    try {
      if (file.size > MAX_IMPORT_BYTES) throw new Error("Choose a JSON file smaller than 4 MB.");
      const imported = parseCasebook(await file.text());
      if (cases.length + imported.length > MAX_CASES) throw new Error(`This import exceeds ${MAX_CASES} cases. Export and remove older work first.`);
      // Import as copies: never replace an existing case or trust external IDs as local identity.
      const copies = imported.map(c => ({ ...c, id: uid(), title: `${c.title} (imported)`, events: recordEvent(c, "Imported as a copy; external activity records are unverified.") }));
      setCases(items => [...copies, ...items]); if (copies[0]) { switchCase(copies[0].id); setView("findings"); } setMessage(`Imported ${copies.length} case${copies.length === 1 ? "" : "s"} as copies. Existing cases were preserved.`); setError("");
    } catch (err) { setError(err.message); }
  }
  async function importScanner(event) {
    const file = event.target.files?.[0]; event.target.value = ""; if (!file) return;
    try {
      if (file.size > MAX_SCANNER_BYTES) throw new Error("Scanner report exceeds 8 MB.");
      const output = importSarif(await file.text(), scannerTarget);
      if (cases.length + output.cases.length > MAX_CASES) throw new Error("Not enough casebook capacity. Export and remove older cases before importing this report.");
      setCases(items => [...output.cases, ...items]);
      if (output.cases[0]) { switchCase(output.cases[0].id); setView("findings"); }
      setError(""); setMessage(`Imported ${output.findings} scanner findings into ${output.cases.length} cases. ${output.ignored} pass/informational records omitted. Scanner evidence remains unverified.`);
    } catch (err) { setError(err.message || "Scanner report could not be imported."); }
  }

  function togglePersistence(checked) {
    try { if (!checked) localStorage.removeItem(STORAGE); setPersist(checked); setMessage(checked ? "Device saving enabled. Security evidence is stored unencrypted in this browser; API keys are excluded from the casebook." : "Device copy removed. Current cases remain in memory until refresh; export to keep them."); }
    catch { setError("This browser blocked storage access. Export work to keep it."); }
  }
  function runSnippet(e) {
    e.preventDefault();
    if (!localCode.trim() || !localPath.trim()) return setError("Enter a path and code to check.");
    const output = scanLocalRules([{ path: localPath, content: localCode }]);
    try {
      addCase({ title: `Local checks · ${localPath}`, target: localPath, kind: "local-rules", paths: [localPath], scope: `One pasted excerpt checked with ${RULE_CATALOG.length + 1} heuristic rules. No data flow or dependencies analyzed. ${output.capped ? "Finding limit reached; observations are incomplete." : ""}`, findings: output.findings });
      setLocalCode(""); setError(""); setView("findings"); setMessage(`${output.findings.length} observations captured. ${output.capped ? "The finding cap was reached. " : ""}No match does not establish security. Pasted source was discarded.`);
    } catch (err) { setError(err.message); }
  }
  function generate() {
    try { if (item.threats.length) throw new Error("This case already has a threat worksheet. Edit it or create a new case for a fresh architecture."); updateCase({ threats: generateThreats(item.architecture) }, "Generated STRIDE questions from declared boundaries; all are unreviewed hypotheses."); setMessage("Threat worksheet created. Assess each question and record evidence; ratings begin as estimates."); setError(""); }
    catch (err) { setError(err.message); }
  }
  function promote(t) {
    if (item.findings.length >= MAX_FINDINGS) return setError("Finding limit reached. Create a second case.");
    const f = normalizeFinding({ ruleId: `THREAT-${t.category}`, title: `${t.category} at ${t.boundary}`, source: "threat-model", path: t.boundary, severity: t.impact === 3 ? "high" : "medium", confidence: "low", evidence: t.notes, preconditions: t.question, impact: `Estimated likelihood ${t.likelihood}/3 and impact ${t.impact}/3. Validate assumptions.`, remediation: t.mitigation, verification: t.verification });
    if (item.findings.some(prior => findingKey(prior) === findingKey(f))) return setError("This threat already has a finding in the case.");
    updateCase({ findings: [...item.findings, f] }, `Promoted threat hypothesis: ${f.title}`); setView("findings"); editFinding(f); setStatusFilter("active");
  }
  async function copyIssue() {
    try { const issue = markdownHandoff({ ...item, findings: [normalizeFinding(draft, { imported: true })], threats: [], events: [] }); await navigator.clipboard.writeText(issue); setIssueCopied(true); }
    catch (err) { setEditorError(err.message || "Clipboard unavailable. Download the Markdown handoff instead."); }
  }
  const filename = (item?.title || "casebook").replace(/[^a-z0-9_-]/gi, "-").slice(0, 70);
  const dirty = Boolean(draft && (selected ? JSON.stringify(item?.findings.find(f => f.id === selected)) !== JSON.stringify(draft) : true));

  return <section className="casebook" hidden={!visible} aria-label="Security casebook">
    <div className="casebook-top panel">
      <div><span className="section-caption">EVIDENCE → ACTION → VERIFICATION</span><h2>Security casebook</h2><p>Turn observations into reviewed decisions and track the fixes. Local tools work without a model connection.</p></div>
      <div className="casebook-actions"><button type="button" className="primary" onClick={() => setNewCase(v => !v)}>New case</button><button type="button" className="ghost" onClick={() => importRef.current.click()}>Import JSON</button><button type="button" className="ghost" onClick={() => setScannerImportOpen(v => !v)}>Import scanner SARIF</button><button type="button" className="ghost" disabled={!cases.length} onClick={() => download(casebookJSON(cases), "cyberouter-casebook.json", "application/json")}>Export casebook</button><input ref={importRef} className="sr-only" type="file" accept=".json,application/json" aria-label="Import casebook JSON" onChange={importFile} /></div>
    </div>
    {scannerImportOpen && <section className="panel casebook-section scanner-import"><h3>Bring external scanner evidence into the queue</h3><p>Import SARIF 2.1.0 exports from Semgrep, CodeQL, Trivy and other compatible tools. Parsing stays in this browser. Findings start open with Low confidence; pass records are omitted and suppression metadata requires fresh review. Reports up to 8 MB are split into cases of 250 findings without dropping actionable results.</p><Field label="Target repository / system" value={scannerTarget} onChange={setScannerTarget} maxLength={300} placeholder="team/service" /><button type="button" className="primary" disabled={!scannerTarget.trim()} onClick={() => scannerRef.current.click()}>Choose SARIF report</button><input type="file" hidden ref={scannerRef} accept=".sarif,.json,application/json" onChange={importScanner} /></section>}
    <div className="casebook-storage"><label className="check-row"><input type="checkbox" checked={persist} onChange={e => togglePersistence(e.target.checked)} /><span>Save cases on this device<small>{persist ? "Unencrypted browser storage · 30 cases / 4 MB · export a backup" : "Memory only · refreshing removes cases · export to keep your work"}</small></span></label><span className="casebook-version">Casebook v{CASEBOOK_VERSION} · {cases.length}/{MAX_CASES} cases</span></div>
    {message && <div className="casebook-notice" role="status"><span>{message}</span><button type="button" className="text-button" onClick={() => setMessage("")}>Dismiss</button></div>}
    {error && <div className="error-box" role="alert">{error}<button type="button" className="text-button" onClick={() => setError("")}>Dismiss</button></div>}
    {undo && <div className="casebook-notice"><span>Removed: {undo.title}</span><button type="button" className="ghost" disabled={cases.length >= MAX_CASES} onClick={() => { setCases(items => [undo, ...items]); switchCase(undo.id); setUndo(null); setMessage("Case restored."); }}>Undo removal</button></div>}
    {newCase && <form className="panel casebook-create" onSubmit={e => { e.preventDefault(); try { addCase({ title, target, scope: "Manual case. Document the scope, exclusions and evidence before release review." }); setError(""); } catch (err) { setError(err.message); } }}><h3>Create an assessment</h3><div className="casebook-form-grid"><Field label="Case title" value={title} onChange={setTitle} required maxLength={300} placeholder="Checkout service · pre-release review" /><Field label="Target / system" value={target} onChange={setTarget} required maxLength={1000} placeholder="team/service or system name" /></div><button type="submit" className="primary">Create case</button><button type="button" className="ghost" onClick={() => setNewCase(false)}>Cancel</button></form>}
    <div className="casebook-layout">
      <aside className="panel casebook-sidebar"><h3>Assessments</h3>{cases.length ? <div className="case-list">{cases.map(c => <button type="button" key={c.id} className={c.id === activeId ? "case-row active" : "case-row"} aria-current={c.id === activeId ? "true" : undefined} onClick={() => switchCase(c.id)}><strong>{c.title}</strong><span>{c.target || "Target not recorded"}</span><small>{c.findings.length} findings · {stamp(c.createdAt)}</small></button>)}</div> : <div className="casebook-empty"><p>No assessments yet.</p><span>Create a case, import an export, or capture a scan report.</span><button type="button" className="text-button" onClick={() => onNavigate("repositories")}>Open repository scans ↗</button></div>}<button type="button" className={view === "dependencies" ? "ghost active" : "ghost"} onClick={() => setView("dependencies")}>Dependency exposure</button><button type="button" className={view === "checks" ? "ghost active" : "ghost"} onClick={() => setView("checks")}>Local code checks</button></aside>
      <div className="casebook-main">
        {view === "dependencies" ? <DependencyAudit onCapture={addCase} /> : view === "checks" ? <section className="panel casebook-section"><span className="section-caption">BROWSER ONLY · NO MODEL REQUIRED</span><h2>Check source patterns locally</h2><p>Identify review points before sending source to a model. Nine rules cover credentials, execution, rendering, TLS, deserialization, hashing, CORS and debug configuration. Matches are hypotheses that need input tracing.</p><form onSubmit={runSnippet}><Field label="File path" value={localPath} onChange={setLocalPath} required maxLength={1000} /><Field label="Code excerpt (maximum 90,000 characters)" value={localCode} onChange={setLocalCode} multiline required maxLength={90000} spellCheck={false} placeholder="Paste authorized code. Source stays in browser memory; only redacted observations enter the case." /><button className="primary" type="submit">Run local checks</button></form><details className="casebook-details"><summary>Rules and limitations</summary><p>Line patterns cannot analyze data flow, dependency versions or runtime reachability. Comments and fixtures can produce false positives. Empty results are not a clean bill of health.</p>{RULE_CATALOG.map(r => <p key={r.id}><strong>{r.id}</strong> · {r.title} · {r.cwe}</p>)}</details>{item && <button type="button" className="ghost" onClick={() => setView("findings")}>Return to selected case</button>}</section> : item ? <>
          <section className="panel casebook-section casebook-case-head"><div><span className="section-caption">{item.kind.toUpperCase()} · {stamp(item.createdAt)}</span><h2>{item.title}</h2><p>{item.target}{item.ref ? ` · ${item.ref}` : ""}</p>{item.commit && <code className="casebook-commit">Pinned commit: {item.commit}</code>}</div><div className="casebook-actions"><button type="button" className="ghost" onClick={() => download(markdownHandoff(item), `${filename}.md`, "text/markdown")}>Handoff .md</button><button type="button" className="ghost" onClick={() => download(JSON.stringify(sarifExport(item), null, 2), `${filename}.sarif`, "application/json")}>SARIF 2.1</button><button type="button" className="text-button" onClick={removeCase}>Remove case</button></div></section>
          <div className="casebook-metrics" aria-label="Selected assessment summary"><div><strong>{metrics.active}</strong><span>Unresolved</span></div><div><strong>{metrics.overdue}</strong><span>Overdue · UTC</span></div><div><strong>{metrics.assigned}</strong><span>Assigned / reviewed</span></div><div><strong>{metrics.resolved}</strong><span>Retested and resolved</span></div></div>
          <nav className="casebook-subnav" aria-label="Assessment views">{[["findings", "Findings"], ["compare", "Compare runs"], ["release", "Release review"], ["threats", "Threat model"], ["evidence", "Scope & activity"]].map(([id, label]) => <button key={id} type="button" aria-current={view === id ? "page" : undefined} className={view === id ? "active" : ""} onClick={() => setView(id)}>{label}</button>)}</nav>
          {view === "findings" && <section className="panel casebook-section"><div className="casebook-section-head"><div><h3>Finding queue</h3><p>Prioritize by severity. Confidence describes the evidence, separately.</p></div><button type="button" className="primary" onClick={startFinding}>Add finding</button></div><div className="casebook-filters"><Field label="Search title, path, owner or CWE" value={query} onChange={setQuery} type="search" /><Select label="Status" value={statusFilter} onChange={setStatusFilter} options={[["active", "Unresolved"], ["all", "All statuses"], ...STATUSES.map(s => [s, STATUS_LABEL[s]])]} /><Select label="Severity" value={severityFilter} onChange={setSeverityFilter} options={[["all", "All severities"], ...SEVERITIES]} /></div>
            <div className="finding-workspace"><div className="finding-list">{filtered.length ? filtered.map(f => <button type="button" key={f.id} aria-pressed={selected === f.id} className={`finding-row ${selected === f.id ? "active" : ""}`} onClick={() => editFinding(f)}><div><span className={`risk-chip ${f.severity}`}>{f.severity}</span><span className="casebook-muted">{STATUS_LABEL[f.status]}</span></div><strong>{f.title}</strong><span className="finding-path">{f.path || "Location missing"}{f.line ? `:${f.line}` : ""}</span><small>{f.confidence} confidence · {f.owner || "Unassigned"}{f.due ? ` · due ${f.due}` : ""}</small></button>) : <div className="casebook-empty"><p>{item.findings.length ? "No findings match these filters." : "No findings captured."}</p><span>{item.findings.length ? "Change the search or status to see other findings." : "Add evidence manually or capture a report. An empty queue does not prove the target is secure."}</span>{item.findings.length > 0 && <button type="button" className="ghost" onClick={() => { setQuery(""); setStatusFilter("all"); setSeverityFilter("all"); }}>Clear filters</button>}</div>}</div>
            {draft ? <form className="finding-editor" onSubmit={saveFinding}><div className="casebook-section-head"><h3>{selected ? "Review finding" : "New finding"}</h3><span className="casebook-muted">{dirty ? "Unsaved changes" : "Saved"}</span></div><Field label="Title" value={draft.title} onChange={v => setDraft({ ...draft, title: v })} required maxLength={300} /><div className="casebook-form-grid"><Select label="Severity" value={draft.severity} onChange={v => setDraft({ ...draft, severity: v })} options={SEVERITIES} /><Select label="Confidence" value={draft.confidence} onChange={v => setDraft({ ...draft, confidence: v })} options={CONFIDENCES} /></div><div className="casebook-form-grid"><Field label="File path / URL" value={draft.path} onChange={v => setDraft({ ...draft, path: v })} maxLength={1000} /><Field label="Line (optional)" type="number" min="1" max="9999999" value={draft.line || ""} onChange={v => setDraft({ ...draft, line: v ? Number(v) : null })} /></div><Field label="Evidence · redact credentials before adding" value={draft.evidence} onChange={v => setDraft({ ...draft, evidence: v })} multiline maxLength={6000} /><Field label="Attack preconditions / false-positive checks" value={draft.preconditions} onChange={v => setDraft({ ...draft, preconditions: v })} multiline maxLength={6000} /><Field label="Impact" value={draft.impact} onChange={v => setDraft({ ...draft, impact: v })} multiline maxLength={6000} /><Field label="Smallest safe remediation" value={draft.remediation} onChange={v => setDraft({ ...draft, remediation: v })} multiline maxLength={6000} /><Field label="Verification plan" value={draft.verification} onChange={v => setDraft({ ...draft, verification: v })} multiline maxLength={6000} /><details className="casebook-details"><summary>Classification and origin</summary><Field label="CWE (optional, e.g. CWE-79)" value={draft.cwe} onChange={v => setDraft({ ...draft, cwe: v })} pattern="CWE-[0-9]{1,5}" /><p>Source: {draft.source} · Rule: {draft.ruleId}. Imported provenance is unverified.</p></details><div className="casebook-form-grid"><Field label="Owner / reviewer" value={draft.owner} onChange={v => setDraft({ ...draft, owner: v })} maxLength={200} /><Field label="Due date (UTC)" type="date" value={draft.due} onChange={v => setDraft({ ...draft, due: v })} /></div><Select label="Disposition" value={draft.status} onChange={v => setDraft({ ...draft, status: v })} options={STATUSES.map(s => [s, STATUS_LABEL[s]])} /><Field label="Decision rationale (required for acceptance / false positive)" value={draft.disposition} onChange={v => setDraft({ ...draft, disposition: v })} multiline maxLength={6000} /><Field label="Retest evidence (required to resolve)" value={draft.retest} onChange={v => setDraft({ ...draft, retest: v })} multiline maxLength={6000} /><p className="casebook-muted">Closing a finding requires a reviewer and supporting evidence. Device data and activity records remain editable.</p>{editorError && <div role="alert" className="error-box">{editorError}</div>}<div className="casebook-actions"><button type="submit" className="primary">Save finding</button><button type="button" className="ghost" onClick={copyIssue}>{issueCopied ? "Issue copied" : "Copy issue handoff"}</button><button type="button" className="ghost" onClick={() => { if (discardAllowed()) { setDraft(null); setSelected(""); } }}>Close editor</button></div></form> : <div className="casebook-empty finding-placeholder"><span className="section-caption">EVIDENCE FIRST</span><h3>Open a finding to review it.</h3><p>Check the evidence and preconditions, assign the fix, then record the retest.</p><ol><li>Validate the observation.</li><li>Assign an owner and due date.</li><li>Save the decision with evidence.</li></ol></div>}</div></section>}
          {view === "compare" && <section className="panel casebook-section"><h3>Compare against an earlier run</h3><p>Identity matches rule, path and title; line shifts do not create new findings. Model title changes can still create a new identity. Missing observations are never automatically resolved.</p><Select label="Baseline assessment" value={baselineId} onChange={setBaselineId} options={[["", "Choose a baseline"], ...cases.filter(c => c.id !== item.id).map(c => [c.id, `${c.title} · ${stamp(c.createdAt)}`])]} />{comparison ? <><div className="casebook-notice"><strong>{comparison.comparable ? "Targets, check type and observed paths match." : "Scope differs or is unspecified. Treat this comparison as informational."}</strong><span>Comparability uses target, assessment kind and path list. Configuration and evidence completeness still require human review.</span></div><div className="casebook-metrics"><div><strong>{comparison.added.length}</strong><span>Newly observed</span></div><div><strong>{comparison.existing.length}</strong><span>Observed again</span></div><div><strong>{comparison.changed.length}</strong><span>Severity / confidence changed</span></div><div><strong>{comparison.absent.length}</strong><span>Not observed this run</span></div></div>{[["Newly observed", comparison.added], ["Severity / confidence changed", comparison.changed], ["Not observed · verify before closure", comparison.absent]].map(([label, list]) => <div key={label} className="comparison-group"><h4>{label}</h4>{list.length ? list.map(f => <p key={f.id}><span className={`risk-chip ${f.severity}`}>{f.severity}</span> {f.title}<small>{f.path}{f.line ? `:${f.line}` : ""}</small></p>) : <p className="casebook-muted">None in this comparison.</p>}</div>)}</> : <div className="casebook-empty"><p>Select another assessment to compare.</p><span>Run checks again after a fix and capture both assessments.</span></div>}</section>}
          {view === "release" && <section className="panel casebook-section"><span className="section-caption">EXPLICIT DECISIONS · HUMAN REVIEW</span><h3>Release review</h3><div className={`release-verdict ${review.blockers.length ? "blocked" : review.verdict === "Review required" ? "pending" : ""}`} role="status"><strong>{review.verdict}</strong><span>{review.blockers.length} unresolved policy blockers · {review.missingEvidence.length} unresolved findings without evidence</span></div><p>This checks the selected case against your severity threshold. It does not verify deployment, coverage, accepted risk or compliance.</p><Select label="Block unresolved findings at or above" value={item.policy} onChange={v => updateCase({ policy: v }, `Changed release threshold to ${v}.`)} options={SEVERITIES} /><Field label="Scope reviewer" value={item.reviewer} onChange={v => updateCase({ reviewer: safeText(v) })} maxLength={200} /><Field label="Scope review · coverage gaps, exclusions and release conditions" value={item.reviewNote} onChange={v => updateCase({ reviewNote: safeText(v) })} multiline maxLength={12000} placeholder="Record what was actually checked, what remains untested, and who accepted the limits." /><h4>Unresolved blockers</h4>{review.blockers.length ? review.blockers.map(f => <button type="button" key={f.id} className="release-finding" onClick={() => { setView("findings"); setStatusFilter("active"); editFinding(f); }}><span className={`risk-chip ${f.severity}`}>{f.severity}</span><strong>{f.title}</strong><span>{f.owner || "Unassigned"} ↗</span></button>) : <p className="casebook-muted">No unresolved findings reach the selected threshold.</p>}<h4>Accepted risks</h4>{item.findings.filter(f => f.status === "accepted").map(f => <p key={f.id}><strong>{f.title}</strong> · {f.owner}<br />{f.disposition}</p>)}{!item.findings.some(f => f.status === "accepted") && <p className="casebook-muted">No accepted risks recorded.</p>}<button type="button" className="ghost" onClick={() => { if (!item.reviewer.trim() || !item.reviewNote.trim()) return setError("Add a scope reviewer and scope review before recording a decision."); updateCase({}, `Release review recorded by ${item.reviewer || "unspecified reviewer"}: ${review.verdict}; ${review.blockers.length} blockers; threshold ${item.policy}.`); setMessage("Release review recorded in local activity. Export the handoff to share it."); }}>Record review snapshot</button></section>}
          {view === "threats" && <section className="panel casebook-section"><span className="section-caption">ARCHITECTURE → TRUST BOUNDARIES → STRIDE</span><h3>Threat model worksheet</h3><p>Declare the system and trust boundaries, then investigate six threat categories per boundary. These are design questions, not discovered vulnerabilities. Ratings are ordinal estimates, not CVSS.</p><div className="casebook-form-grid">{[["system", "System / purpose"], ["assets", "Sensitive assets and data"], ["actors", "Actors and privilege levels"], ["boundaries", "Trust boundaries · one per line, up to 8"]].map(([key, label]) => <Field key={key} label={label} value={item.architecture[key]} onChange={v => updateCase({ architecture: { ...item.architecture, [key]: safeText(v) } })} multiline maxLength={3000} placeholder={key === "boundaries" ? "Browser → API\nAPI → payments provider" : ""} />)}</div><button type="button" className="primary" disabled={item.threats.length > 0} onClick={generate}>{item.threats.length ? "Worksheet generated" : "Generate review worksheet"}</button>{item.threats.length > 0 && <p className="casebook-muted">{item.threats.filter(t => t.status === "unreviewed").length}/{item.threats.length} questions unreviewed. Existing questions retain the boundaries used when generated; edit them if the architecture changes.</p>}<div className="threat-list">{item.threats.map(t => <details key={t.id} className="casebook-details threat-card"><summary><strong>{t.category}</strong><span>{t.boundary} · {t.status} · estimate {t.likelihood * t.impact}/9</span></summary><p>{t.question}</p><Field label="Boundary" value={t.boundary} onChange={v => updateCase({ threats: item.threats.map(x => x.id === t.id ? normalizeThreat({ ...t, boundary: v }) : x) })} maxLength={400} /><div className="casebook-form-grid"><Select label="Likelihood estimate" value={String(t.likelihood)} onChange={v => updateCase({ threats: item.threats.map(x => x.id === t.id ? { ...t, likelihood: Number(v) } : x) })} options={[["1", "1 · Low"], ["2", "2 · Medium"], ["3", "3 · High"]]} /><Select label="Impact estimate" value={String(t.impact)} onChange={v => updateCase({ threats: item.threats.map(x => x.id === t.id ? { ...t, impact: Number(v) } : x) })} options={[["1", "1 · Low"], ["2", "2 · Medium"], ["3", "3 · High"]]} /></div>{[["mitigation", "Mitigation / control"], ["verification", "Verification plan"], ["notes", "Review evidence / rationale"]].map(([key, label]) => <Field key={key} label={label} value={t[key]} onChange={v => updateCase({ threats: item.threats.map(x => x.id === t.id ? normalizeThreat({ ...t, [key]: v }) : x) })} multiline maxLength={3000} />)}<Select label="Review state" value={t.status} onChange={v => { if (v !== "unreviewed" && !t.notes.trim()) return setError("Record evidence or a rationale before completing a threat review."); updateCase({ threats: item.threats.map(x => x.id === t.id ? { ...t, status: v } : x) }, `Threat review: ${t.category} at ${t.boundary} → ${v}.`); }} options={[["unreviewed", "Unreviewed"], ["needs-action", "Needs action"], ["mitigated", "Mitigated"], ["not-applicable", "Not applicable"]]} /><button type="button" className="ghost" onClick={() => promote(t)}>Create finding from hypothesis</button></details>)}</div></section>}
          {view === "evidence" && <section className="panel casebook-section"><h3>Assessment scope</h3><Field label="Scope, omissions and data handling" value={item.scope} onChange={v => updateCase({ scope: safeText(v) })} multiline maxLength={12000} /><p>{item.paths.length} observed paths · Model: {item.model || "None"}</p><details className="casebook-details"><summary>Observed paths</summary><ul>{item.paths.map(path => <li key={path}><code>{path}</code></li>)}</ul></details>{item.report && <details className="casebook-details"><summary>Captured report · redacted common patterns</summary><pre className="casebook-source">{item.report}</pre></details>}<h3>Local activity</h3><p>Records case decisions in this browser. Imports, device edits and exports can change these records; this is not an immutable compliance audit trail.</p>{item.events.length ? <ol className="casebook-activity">{[...item.events].reverse().map((e, i) => <li key={`${e.at}-${i}`}><time dateTime={e.at}>{stamp(e.at)}</time><span>{e.text}</span></li>)}</ol> : <p className="casebook-muted">No decisions recorded yet.</p>}</section>}
        </> : <section className="panel casebook-section casebook-empty"><span className="section-caption">MAKE THE NEXT REVIEW REPEATABLE</span><h2>Start with a real assessment.</h2><p>Capture a report to organize findings, or create a manual case for an architecture review.</p><div className="casebook-actions"><button type="button" className="primary" onClick={() => setNewCase(true)}>Create your first case</button><button type="button" className="ghost" onClick={() => setView("checks")}>Check a code excerpt</button></div><div className="casebook-flow"><div><strong>01 · Collect</strong><span>Repository, web observations or manual evidence</span></div><div><strong>02 · Decide</strong><span>Confidence, owner, due date and rationale</span></div><div><strong>03 · Verify</strong><span>Retest evidence, baseline and release review</span></div></div></section>}
      </div>
    </div>
  </section>;
}
