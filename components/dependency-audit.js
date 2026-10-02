"use client";
import { useRef, useState } from "react";
import { MAX_PACKAGES, parseNpmInventory, advisoryFindings } from "@/lib/dependency-audit";

function save(text, filename, type = "application/json") {
  const url = URL.createObjectURL(new Blob([text], { type })); const link = document.createElement("a"); link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
}
export default function DependencyAudit({ onCapture }) {
  const fileRef = useRef(null);
  const [source, setSource] = useState("");
  const [inventory, setInventory] = useState(null);
  const [includeDev, setIncludeDev] = useState(false);
  const [target, setTarget] = useState("");
  const [checked, setChecked] = useState(null);
  const [selected, setSelected] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  async function load(event) {
    const file = event.target.files?.[0]; event.target.value = ""; if (!file) return;
    try {
      if (file.size > 4_000_000) throw new Error("Use an npm file smaller than 4 MB.");
      const text = await file.text(); const data = parseNpmInventory(text, includeDev); setSource(text); setInventory(data); setTarget(data.name); setSelected(data.packages.slice(0, MAX_PACKAGES).map(p => `${p.name}@${p.version}`)); setChecked(null); setError(""); setNotice("Inventory parsed in your browser. Choose versions, then explicitly query the advisory service.");
    } catch (err) { setError(err.message); }
  }
  function changeDev(value) {
    setIncludeDev(value); setChecked(null);
    if (source) { try { const data = parseNpmInventory(source, value); setInventory(data); setSelected(data.packages.slice(0, MAX_PACKAGES).map(p => `${p.name}@${p.version}`)); } catch (err) { setError(err.message); } }
  }
  async function query() {
    if (!target.trim()) return setError("Name the target project before checking versions.");
    setBusy(true); setError(""); setChecked(null);
    try {
      const packages = inventory.packages.filter(p => selected.includes(`${p.name}@${p.version}`));
      const res = await fetch("/api/dependencies/audit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ packages }), cache: "no-store" });
      const data = await res.json(); if (!res.ok) throw new Error(data.error || "Advisory lookup failed.");
      setChecked({ ...data, target: target.trim(), format: inventory.format, includeDev, available: inventory.packages.length, skipped: inventory.skipped });
      setNotice("Lookup finished. Failed lookups and unmatched versions both need coverage review.");
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  function capture() {
    try {
      const all = advisoryFindings(checked.results);
      const failures = checked.results.filter(r => r.error).length;
      const capped = checked.results.filter(r => r.truncated).length;
      onCapture({ title: `${checked.target} · dependency exposure`, target: checked.target, kind: "dependency-advisories", paths: checked.results.map(r => `${r.name}@${r.version}`), findings: all.slice(0, 250), scope: `OSV.dev lookup at ${checked.checkedAt}. ${checked.results.length}/${checked.available} eligible unique npm package versions selected from ${checked.format}. Development packages ${checked.includeDev ? "included" : "excluded"}; ${checked.skipped} unresolved/range/non-registry entries omitted. ${failures} lookup failures; ${capped} package advisory lists truncated at 25. ${all.length > 250 ? `Only the first 250 of ${all.length} advisory matches captured; export raw lookup results and split the inventory for complete triage.` : `${all.length} advisory matches captured.`} Advisory matches do not establish runtime exploitability; no source, data flow or deployment was analyzed. Source lockfile is not saved in the case.` }); setNotice("Advisory findings captured. Review reachability and fixed-version ranges before assigning fixes.");
    } catch (err) { setError(err.message); }
  }
  function sbom() {
    const components = inventory.packages.map(p => {
      const parts = p.name.split("/"); const scoped = p.name.startsWith("@");
      return { type: "library", "bom-ref": `${p.name}@${p.version}`, ...(scoped ? { group: parts[0] } : {}), name: scoped ? parts[1] : p.name, version: p.version, purl: `pkg:npm/${parts.map(encodeURIComponent).join("/")}@${encodeURIComponent(p.version)}`, properties: [{ name: "cyberouter:development", value: String(p.dev) }] };
    });
    const result = { bomFormat: "CycloneDX", specVersion: "1.6", serialNumber: `urn:uuid:${crypto.randomUUID()}`, version: 1, metadata: { timestamp: new Date().toISOString(), component: { type: "application", name: target || inventory.name } }, components };
    save(JSON.stringify(result, null, 2), "cyberouter-inventory.cdx.json"); setNotice("SBOM exported for every eligible parsed version, with your development-package setting. Ranges and unresolved entries are omitted; this is not a deployed runtime inventory.");
  }
  const matches = checked?.results.reduce((n, r) => n + r.advisories.length, 0) || 0;
  return <section className="panel casebook-section"><span className="section-caption">RESOLVED VERSIONS → LIVE ADVISORIES → REMEDIATION</span><h2>Dependency exposure</h2><p>Read an npm lockfile locally, check exact package versions against OSV.dev, then capture advisory matches as findings. No model key required. Package names and versions go through this app to the fixed OSV API only when you run the lookup.</p><div className="casebook-actions"><button type="button" className={inventory ? "ghost" : "primary"} disabled={busy} onClick={() => fileRef.current.click()}>Choose npm file</button><input type="file" hidden ref={fileRef} accept=".json,application/json" onChange={load} /><label className="check-row"><input type="checkbox" checked={includeDev} disabled={busy} onChange={e => changeDev(e.target.checked)} /><span>Include development packages</span></label></div><p>Supports package-lock.json / npm-shrinkwrap v1–v3 and exact package.json versions. Semver ranges, git/file dependencies and unresolved entries are omitted.</p>{notice && <div className="casebook-notice" role="status">{notice}</div>}{error && <div className="error-box" role="alert">{error}</div>}
    {inventory && <><label className="field"><span>Target project</span><input value={target} maxLength={300} disabled={busy} onChange={e => setTarget(e.target.value)} /></label><div className="casebook-metrics"><div><strong>{inventory.packages.length}</strong><span>Unique eligible versions</span></div><div><strong>{selected.length}</strong><span>Selected / {MAX_PACKAGES} maximum</span></div><div><strong>{inventory.skipped}</strong><span>Unresolved entries omitted</span></div><div><strong>{matches}</strong><span>Advisory matches</span></div></div><details className="casebook-details" open><summary>Choose inventory coverage · {inventory.format}</summary><p>Each name/version pair is checked once. A nested version may be present even when another version of the same package is patched.</p><div className="dependency-inventory">{inventory.packages.map(p => { const key = `${p.name}@${p.version}`; return <label key={key} className="scope-file"><input type="checkbox" disabled={busy || (!selected.includes(key) && selected.length >= MAX_PACKAGES)} checked={selected.includes(key)} onChange={e => { setChecked(null); setSelected(prev => e.target.checked ? [...prev, key] : prev.filter(x => x !== key)); }} /><span className="scope-file-name">{key}</span><small>{p.dev ? "development" : "runtime / unspecified"}</small></label>; })}</div></details><div className="casebook-actions"><button type="button" className="primary" disabled={busy || !selected.length} onClick={query}>{busy ? `Looking up ${selected.length} versions…` : "Check selected versions"}</button><button type="button" className="ghost" disabled={!inventory.packages.length || busy} onClick={sbom}>Export CycloneDX SBOM</button></div></>}
    {checked && <div className="dependency-results"><h3>Lookup results · {new Date(checked.checkedAt).toLocaleString()}</h3><p>{checked.results.filter(r => r.error).length} failed lookups · {checked.results.filter(r => r.truncated).length} lists capped. Zero matches means no advisories were returned for the checked versions; it does not prove the application is secure.</p><div className="casebook-actions"><button type="button" className="primary" onClick={capture}>Capture advisory findings{matches > 250 ? " (first 250)" : ""}</button><button type="button" className="ghost" onClick={() => save(JSON.stringify(checked, null, 2), "cyberouter-advisory-lookups.json")}>Export lookup results</button></div>{checked.results.map(r => <details key={`${r.name}@${r.version}`} className="casebook-details" open={Boolean(r.error)}><summary><strong>{r.name}@{r.version}</strong> · {r.error ? "Lookup failed" : `${r.advisories.length} advisory matches`}{r.truncated ? " · capped" : ""}</summary>{r.error && <p className="warning">{r.error}</p>}{r.advisories.map(a => <p key={a.id}><a href={a.url} target="_blank" rel="noreferrer">{a.id} ↗</a> · {a.summary}<br /><span>{a.severity ? `${a.severity} advisory severity` : "Severity not supplied; requires triage"}{a.fixed.length ? ` · listed fixed versions: ${a.fixed.join(", ")}` : " · fixed version not supplied"}</span></p>)}</details>)}</div>}
  </section>;
}
