"use client";

import { useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const MODES = {
  ask: {
    label: "Ask",
    title: "Ask a Cyberouter model",
    helper: "Secure coding questions, architecture checks, and focused model exploration.",
    placeholder: "Ask a security or secure-software question…",
  },
  review: {
    label: "Review code",
    title: "Review code or a diff",
    helper: "Find concrete issues and separate evidence from hypotheses.",
    placeholder: "Paste code, a diff, or a focused file here…",
  },
  triage: {
    label: "Triage finding",
    title: "Pressure-test a suspected finding",
    helper: "Check whether another scanner or model's finding is actually supported.",
    placeholder: "Describe the suspected vulnerability or finding…",
  },
};

function modelId(item) {
  if (typeof item === "string") return item;
  return item?.id || item?.name || item?.model || "";
}

function extractModels(payload) {
  const raw = Array.isArray(payload) ? payload : payload?.data || payload?.models || [];
  return raw.map(modelId).filter(Boolean);
}

function extractText(payload) {
  return payload?.choices?.[0]?.message?.content || payload?.output_text || payload?.response || "";
}

function reportSeverityCounts(markdown = "") {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const match of markdown.matchAll(/Severity:\s*\*{0,2}(Critical|High|Medium|Low)/gi)) {
    counts[match[1].toLowerCase()] += 1;
  }
  return counts;
}

function StrongLabel({ children }) {
  const text = Array.isArray(children) ? children.join("") : String(children ?? "");
  const lower = text.toLowerCase();
  let className = "";
  if (lower.includes("severity: critical")) className = "severity severity-critical";
  else if (lower.includes("severity: high")) className = "severity severity-high";
  else if (lower.includes("severity: medium")) className = "severity severity-medium";
  else if (lower.includes("severity: low")) className = "severity severity-low";
  else if (lower.includes("confidence:")) className = "confidence-label";
  return <strong className={className}>{children}</strong>;
}

function parseRepoInput(value) {
  const cleaned = String(value || "").trim().replace(/\.git$/i, "")
    .replace(/^https?:\/\/github\.com\//i, "").replace(/^github\.com\//i, "");
  const parts = cleaned.split("/").filter(Boolean);
  if (parts.length < 2) return null;
  return { owner: parts[0], repo: parts[1] };
}

function selectAuditFiles(candidates, limit) {
  const buckets = { runtime: [], auth: [], api: [], data: [], frontend: [], config: [], general: [] };
  const migration = (item) => /\/migrations\//.test(item.path.toLowerCase());

  for (const item of candidates) {
    const path = item.path.toLowerCase();
    if (/supabase\/functions|\/functions\/|worker\/|edge[_-]|src\/lib\/backend|server[_-]?action/.test(path)) buckets.runtime.push(item);
    else if (/auth|login|session|oauth|password|recovery|invite|permission|role/.test(path)) buckets.auth.push(item);
    else if (/\/api\/|route\.(js|ts|tsx)$|server|controller|webhook|rpc/.test(path)) buckets.api.push(item);
    else if (/supabase|migration|database|\/db\/|\.sql$|rls|policy|neon/.test(path)) buckets.data.push(item);
    else if (/components|pages|\/app\/|\/src\/|hooks|ui|view|screen/.test(path)) buckets.frontend.push(item);
    else if (/package\.json|requirements|pyproject|cargo\.toml|go\.mod|vercel|next\.config|docker|\.github\/workflows|\.env/.test(path)) buckets.config.push(item);
    else buckets.general.push(item);
  }

  for (const key of ["runtime", "auth", "api", "frontend", "config", "general"]) {
    buckets[key].sort((a, b) => Number(migration(a)) - Number(migration(b)) || b.score - a.score);
  }

  const quotas = limit <= 18
    ? { runtime: 3, auth: 3, api: 2, data: 4, frontend: 3, config: 2, general: 1 }
    : { runtime: 7, auth: 7, api: 6, data: 12, frontend: 8, config: 5, general: 3 };

  const selected = [];
  const seen = new Set();

  for (const [bucket, quota] of Object.entries(quotas)) {
    for (const item of buckets[bucket].slice(0, quota)) {
      if (!seen.has(item.path)) {
        seen.add(item.path);
        selected.push(item);
      }
    }
  }

  for (const item of candidates) {
    if (selected.length >= limit) break;
    if (!seen.has(item.path)) {
      seen.add(item.path);
      selected.push(item);
    }
  }

  return selected.slice(0, limit);
}

function batchFiles(files, budget = 32000) {
  const groups = [];
  let current = [];
  let chars = 0;
  for (const file of files) {
    if (!file?.content) continue;
    const chunk = `\n\n===== FILE: ${file.path} =====\n${file.content}`;
    if (current.length && chars + chunk.length > budget) {
      groups.push(current);
      current = [];
      chars = 0;
    }
    current.push({ ...file, rendered: chunk });
    chars += chunk.length;
  }
  if (current.length) groups.push(current);
  return groups;
}

function redactSignal(line) {
  return line.replace(/([=:]\s*)[^\s"']{8,}/g, "$1[REDACTED]");
}

function localSecretSignals(files) {
  const patterns = [
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
    /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][^"']{8,}["']/i,
    /gh[pousr]_[A-Za-z0-9_]{20,}/,
    /sk-[A-Za-z0-9_-]{20,}/,
  ];
  const hits = [];
  for (const file of files) {
    if (!file?.content) continue;
    const lines = file.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (patterns.some((pattern) => pattern.test(lines[i]))) {
        hits.push({ path: file.path, line: i + 1, preview: redactSignal(lines[i].trim()).slice(0, 140) });
        if (hits.length >= 20) return hits;
      }
    }
  }
  return hits;
}

export default function Home() {
  const [surface, setSurface] = useState("repositories");
  const [apiKey, setApiKey] = useState("");
  const [remember, setRemember] = useState(false);
  const [connected, setConnected] = useState(false);
  const [models, setModels] = useState([]);
  const [model, setModel] = useState("");
  const [mode, setMode] = useState("review");
  const [prompt, setPrompt] = useState("");
  const [evidence, setEvidence] = useState("");
  const [context, setContext] = useState("");
  const [maxTokens, setMaxTokens] = useState(2048);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("Not connected");
  const [result, setResult] = useState("");
  const [usage, setUsage] = useState(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const [repoInput, setRepoInput] = useState("");
  const [repoRef, setRepoRef] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [repoData, setRepoData] = useState(null);
  const [repoBusy, setRepoBusy] = useState(false);
  const [repoProgress, setRepoProgress] = useState("");
  const [scanKind, setScanKind] = useState("quick");
  const [prNumber, setPrNumber] = useState("");
  const [sessionHistory, setSessionHistory] = useState([]);
  const [resultSource, setResultSource] = useState("none");

  const [siteTarget, setSiteTarget] = useState("");
  const [siteMode, setSiteMode] = useState("passive");
  const [siteToken, setSiteToken] = useState("");
  const [siteAuthorized, setSiteAuthorized] = useState(false);
  const [siteScan, setSiteScan] = useState(null);
  const [siteBusy, setSiteBusy] = useState(false);
  const [siteProgress, setSiteProgress] = useState("");
  const [correlateRepo, setCorrelateRepo] = useState(false);

  useEffect(() => {
    const persistent = localStorage.getItem("cyberouter_key");
    const session = sessionStorage.getItem("cyberouter_key");
    const found = persistent || session || "";
    if (found) {
      setApiKey(found);
      setRemember(Boolean(persistent));
    }
    const gh = sessionStorage.getItem("cyberouter_github_token");
    if (gh) setGithubToken(gh);
  }, []);

  const currentMode = MODES[mode];
  const severityCounts = useMemo(() => reportSeverityCounts(result), [result]);
  const latestScan = sessionHistory[0] || null;

  async function cyberApi(path, init = {}) {
    const response = await fetch(path, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        "x-cyberouter-key": apiKey.trim(),
        ...(init.headers || {}),
      },
      cache: "no-store",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data?.error || `Request failed with HTTP ${response.status}`);
    return data;
  }

  async function githubApi(path, init = {}) {
    const response = await fetch(path, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(githubToken.trim() ? { "x-github-token": githubToken.trim() } : {}),
        ...(init.headers || {}),
      },
      cache: "no-store",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data?.error || `GitHub request failed with HTTP ${response.status}`);
    return data;
  }

  async function connect() {
    if (!apiKey.trim()) return setError("Enter your Cyberouter API key first.");
    setBusy(true);
    setError("");
    setStatus("Checking key…");
    try {
      const data = await cyberApi("/api/cyberouter/models");
      const list = extractModels(data);
      if (!list.length) throw new Error("The key worked, but Cyberouter returned no model IDs.");
      setModels(list);
      setModel((previous) => (list.includes(previous) ? previous : list[0]));
      if (remember) {
        localStorage.setItem("cyberouter_key", apiKey.trim());
        sessionStorage.removeItem("cyberouter_key");
      } else {
        sessionStorage.setItem("cyberouter_key", apiKey.trim());
        localStorage.removeItem("cyberouter_key");
      }
      setConnected(true);
      setStatus(`Connected · ${list.length} model${list.length === 1 ? "" : "s"}`);
    } catch (err) {
      setConnected(false);
      setModels([]);
      setStatus("Connection failed");
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  function disconnect() {
    setConnected(false);
    setModels([]);
    setModel("");
    setStatus("Not connected");
    setResult("");
    setUsage(null);
    sessionStorage.removeItem("cyberouter_key");
    localStorage.removeItem("cyberouter_key");
    setApiKey("");
    setRemember(false);
  }

  const messages = useMemo(() => {
    if (mode === "review") {
      return [
        { role: "system", content: "You are a defensive application-security reviewer. Analyze only authorized code and context supplied. Focus on concrete vulnerabilities, exact evidence, realistic attack preconditions, false-positive checks, impact, confidence, and minimal remediation. Do not invent findings. Clearly separate confirmed issues from hypotheses." },
        { role: "user", content: `${context.trim() ? `Context:\n${context.trim()}\n\n` : ""}Code or diff to review:\n\n${prompt.trim()}` },
      ];
    }
    if (mode === "triage") {
      return [
        { role: "system", content: "You are a defensive security triage analyst. Test the claimed issue against the supplied evidence. Identify assumptions, attack preconditions, disconfirming evidence, confidence, likely impact, and the smallest safe remediation. Do not claim exploitability without evidence." },
        { role: "user", content: `Suspected finding:\n${prompt.trim()}\n\nEvidence:\n${evidence.trim()}` },
      ];
    }
    return [
      { role: "system", content: "You are a cybersecurity and secure-software engineering assistant. Work only with authorized systems and code. Be concrete, evidence-driven, and explicit about uncertainty." },
      { role: "user", content: prompt.trim() },
    ];
  }, [mode, prompt, evidence, context]);

  async function run() {
    if (!connected) return setError("Connect your Cyberouter key first.");
    if (!model) return setError("Choose a model.");
    if (!prompt.trim()) return setError("Add something for the model to work on.");
    if (mode === "triage" && !evidence.trim()) return setError("Add the evidence you want the model to check.");

    setBusy(true);
    setError("");
    setResult("");
    setUsage(null);
    try {
      const data = await cyberApi("/api/cyberouter/chat", {
        method: "POST",
        body: JSON.stringify({ model, messages, maxTokens, temperature: 0.1 }),
      });
      setResult(extractText(data) || "Cyberouter returned a response, but no text message was found.");
      setUsage(data?.usage || null);
      setResultSource("playground");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function loadRepository() {
    const parsed = parseRepoInput(repoInput);
    if (!parsed) return setError("Enter a repository as owner/repo or paste its GitHub URL.");
    setRepoBusy(true);
    setError("");
    setRepoProgress("Reading repository map…");
    try {
      if (githubToken.trim()) sessionStorage.setItem("cyberouter_github_token", githubToken.trim());
      else sessionStorage.removeItem("cyberouter_github_token");
      const params = new URLSearchParams({ owner: parsed.owner, repo: parsed.repo });
      if (repoRef.trim()) params.set("ref", repoRef.trim());
      const data = await githubApi(`/api/github/repo?${params}`);
      setRepoData(data);
      setRepoRef(data.repository.ref);
      setRepoProgress("");
    } catch (err) {
      setRepoData(null);
      setRepoProgress("");
      setError(err.message);
    } finally {
      setRepoBusy(false);
    }
  }

  async function getFiles(paths) {
    const repo = repoData.repository;
    const collected = [];
    for (let i = 0; i < paths.length; i += 18) {
      setRepoProgress(`Reading source files · ${Math.min(i + 18, paths.length)}/${paths.length}`);
      const data = await githubApi("/api/github/files", {
        method: "POST",
        body: JSON.stringify({
          owner: repo.owner,
          repo: repo.name,
          ref: repo.ref,
          paths: paths.slice(i, i + 18),
        }),
      });
      collected.push(...(data.files || []));
    }
    return collected;
  }

  async function modelCall(messages, outputTokens = 2600) {
    const data = await cyberApi("/api/cyberouter/chat", {
      method: "POST",
      body: JSON.stringify({
        model,
        messages,
        maxTokens: outputTokens,
        temperature: 0.05,
      }),
    });
    return { text: extractText(data), usage: data?.usage || null };
  }

  async function scanRepository(kind = scanKind) {
    if (!connected) return setError("Connect Cyberouter before scanning a repository.");
    if (!repoData) return setError("Load a repository first.");
    if (!model) return setError("Choose a Cyberouter model.");

    setRepoBusy(true);
    setError("");
    setResult("");
    setUsage(null);
    setScanKind(kind);

    try {
      const candidates = repoData.tree.candidates || [];
      const limit = kind === "deep" ? 48 : 18;
      const selected = selectAuditFiles(candidates, limit);
      const chosen = selected.map((item) => item.path);
      setRepoProgress(`Preparing ${kind === "deep" ? "deep audit" : "quick scan"} · ${chosen.length} files`);
      const files = await getFiles(chosen);
      const readable = files.filter((file) => file.content);
      if (!readable.length) throw new Error("No readable source files were returned.");

      const secretHits = localSecretSignals(readable);
      const batches = batchFiles(readable, kind === "deep" ? 30000 : 38000);
      const findings = [];
      const manifest = candidates.slice(0, 100).map((item) => item.path).join("\n");

      for (let i = 0; i < batches.length; i++) {
        setRepoProgress(`Cyberouter review · batch ${i + 1}/${batches.length}`);
        const source = batches[i].map((file) => file.rendered).join("");
        const response = await modelCall([
          {
            role: "system",
            content: "You are conducting an authorized defensive source-code security audit. Report only evidence-backed issues. For each issue include severity, confidence, exact file, relevant code evidence, attack preconditions, impact, false-positive checks, and minimal remediation. Look especially for broken authorization, IDOR, authentication/session mistakes, injection, unsafe database access, secret exposure, SSRF, file/upload issues, XSS, insecure storage, webhook trust, business-logic abuse, and dangerous infrastructure configuration. Do not invent missing runtime behavior.",
          },
          {
            role: "user",
            content: `Repository: ${repoData.repository.fullName}\nRef: ${repoData.repository.ref}\nAudit depth: ${kind}\n\nRepository map (security-relevant subset):\n${manifest}\n\nReview this source batch:\n${source}`,
          },
        ], kind === "deep" ? 3200 : 2400);
        if (response.text) findings.push(response.text);
      }

      setRepoProgress("Consolidating findings…");
      const localSignalsText = secretHits.length
        ? secretHits.map((h) => `${h.path}:${h.line} ${h.preview}`).join("\n")
        : "No simple local secret-pattern signals were detected in the files reviewed.";

      const synthesisInput = findings.map((text, i) => `=== REVIEW BATCH ${i + 1} ===\n${text.slice(0, 12000)}`).join("\n\n");
      const synthesis = await modelCall([
        {
          role: "system",
          content: "You are the lead defensive security reviewer. Consolidate multiple code-review passes into one practical report. Deduplicate findings. Do not upgrade hypotheses into confirmed vulnerabilities. Rank findings by severity within the report, but preserve confidence separately. Include: executive summary, attack surface, confirmed/high-confidence findings, hypotheses needing runtime verification, local secret-scan signals, remediation order, and a retest checklist. Cite file paths throughout. Return clean GitHub-flavored Markdown only. Do not wrap the full report in a code fence. Keep tables compact and prefer short paragraphs and bullets.",
        },
        {
          role: "user",
          content: `Repository: ${repoData.repository.fullName}\nRef: ${repoData.repository.ref}\nMode: ${kind}\nFiles reviewed: ${readable.length}\nReviewable files mapped: ${repoData.tree.reviewableFiles}\n\nLocal secret-pattern signals (values redacted):\n${localSignalsText}\n\nModel review outputs:\n${synthesisInput.slice(0, 52000)}`,
        },
      ], 4200);

      const finalText = synthesis.text || findings.join("\n\n");
      setResult(finalText);
      setUsage(synthesis.usage);
      setResultSource("repo");
      setSessionHistory((items) => [{
        id: Date.now(),
        kind,
        repo: repoData.repository.fullName,
        ref: repoData.repository.ref,
        model,
        files: readable.length,
        secretSignals: secretHits.length,
      }, ...items].slice(0, 8));
      setRepoProgress(`Finished · ${readable.length} files reviewed`);
    } catch (err) {
      setRepoProgress("");
      setError(err.message);
    } finally {
      setRepoBusy(false);
    }
  }

  async function reviewPullRequest() {
    if (!connected) return setError("Connect Cyberouter first.");
    if (!repoData) return setError("Load a repository first.");
    const number = Number(prNumber);
    if (!Number.isInteger(number) || number < 1) return setError("Enter a valid pull request number.");

    setRepoBusy(true);
    setError("");
    setResult("");
    setRepoProgress(`Loading PR #${number}…`);
    try {
      const repo = repoData.repository;
      const params = new URLSearchParams({ owner: repo.owner, repo: repo.name, number: String(number) });
      const pr = await githubApi(`/api/github/pr?${params}`);
      setRepoProgress(`Reviewing PR #${number} with Cyberouter…`);

      const chunks = [];
      for (let i = 0; i < pr.diff.length; i += 38000) chunks.push(pr.diff.slice(i, i + 38000));
      const outputs = [];
      for (let i = 0; i < chunks.length; i++) {
        setRepoProgress(`Reviewing PR #${number} · chunk ${i + 1}/${chunks.length}`);
        const response = await modelCall([
          {
            role: "system",
            content: "You are reviewing an authorized pull request for security regressions. Focus on vulnerabilities introduced or made reachable by this diff. Cite changed files and relevant diff evidence. Distinguish confirmed issues from hypotheses and avoid unrelated style feedback.",
          },
          {
            role: "user",
            content: `Repository: ${repo.fullName}\nPR #${number}: ${pr.pullRequest.title}\nBase: ${pr.pullRequest.base}\nHead: ${pr.pullRequest.head}\nChanged files: ${pr.pullRequest.changedFiles}\n\nDiff chunk:\n${chunks[i]}`,
          },
        ], 2800);
        if (response.text) outputs.push(response.text);
      }

      let final = outputs.join("\n\n");
      if (outputs.length > 1) {
        setRepoProgress(`Consolidating PR #${number} review…`);
        const synthesis = await modelCall([
          { role: "system", content: "Consolidate these authorized PR security review notes. Deduplicate findings, keep exact file references, preserve confidence, and finish with a short merge-safety checklist. Do not invent evidence. Return clean GitHub-flavored Markdown only and do not wrap the whole response in a code fence." },
          { role: "user", content: outputs.join("\n\n").slice(0, 52000) },
        ], 3200);
        final = synthesis.text || final;
        setUsage(synthesis.usage);
      }
      setResult(final || "No textual review was returned.");
      setResultSource("pr");
      setRepoProgress(`Finished PR #${number} review`);
      setSessionHistory((items) => [{
        id: Date.now(),
        kind: "PR review",
        repo: repo.fullName,
        ref: `#${number}`,
        model,
        files: pr.pullRequest.changedFiles,
        secretSignals: 0,
      }, ...items].slice(0, 8));
    } catch (err) {
      setRepoProgress("");
      setError(err.message);
    } finally {
      setRepoBusy(false);
    }
  }

  async function siteApi(path, init = {}) {
    const response = await fetch(path, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        "x-cyberouter-key": apiKey.trim(),
        ...(init.headers || {}),
      },
      cache: "no-store",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data?.error || `Website audit failed with HTTP ${response.status}`);
    return data;
  }

  function generateSiteToken() {
    const random = typeof crypto !== "undefined" && crypto.randomUUID
      ? crypto.randomUUID()
      : Math.random().toString(36).slice(2) + Date.now().toString(36);
    setSiteToken(`cyberouter-${random}`);
  }

  function verificationUrl() {
    try {
      const value = /^[a-z][a-z0-9+.-]*:\/\//i.test(siteTarget.trim()) ? siteTarget.trim() : `https://${siteTarget.trim()}`;
      return new URL("/.well-known/cyberouter-lab.txt", value).toString();
    } catch {
      return "/.well-known/cyberouter-lab.txt";
    }
  }

  function localSiteMarkdown(scan) {
    const s = scan?.summary || {};
    const lines = [
      `# Website Security Assessment`,
      ``,
      `**Target:** ${scan?.finalUrl || scan?.target || siteTarget}`,
      `**Mode:** ${scan?.mode === "active" ? "Verified active checks" : "Passive assessment"}`,
      `**Pages scanned:** ${s.pagesScanned || 0}`,
      ``,
      `## Findings`,
    ];
    if (!scan?.findings?.length) {
      lines.push("", "No deterministic findings were produced by the bounded scanner. This does not mean the application has no vulnerabilities.");
    } else {
      for (const item of scan.findings) {
        lines.push(
          "",
          `### ${item.title}`,
          `**Severity: ${item.severity}**  `,
          `**Confidence:** ${item.confidence || "Medium"}  `,
          `**Category:** ${item.category || "Web security"}  `,
          `**Page:** ${item.page || scan.target}`,
          "",
          `**Evidence:** ${item.evidence}`,
          "",
          `**Remediation:** ${item.recommendation}`,
        );
      }
    }
    lines.push(
      "",
      "## Scope limits",
      "",
      "This hosted assessment does not submit forms, attempt passwords, exploit vulnerabilities, access private networks, or perform destructive actions. Authenticated business-logic testing still requires a dedicated staging/sandbox test setup.",
    );
    return lines.join("\n");
  }

  async function auditWebsite() {
    if (!connected) return setError("Connect Cyberouter before scanning a website.");
    if (!siteTarget.trim()) return setError("Enter a website URL.");
    if (!model) return setError("Choose a Cyberouter model.");
    if (siteMode === "active" && !siteAuthorized) return setError("Confirm that you own the target or have explicit permission to test it.");
    if (siteMode === "active" && !siteToken) return setError("Generate a verification token and publish the verification file first.");

    setSiteBusy(true);
    setError("");
    setResult("");
    setUsage(null);
    setSiteScan(null);
    setSiteProgress(siteMode === "active" ? "Verifying target ownership…" : "Mapping public attack surface…");

    try {
      const scan = await siteApi("/api/site/audit", {
        method: "POST",
        body: JSON.stringify({
          target: siteTarget.trim(),
          mode: siteMode,
          authorizationToken: siteToken,
          authorized: siteAuthorized,
        }),
      });
      setSiteScan(scan);

      if (siteMode === "active" && !scan?.verification?.ok) {
        setResult([
          "# Target verification required",
          "",
          scan?.verification?.reason || "The verification file could not be confirmed.",
          "",
          `Publish this exact token at \`${verificationUrl()}\` and run the scan again.`,
          "",
          `\`${siteToken}\``,
        ].join("\n"));
        setResultSource("website");
        setSiteProgress("Verification did not pass");
        return;
      }

      let repoContext = "";
      if (correlateRepo && repoData?.tree?.candidates?.length) {
        setSiteProgress("Reading linked repository context…");
        const selected = selectAuditFiles(repoData.tree.candidates, 8);
        const repo = repoData.repository;
        const fileData = await githubApi("/api/github/files", {
          method: "POST",
          body: JSON.stringify({
            owner: repo.owner,
            repo: repo.name,
            ref: repo.ref,
            paths: selected.map((item) => item.path),
          }),
        });
        repoContext = (fileData.files || [])
          .filter((item) => item.content)
          .map((item) => `===== ${item.path} =====\n${item.content}`)
          .join("\n\n")
          .slice(0, 30000);
      }

      setSiteProgress("Cyberouter is interpreting the web evidence…");
      let report = "";
      let reportUsage = null;
      try {
        const response = await modelCall([
          {
            role: "system",
            content: "You are the lead defensive web application security reviewer. Interpret only the supplied evidence from an authorized bounded website assessment. Use OWASP WSTG and ASVS 5.0 concepts as a taxonomy, not as a claim of compliance. Separate confirmed observations from hypotheses that require authenticated or deeper testing. Do not invent endpoints, credentials, source behavior, or exploitability. Return clean GitHub-flavored Markdown. Include executive summary, attack surface, findings with severity and confidence, evidence, likely impact, remediation, what was not tested, and a prioritized retest plan.",
          },
          {
            role: "user",
            content: `Website evidence:\n${JSON.stringify(scan).slice(0, 62000)}${repoContext ? `\n\nLinked repository: ${repoData.repository.fullName}@${repoData.repository.ref}\nUse the source excerpts only to correlate web observations with likely implementation points.\n\n${repoContext}` : ""}`,
          },
        ], 4200);
        report = response.text || "";
        reportUsage = response.usage;
      } catch {
        report = "";
      }

      setResult(report || localSiteMarkdown(scan));
      setUsage(reportUsage);
      setResultSource("website");
      setSiteProgress(`Finished · ${scan.summary?.pagesScanned || 0} pages · ${scan.findings?.length || 0} deterministic observations`);
    } catch (err) {
      setSiteProgress("");
      setError(err.message);
    } finally {
      setSiteBusy(false);
    }
  }

  async function copyReport() {
    if (!result) return;
    await navigator.clipboard.writeText(result);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  }

  function downloadReport() {
    if (!result) return;
    const repoName = repoData?.repository?.name || "cyberouter";
    const kind = latestScan?.kind ? String(latestScan.kind).replace(/\s+/g, "-") : "report";
    const blob = new Blob([result], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${repoName}-${kind}-security-report.md`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  async function copyMcp() {
    await navigator.clipboard.writeText(`${window.location.origin}/api/mcp`);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  }

  async function copyCodexConfig() {
    const config = `[mcp_servers.cyberouter]\nurl = "${window.location.origin}/api/mcp"\nbearer_token_env_var = "CYBEROUTER_API_KEY"`;
    await navigator.clipboard.writeText(config);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand">
          <div className="mark">C</div>
          <div>
            <div className="brand-title">Cyberouter Lab</div>
            <div className="brand-sub">Repository security lab + remote MCP</div>
          </div>
        </div>
        <div className={`status-pill ${connected ? "ok" : ""}`}><span className="status-dot" />{status}</div>
      </header>

      <section className="hero compact-hero">
        <div>
          <div className="eyebrow">CYBEROUTER SECURITY WORKSPACE</div>
          <h1>Review a file, a pull request, or an entire codebase.</h1>
          <p>Your Cyberouter key stays in this browser. Repository access is read-only. Public repos need no GitHub token; private repos can use a fine-grained read-only token for the current browser session.</p>
        </div>
        <div className="mcp-card">
          <span className="card-kicker">REMOTE MCP</span>
          <strong>/api/mcp</strong>
          <p>Connect Codex and let it call Cyberouter as a specialist while Codex keeps your repo context.</p>
          <button className="ghost" onClick={copyMcp}>{copied ? "Copied" : "Copy MCP URL"}</button>
        </div>
      </section>

      <nav className="surface-tabs">
        <button className={surface === "repositories" ? "active" : ""} onClick={() => setSurface("repositories")}>Repositories</button>
        <button className={surface === "website" ? "active" : ""} onClick={() => setSurface("website")}>Website</button>
        <button className={surface === "playground" ? "active" : ""} onClick={() => setSurface("playground")}>Playground</button>
        <button className={surface === "connection" ? "active" : ""} onClick={() => setSurface("connection")}>Connection</button>
      </nav>

      {surface === "connection" && (
        <section className="grid connection-grid">
          <aside className="panel key-panel">
            <div className="panel-head"><div><span className="step">01</span><h2>Cyberouter</h2></div>{connected && <button className="text-button" onClick={disconnect}>Disconnect</button>}</div>
            <label className="field"><span>Cyberouter API key</span><input type="password" autoComplete="off" spellCheck="false" value={apiKey} placeholder="Paste your key" onChange={(e) => setApiKey(e.target.value)} /></label>
            <label className="check-row"><input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} /><span>Remember on this device<small>Off keeps it only until this browser session ends.</small></span></label>
            <button className="primary" disabled={busy || !apiKey.trim()} onClick={connect}>{busy && !connected ? "Checking…" : connected ? "Refresh models" : "Connect & load models"}</button>
            <div className="privacy-note"><span>Key handling</span><p>No database. The key is forwarded only to the fixed Cyberouter API when you make a request.</p></div>
          </aside>

          <section className="panel work-panel">
            <div className="panel-head"><div><span className="step">02</span><h2>GitHub access</h2></div></div>
            <label className="field"><span>Fine-grained GitHub token <em>optional</em></span><input type="password" autoComplete="off" value={githubToken} placeholder="Only needed for private repos" onChange={(e) => setGithubToken(e.target.value)} /></label>
            <div className="privacy-note"><span>Recommended permission</span><p>Use a fine-grained token scoped only to repositories you want to scan, with Contents: Read and Pull requests: Read. It is kept in sessionStorage only and is not committed or stored server-side.</p></div>
            {connected && <div className="model-cloud">{models.map((item) => <span key={item}>{item}</span>)}</div>}
            <div className="codex-box">
              <span className="scan-label">CODEX MCP</span>
              <strong>Use Cyberouter beside Codex</strong>
              <p>Codex keeps its OpenAI model as the main agent and can call these Cyberouter models through the MCP tools. They do not become entries in Codex's native model picker.</p>
              <button className="ghost" onClick={copyCodexConfig}>{copied ? "Copied" : "Copy Codex config"}</button>
            </div>
          </section>
        </section>
      )}

      {surface === "website" && (
        <section className="site-layout">
          <aside className="panel site-target-panel">
            <div className="panel-head"><div><span className="step">01</span><h2>Target</h2></div></div>
            <label className="field">
              <span>Website URL</span>
              <input value={siteTarget} placeholder="https://staging.example.com" onChange={(e) => { setSiteTarget(e.target.value); setSiteScan(null); }} />
            </label>
            <div className="privacy-note">
              <span>Hosted scanner boundary</span>
              <p>Public HTTP/HTTPS only. Private IPs, localhost, internal hostnames, non-standard ports, cross-host redirects, form submission, credential attacks, and exploit payloads are blocked.</p>
            </div>
            {repoData && (
              <label className="check-row">
                <input type="checkbox" checked={correlateRepo} onChange={(e) => setCorrelateRepo(e.target.checked)} />
                <span>Correlate with {repoData.repository.fullName}<small>Cyberouter can compare web observations with a small set of security-relevant source files from the repository you already loaded.</small></span>
              </label>
            )}
          </aside>

          <section className="panel site-main">
            <div className="panel-head">
              <div><span className="step">02</span><h2>Website assessment</h2></div>
              <select className="model-select" value={model} onChange={(e) => setModel(e.target.value)} disabled={!connected}>
                {!connected && <option>Connect Cyberouter</option>}
                {models.map((item) => <option value={item} key={item}>{item}</option>)}
              </select>
            </div>

            <div className="scan-cards">
              <button className={`scan-card ${siteMode === "passive" ? "selected" : ""}`} onClick={() => setSiteMode("passive")}>
                <span className="scan-label">PASSIVE ASSESSMENT</span>
                <strong>Public attack-surface review</strong>
                <p>GET-only crawl of up to 6 same-host pages, browser security headers, cookies, forms, mixed content, security.txt and robots.txt.</p>
              </button>
              <button className={`scan-card ${siteMode === "active" ? "selected" : ""}`} onClick={() => setSiteMode("active")}>
                <span className="scan-label">VERIFIED ACTIVE</span>
                <strong>Ownership-gated checks</strong>
                <p>Requires a file challenge on the target. Adds bounded CORS and HTTP-method checks without submitting forms or sending exploit payloads.</p>
              </button>
            </div>

            {siteMode === "active" && (
              <div className="verification-card">
                <div className="verification-head">
                  <div><span className="scan-label">DOMAIN VERIFICATION</span><strong>Prove control before active checks</strong></div>
                  <button className="ghost" onClick={generateSiteToken}>{siteToken ? "New token" : "Generate token"}</button>
                </div>
                {siteToken ? (
                  <>
                    <p>Create a plain text file at:</p>
                    <code className="verification-code">{verificationUrl()}</code>
                    <p>Its entire contents must be:</p>
                    <code className="verification-code">{siteToken}</code>
                  </>
                ) : <p>Generate a token, publish it at the well-known path, then run the verified scan.</p>}
                <label className="check-row authorization-check">
                  <input type="checkbox" checked={siteAuthorized} onChange={(e) => setSiteAuthorized(e.target.checked)} />
                  <span>I own this target or have explicit permission to test it.<small>The scanner still remains bounded even after verification.</small></span>
                </label>
              </div>
            )}

            <div className="site-scope">
              <span><b>No</b> password guessing</span>
              <span><b>No</b> destructive requests</span>
              <span><b>No</b> private-network access</span>
              <span><b>No</b> form submission</span>
            </div>

            <div className="scan-actions">
              <button className="primary" disabled={siteBusy || !connected || !siteTarget.trim()} onClick={auditWebsite}>
                {siteBusy ? "Testing…" : siteMode === "active" ? "Run verified assessment" : "Run passive assessment"}
              </button>
              <div className="progress-copy">{siteProgress || (connected ? "Ready to assess" : "Connect Cyberouter first")}</div>
            </div>

            {siteScan && (
              <div className="site-summary">
                <div><strong>{siteScan.summary?.pagesScanned || 0}</strong><span>pages</span></div>
                <div><strong>{siteScan.summary?.critical || 0}</strong><span>critical</span></div>
                <div><strong>{siteScan.summary?.high || 0}</strong><span>high</span></div>
                <div><strong>{siteScan.summary?.medium || 0}</strong><span>medium</span></div>
                <div><strong>{siteScan.findings?.length || 0}</strong><span>observations</span></div>
              </div>
            )}

            <div className="method-note">
              <span className="scan-label">METHOD</span>
              <p>Structured around OWASP WSTG web-testing categories and ASVS control areas. The hosted scan is deliberately bounded. Authenticated role abuse, business-logic abuse, exploit validation, and destructive testing belong in a disposable staging environment.</p>
            </div>
          </section>
        </section>
      )}

      {surface === "playground" && (
        <section className="panel work-panel standalone">
          <div className="panel-head">
            <div><span className="step">01</span><h2>Focused task</h2></div>
            <select className="model-select" value={model} onChange={(e) => setModel(e.target.value)} disabled={!connected}>
              {!connected && <option>Connect first</option>}
              {models.map((item) => <option value={item} key={item}>{item}</option>)}
            </select>
          </div>
          <div className="mode-tabs">{Object.entries(MODES).map(([id, item]) => <button key={id} className={mode === id ? "active" : ""} onClick={() => setMode(id)}>{item.label}</button>)}</div>
          <div className="task-title"><h3>{currentMode.title}</h3><p>{currentMode.helper}</p></div>
          {mode === "review" && <label className="field"><span>Context <em>optional</em></span><textarea className="short" value={context} placeholder="Architecture, framework, expected trust boundary, relevant user role…" onChange={(e) => setContext(e.target.value)} /></label>}
          <label className="field"><span>{mode === "triage" ? "Finding" : mode === "review" ? "Code or diff" : "Prompt"}</span><textarea value={prompt} placeholder={currentMode.placeholder} onChange={(e) => setPrompt(e.target.value)} /></label>
          {mode === "triage" && <label className="field"><span>Evidence</span><textarea value={evidence} placeholder="Paste code, request/response traces, logs, scanner output, or the relevant diff…" onChange={(e) => setEvidence(e.target.value)} /></label>}
          <div className="run-row"><label className="token-field"><span>Max output tokens</span><input type="number" min="64" max="8192" step="64" value={maxTokens} onChange={(e) => setMaxTokens(e.target.value)} /></label><button className="primary run" disabled={busy || !connected} onClick={run}>{busy && connected ? "Running…" : "Run with Cyberouter"}</button></div>
        </section>
      )}

      {surface === "repositories" && (
        <section className="repo-layout">
          <aside className="panel repo-sidebar">
            <div className="panel-head"><div><span className="step">01</span><h2>Repository</h2></div></div>
            <label className="field"><span>GitHub repository</span><input value={repoInput} placeholder="owner/repo or GitHub URL" onChange={(e) => setRepoInput(e.target.value)} /></label>
            <label className="field"><span>Branch / ref <em>optional</em></span><input value={repoRef} placeholder="Uses default branch" onChange={(e) => setRepoRef(e.target.value)} /></label>
            <button className="primary" disabled={repoBusy || !repoInput.trim()} onClick={loadRepository}>{repoBusy && !repoData ? "Reading…" : "Load repository"}</button>

            {repoData && (
              <div className="repo-summary">
                <div className="repo-name">{repoData.repository.fullName}</div>
                <div className="repo-meta"><span>{repoData.repository.private ? "Private" : "Public"}</span><span>{repoData.repository.ref}</span></div>
                <div className="stat-grid">
                  <div><strong>{repoData.tree.reviewableFiles}</strong><span>reviewable files</span></div>
                  <div><strong>{repoData.tree.directories}</strong><span>directories</span></div>
                </div>
                {repoData.tree.truncated && <div className="warning">GitHub returned a truncated tree. The scan will cover the security-ranked subset that was available.</div>}
              </div>
            )}

            <div className="privacy-note"><span>Private repositories</span><p>Go to Connection and add a fine-grained read-only GitHub token. Public repositories work without one.</p></div>
          </aside>

          <section className="panel repo-main">
            <div className="panel-head">
              <div><span className="step">02</span><h2>Security scan</h2></div>
              <select className="model-select" value={model} onChange={(e) => setModel(e.target.value)} disabled={!connected}>
                {!connected && <option>Connect Cyberouter</option>}
                {models.map((item) => <option value={item} key={item}>{item}</option>)}
              </select>
            </div>

            {!repoData ? (
              <div className="repo-empty">
                <div className="empty-mark">⌁</div>
                <h3>Load a repository to map its attack surface.</h3>
                <p>The first pass reads the GitHub tree only. Source files are fetched when you start a scan.</p>
              </div>
            ) : (
              <>
                <div className="scan-cards">
                  <button className={`scan-card ${scanKind === "quick" ? "selected" : ""}`} onClick={() => setScanKind("quick")}>
                    <span className="scan-label">QUICK SCAN</span>
                    <strong>Focused security pass</strong>
                    <p>Reviews up to 18 high-signal files. Good before deployment or after a small feature.</p>
                  </button>
                  <button className={`scan-card ${scanKind === "deep" ? "selected" : ""}`} onClick={() => setScanKind("deep")}>
                    <span className="scan-label">DEEP AUDIT</span>
                    <strong>Broader codebase review</strong>
                    <p>Reviews up to 48 security-ranked files in multiple model passes, then consolidates the findings.</p>
                  </button>
                </div>

                <div className="scan-actions">
                  <button className="primary" disabled={repoBusy || !connected} onClick={() => scanRepository(scanKind)}>{repoBusy ? "Working…" : scanKind === "deep" ? "Start deep audit" : "Start quick scan"}</button>
                  <div className="progress-copy">{repoProgress || (connected ? "Ready to scan" : "Connect Cyberouter first")}</div>
                </div>

                <div className="pr-row">
                  <div><span className="scan-label">PULL REQUEST REVIEW</span><p>Review only the code changed by a PR for new security regressions.</p></div>
                  <div className="pr-controls"><input type="number" min="1" value={prNumber} placeholder="PR #" onChange={(e) => setPrNumber(e.target.value)} /><button className="ghost" disabled={repoBusy || !connected} onClick={reviewPullRequest}>Review PR</button></div>
                </div>

                <div className="attack-map">
                  <div className="section-caption">HIGH-SIGNAL FILES</div>
                  <div className="file-list">{repoData.tree.candidates.slice(0, 16).map((file) => <div className="file-row" key={file.path}><span>{file.path}</span><b>{file.score}</b></div>)}</div>
                </div>
              </>
            )}
          </section>

          {sessionHistory.length > 0 && (
            <aside className="panel history-panel">
              <div className="panel-head"><div><span className="step">03</span><h2>This session</h2></div></div>
              <div className="history-list">{sessionHistory.map((item) => <div className="history-item" key={item.id}><strong>{item.kind}</strong><span>{item.repo}</span><small>{item.ref} · {item.files} files · {item.model}</small></div>)}</div>
            </aside>
          )}
        </section>
      )}

      {error && <div className="error-box global-error">{error}</div>}

      <section className="panel output-panel">
        <div className="panel-head">
          <div><span className="step">{surface === "repositories" ? "04" : "03"}</span><h2>Security report</h2></div>
          {usage && <div className="usage">{usage.prompt_tokens != null && <span>In {usage.prompt_tokens.toLocaleString()}</span>}{usage.completion_tokens != null && <span>Out {usage.completion_tokens.toLocaleString()}</span>}{usage.total_tokens != null && <span>Total {usage.total_tokens.toLocaleString()}</span>}</div>}
        </div>
        {result ? (
          <div className="report-wrap">
            <div className="report-toolbar">
              <div className="report-badges">
                {severityCounts.critical > 0 && <span className="risk-chip critical">{severityCounts.critical} critical</span>}
                {severityCounts.high > 0 && <span className="risk-chip high">{severityCounts.high} high</span>}
                {severityCounts.medium > 0 && <span className="risk-chip medium">{severityCounts.medium} medium</span>}
                {severityCounts.low > 0 && <span className="risk-chip low">{severityCounts.low} low</span>}
                {resultSource === "repo" && latestScan && repoData && <span className="coverage-chip">{latestScan.files} of {repoData.tree.reviewableFiles} reviewable files</span>}
              </div>
              <div className="report-actions">
                <button className="ghost" onClick={copyReport}>{copied ? "Copied" : "Copy report"}</button>
                <button className="ghost" onClick={downloadReport}>Download .md</button>
              </div>
            </div>
            {resultSource === "repo" && latestScan && repoData && latestScan.files < repoData.tree.reviewableFiles && (
              <div className="coverage-note">
                <strong>Coverage note</strong>
                <span>This was a focused {latestScan.kind} scan, not a full review of all {repoData.tree.reviewableFiles} mapped files. New scans spread coverage across auth, API, data, frontend, and configuration code instead of letting one folder dominate.</span>
              </div>
            )}
            <article className="markdown-report">
              <ReactMarkdown remarkPlugins={[remarkGfm]} components={{ strong: StrongLabel }}>{result}</ReactMarkdown>
            </article>
          </div>
        ) : <div className="empty"><div className="empty-mark">⌁</div><p>Your Cyberouter report will appear here.</p><span>Run a repository scan, PR review, or focused playground task.</span></div>}
      </section>

      <footer><span>Cyberouter Lab</span><span>Read-only repository access · fixed upstream: router.enclave.ai/v1</span></footer>
    </main>
  );
}
