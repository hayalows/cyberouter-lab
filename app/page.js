"use client";

import { useEffect, useMemo, useState } from "react";

const MODES = {
  ask: {
    label: "Ask",
    title: "Ask a Cyberouter model",
    helper: "Good for secure coding questions, architecture checks, and model exploration.",
    placeholder: "Ask a security or secure-software question…",
  },
  review: {
    label: "Review code",
    title: "Review code or a diff",
    helper: "Looks for concrete security issues and asks the model to separate evidence from hypotheses.",
    placeholder: "Paste code, a diff, or a focused file here…",
  },
  triage: {
    label: "Triage finding",
    title: "Pressure-test a suspected finding",
    helper: "Useful when another scanner or model flags something and you want a second opinion.",
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

function money(value) {
  if (value == null || Number.isNaN(Number(value))) return null;
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 5 }).format(Number(value));
}

export default function Home() {
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

  useEffect(() => {
    const persistent = localStorage.getItem("cyberouter_key");
    const session = sessionStorage.getItem("cyberouter_key");
    const found = persistent || session || "";
    if (found) {
      setApiKey(found);
      setRemember(Boolean(persistent));
    }
  }, []);

  const currentMode = MODES[mode];

  async function api(path, init = {}) {
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
    if (!response.ok) {
      throw new Error(data?.error || `Request failed with HTTP ${response.status}`);
    }
    return data;
  }

  async function connect() {
    if (!apiKey.trim()) {
      setError("Enter your Cyberouter API key first.");
      return;
    }
    setBusy(true);
    setError("");
    setStatus("Checking key…");
    try {
      const data = await api("/api/cyberouter/models");
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
    if (!remember) setApiKey("");
  }

  const messages = useMemo(() => {
    if (mode === "review") {
      return [
        {
          role: "system",
          content:
            "You are a defensive application-security reviewer. Analyze only the authorized code and context supplied. Focus on concrete vulnerabilities, exact evidence, realistic attack preconditions, false-positive checks, impact, confidence, and minimal remediation. Do not invent findings. Clearly separate confirmed issues from hypotheses.",
        },
        {
          role: "user",
          content: `${context.trim() ? `Context:\n${context.trim()}\n\n` : ""}Code or diff to review:\n\n${prompt.trim()}`,
        },
      ];
    }
    if (mode === "triage") {
      return [
        {
          role: "system",
          content:
            "You are a defensive security triage analyst. Test the claimed issue against the supplied evidence. Identify assumptions, attack preconditions, disconfirming evidence, confidence, likely impact, and the smallest safe remediation. Do not claim exploitability without evidence.",
        },
        {
          role: "user",
          content: `Suspected finding:\n${prompt.trim()}\n\nEvidence:\n${evidence.trim()}`,
        },
      ];
    }
    return [
      {
        role: "system",
        content:
          "You are a cybersecurity and secure-software engineering assistant. Work only with authorized systems and code. Be concrete, evidence-driven, and explicit about uncertainty.",
      },
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
      const data = await api("/api/cyberouter/chat", {
        method: "POST",
        body: JSON.stringify({
          model,
          messages,
          maxTokens,
          temperature: 0.1,
        }),
      });
      const text = extractText(data);
      setResult(text || "Cyberouter returned a response, but this UI could not find a text message in it.");
      setUsage(data?.usage || null);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function copyMcp() {
    const value = `${window.location.origin}/api/mcp`;
    await navigator.clipboard.writeText(value);
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
            <div className="brand-sub">Enclave model playground + remote MCP</div>
          </div>
        </div>
        <div className={`status-pill ${connected ? "ok" : ""}`}>
          <span className="status-dot" />
          {status}
        </div>
      </header>

      <section className="hero">
        <div>
          <div className="eyebrow">PRIVATE-BY-DESIGN CLIENT</div>
          <h1>Use your Cyberouter models without putting the key in the repo.</h1>
          <p>
            Your key is stored in this browser only. The server function forwards each request to
            <code> router.enclave.ai</code> and does not persist the credential.
          </p>
        </div>
        <div className="mcp-card">
          <span className="card-kicker">REMOTE MCP</span>
          <strong>/api/mcp</strong>
          <p>Use the same deployment from Codex or another Streamable HTTP MCP client.</p>
          <button className="ghost" onClick={copyMcp}>{copied ? "Copied" : "Copy MCP URL"}</button>
        </div>
      </section>

      <section className="grid">
        <aside className="panel key-panel">
          <div className="panel-head">
            <div>
              <span className="step">01</span>
              <h2>Connect</h2>
            </div>
            {connected && <button className="text-button" onClick={disconnect}>Disconnect</button>}
          </div>

          <label className="field">
            <span>Cyberouter API key</span>
            <input
              type="password"
              autoComplete="off"
              spellCheck="false"
              value={apiKey}
              placeholder="Paste your temporary key"
              onChange={(e) => setApiKey(e.target.value)}
            />
          </label>

          <label className="check-row">
            <input
              type="checkbox"
              checked={remember}
              onChange={(e) => setRemember(e.target.checked)}
            />
            <span>
              Remember on this device
              <small>Off means the key disappears when this browser session ends.</small>
            </span>
          </label>

          <button className="primary" disabled={busy || !apiKey.trim()} onClick={connect}>
            {busy && !connected ? "Checking…" : connected ? "Refresh models" : "Connect & load models"}
          </button>

          <div className="privacy-note">
            <span>Key handling</span>
            <p>No database. No analytics. No server-side storage. The key is sent only when you make a Cyberouter request.</p>
          </div>
        </aside>

        <section className="panel work-panel">
          <div className="panel-head">
            <div>
              <span className="step">02</span>
              <h2>Run a task</h2>
            </div>
            <select
              className="model-select"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              disabled={!connected}
            >
              {!connected && <option>Connect first</option>}
              {models.map((item) => <option value={item} key={item}>{item}</option>)}
            </select>
          </div>

          <div className="mode-tabs">
            {Object.entries(MODES).map(([id, item]) => (
              <button key={id} className={mode === id ? "active" : ""} onClick={() => setMode(id)}>
                {item.label}
              </button>
            ))}
          </div>

          <div className="task-title">
            <h3>{currentMode.title}</h3>
            <p>{currentMode.helper}</p>
          </div>

          {mode === "review" && (
            <label className="field">
              <span>Context <em>optional</em></span>
              <textarea
                className="short"
                value={context}
                placeholder="Architecture, framework, expected trust boundary, relevant user role…"
                onChange={(e) => setContext(e.target.value)}
              />
            </label>
          )}

          <label className="field">
            <span>{mode === "triage" ? "Finding" : mode === "review" ? "Code or diff" : "Prompt"}</span>
            <textarea
              value={prompt}
              placeholder={currentMode.placeholder}
              onChange={(e) => setPrompt(e.target.value)}
            />
          </label>

          {mode === "triage" && (
            <label className="field">
              <span>Evidence</span>
              <textarea
                value={evidence}
                placeholder="Paste code, request/response traces, scanner evidence, logs, or the relevant diff…"
                onChange={(e) => setEvidence(e.target.value)}
              />
            </label>
          )}

          <div className="run-row">
            <label className="token-field">
              <span>Max output tokens</span>
              <input
                type="number"
                min="64"
                max="8192"
                step="64"
                value={maxTokens}
                onChange={(e) => setMaxTokens(e.target.value)}
              />
            </label>
            <button className="primary run" disabled={busy || !connected} onClick={run}>
              {busy && connected ? "Running…" : "Run with Cyberouter"}
            </button>
          </div>

          {error && <div className="error-box">{error}</div>}
        </section>
      </section>

      <section className="panel output-panel">
        <div className="panel-head">
          <div>
            <span className="step">03</span>
            <h2>Response</h2>
          </div>
          {usage && (
            <div className="usage">
              {usage.prompt_tokens != null && <span>In {usage.prompt_tokens.toLocaleString()}</span>}
              {usage.completion_tokens != null && <span>Out {usage.completion_tokens.toLocaleString()}</span>}
              {usage.total_tokens != null && <span>Total {usage.total_tokens.toLocaleString()}</span>}
              {usage.cost != null && <span>{money(usage.cost)}</span>}
            </div>
          )}
        </div>

        {result ? (
          <pre className="result">{result}</pre>
        ) : (
          <div className="empty">
            <div className="empty-mark">⌁</div>
            <p>Your model response will appear here.</p>
            <span>Connect a key, pick a model, and run a focused task.</span>
          </div>
        )}
      </section>

      <footer>
        <span>Cyberouter Lab</span>
        <span>Fixed upstream: https://router.enclave.ai/v1</span>
      </footer>
    </main>
  );
}
