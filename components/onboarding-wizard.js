"use client";

import { useEffect } from "react";

const STEPS = ["Welcome", "Connect", "Choose"];

export default function OnboardingWizard({
  open,
  step,
  onStep,
  onClose,
  apiKey,
  onApiKey,
  remember,
  onRemember,
  onConnect,
  busy,
  connected,
  keyUrl,
  onChoose,
}) {
  useEffect(() => {
    function keydown(event) {
      if (event.key === "Escape") onClose();
    }
    if (open) {
      document.addEventListener("keydown", keydown);
      document.body.style.overflow = "hidden";
    }
    return () => {
      document.removeEventListener("keydown", keydown);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="wizard-backdrop" role="dialog" aria-modal="true" aria-labelledby="wizard-title">
      <div className="wizard">
        <div className="wizard-head">
          <div className="wizard-dots" aria-hidden="true">
            {STEPS.map((label, index) => <span key={label} className={index === step ? "on" : index < step ? "done" : ""} />)}
          </div>
          <button type="button" className="text-button" onClick={onClose}>Skip setup</button>
        </div>

        {step === 0 && (
          <>
            <h2 id="wizard-title">Welcome to Cyberouter Lab</h2>
            <p className="wizard-lead">A safe way to check whether your website or your code has common security problems — explained in plain language.</p>
            <ul className="wizard-points">
              <li><strong>Safe by design.</strong> Website checks are read-only. They never guess passwords, submit forms, or attack anyone.</li>
              <li><strong>Plain answers.</strong> You get a score from 0–100 and a short list of what to fix.</li>
              <li><strong>Your key stays yours.</strong> Your Cyberouter key is kept in this browser and used only for your requests.</li>
            </ul>
            <div className="wizard-actions">
              <button type="button" className="primary" onClick={() => onStep(1)}>Get started</button>
            </div>
          </>
        )}

        {step === 1 && (
          <>
            <h2 id="wizard-title">Connect your Cyberouter key</h2>
            <p className="wizard-lead">Checks use your own Cyberouter key. Paste it below and we will confirm it works. You can change this later in Connection.</p>
            <label className="field">
              <span>Cyberouter API key</span>
              <input type="password" autoComplete="new-password" spellCheck="false" value={apiKey} placeholder="Paste your key" onChange={(event) => onApiKey(event.target.value)} />
            </label>
            <label className="check-row">
              <input type="checkbox" checked={remember} onChange={(event) => onRemember(event.target.checked)} />
              <span>Remember on this device<small>Off keeps the key only until this browser session ends.</small></span>
            </label>
            {connected && <div className="wizard-ok" role="status">Key connected. You are ready to go.</div>}
            <div className="wizard-actions">
              <button type="button" className="ghost" onClick={() => onStep(2)}>Skip for now</button>
              <button type="button" className="primary" disabled={busy || !apiKey.trim()} onClick={onConnect}>{busy ? "Checking…" : connected ? "Connected" : "Connect key"}</button>
            </div>
            <p className="wizard-foot">No key yet? <a href={keyUrl} target="_blank" rel="noreferrer">Open the Cyberouter console ↗</a></p>
          </>
        )}

        {step === 2 && (
          <>
            <h2 id="wizard-title">What would you like to check?</h2>
            <p className="wizard-lead">Pick one to begin. You can always switch later from the menu.</p>
            <div className="wizard-choices">
              <button type="button" className="wizard-choice" onClick={() => onChoose("website")}>
                <strong>Check my website</strong>
                <span>A public or staging address. Safe read-only scan.</span>
              </button>
              <button type="button" className="wizard-choice" onClick={() => onChoose("repositories")}>
                <strong>Check my code</strong>
                <span>A GitHub repository. Read-only review.</span>
              </button>
            </div>
            <div className="wizard-actions">
              <button type="button" className="ghost" onClick={onClose}>Look around first</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
