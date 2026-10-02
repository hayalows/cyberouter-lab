"use client";

import { GRADE_LABEL } from "@/lib/plain-language";

const GRADE_TONE = { A: "great", B: "good", C: "warn", D: "bad", F: "bad" };

export function SimpleHome({ connected, onChoose, onConnect }) {
  return (
    <section className="simple-home" aria-label="Start a security check">
      <div className="simple-home-actions">
        <button type="button" className="big-action" onClick={() => onChoose("website")}>
          <span className="big-action-emoji" aria-hidden="true">🌐</span>
          <strong>Check my website</strong>
          <span>Is my public site safe for visitors? Takes about a minute.</span>
        </button>
        <button type="button" className="big-action" onClick={() => onChoose("repositories")}>
          <span className="big-action-emoji" aria-hidden="true">📦</span>
          <strong>Check my code</strong>
          <span>Does my GitHub project have security mistakes? Read-only.</span>
        </button>
      </div>

      {!connected && (
        <div className="simple-home-hint" role="status">
          <strong>One quick step first</strong>
          <p>Checks use your own Cyberouter key, kept in this browser. Connect it once and you are set.</p>
          <button type="button" className="primary" onClick={onConnect}>Connect my key</button>
        </div>
      )}

      <div className="simple-steps">
        <div className="simple-step"><span className="simple-step-num">1</span><strong>Pick a check</strong><p>Website or code.</p></div>
        <div className="simple-step"><span className="simple-step-num">2</span><strong>We look safely</strong><p>Read-only. Nothing is changed or attacked.</p></div>
        <div className="simple-step"><span className="simple-step-num">3</span><strong>You get a score</strong><p>0–100, a grade, and what to fix next.</p></div>
      </div>

      <p className="simple-home-note">This is a first-look check, not a full guarantee. It finds common, well-known problems. It cannot prove a site is perfectly safe.</p>
    </section>
  );
}

export function ScoreCard({ report, onExplain, explaining, onPrint, onCapture, captureBusy, canCapture, includeTechnical, onToggleTechnical }) {
  if (!report) return null;
  const tone = GRADE_TONE[report.grade] || "good";
  return (
    <div className={`score-card tone-${tone}`}>
      <div className="score-head">
        <div className="score-dial" aria-hidden="true">
          <strong>{report.score}</strong>
          <span>out of 100</span>
        </div>
        <div className="score-verdict">
          <span className="score-grade">Grade {report.grade} · {GRADE_LABEL[report.grade] || ""}</span>
          <h3>{report.total === 0 ? "No common problems found" : `${report.total} thing${report.total === 1 ? "" : "s"} to look at`}</h3>
          <p>{report.verdict}</p>
        </div>
      </div>

      <div className="score-actions">
        {onExplain && <button type="button" className="ghost" disabled={explaining} onClick={onExplain}>{explaining ? "Writing…" : "Explain simply"}</button>}
        {onPrint && <button type="button" className="ghost" onClick={onPrint}>Print / save PDF</button>}
        {canCapture && <button type="button" className="ghost" disabled={captureBusy} onClick={onCapture}>{captureBusy ? "Saving…" : "Save to casebook"}</button>}
        {onToggleTechnical && <button type="button" className="text-button" onClick={onToggleTechnical}>{includeTechnical ? "Hide technical detail" : "Show technical detail"}</button>}
      </div>

      {report.steps.length > 0 && (
        <div className="next-steps">
          <h4>What to do next</h4>
          <ol>
            {report.steps.map((step, index) => (
              <li key={`${step.title}-${index}`}>
                <strong>{step.title}</strong>
                <span>{step.fix}</span>
                <em>{step.effort}</em>
              </li>
            ))}
          </ol>
        </div>
      )}

      {report.findings.length > 0 && (
        <details className="plain-findings">
          <summary>See every finding in plain words ({report.findings.length})</summary>
          <ul>
            {report.findings.map((item, index) => (
              <li key={`${item.id}-${index}`}>
                <div className="plain-finding-head">
                  <strong>{item.title}</strong>
                  <span className={`sev-dot sev-${item.severity.toLowerCase()}`}>{item.severity}</span>
                </div>
                <p className="plain-meaning">{item.meaning}</p>
                <p className="plain-fix"><b>What to do:</b> {item.fix}</p>
                {includeTechnical && (
                  <dl className="plain-technical">
                    <dt>Category</dt><dd>{item.technical.category}</dd>
                    {item.technical.page && <><dt>Page</dt><dd>{item.technical.page}</dd></>}
                    {item.technical.evidence && <><dt>Evidence</dt><dd>{item.technical.evidence}</dd></>}
                    {item.technical.confidence && <><dt>Confidence</dt><dd>{item.technical.confidence}</dd></>}
                    {item.technical.reference && <><dt>Reference</dt><dd>{item.technical.reference}</dd></>}
                  </dl>
                )}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
