"use client";
import { GRADE_LABEL } from "@/lib/plain-language";
import { WORKSPACE_ITEMS, WorkspaceIcon } from "@/components/uselayouts/discrete-tabs";
const GRADE_TONE = { A: "great", B: "good", C: "warn", D: "bad", F: "bad" };

export function SimpleHome({ connected, onChoose, onConnect, onSetup }) {
  const cards = [
    { id: "repositories", title: "Review your code", text: "Connect a GitHub repository. Review important files or investigate the whole supported codebase.", meta: "Read-only · pinned source", action: "Open code review" },
    { id: "website", title: "Check your website", text: "Inspect public pages, headers, cookies, and forms. Expand coverage after verifying ownership.", meta: "Bounded checks · clear scope", action: "Open website checks" },
  ];
  return <section className="simple-home" aria-label="Start a security review">
    <div className="home-section-heading"><h2>Start a review</h2><button type="button" className="text-button" onClick={onSetup}>Setup guide</button></div>
    <div className="simple-home-actions">{cards.map(card => <button type="button" className="big-action" key={card.id} onClick={() => onChoose(card.id)}><span className="home-task-icon"><WorkspaceIcon path={WORKSPACE_ITEMS.find(i => i.id === card.id).icon} size={22} /></span><strong>{card.title}</strong><span>{card.text}</span><small>{card.meta}</small><b>{card.action} <span aria-hidden="true">→</span></b></button>)}</div>
    {!connected && <div className="simple-home-hint"><div><strong>Connect a model for AI reviews</strong><p>Use your own Cyberouter key. Research, local tools, and evidence management are available without it.</p></div><button type="button" className="primary" onClick={onConnect}>Connect model</button></div>}
    <div className="home-section-heading home-tools-heading"><h2>Work with evidence</h2><span>No model required to get started</span></div>
    <div className="home-tool-grid"><button type="button" className="home-tool" onClick={() => onChoose("casebook")}><WorkspaceIcon path={WORKSPACE_ITEMS.find(i => i.id === "casebook").icon} /><span><strong>Findings & evidence</strong><small>Import scanner reports, prioritize findings, and track fixes.</small></span><span aria-hidden="true">→</span></button><button type="button" className="home-tool" onClick={() => onChoose("research")}><WorkspaceIcon path={WORKSPACE_ITEMS.find(i => i.id === "research").icon} /><span><strong>Investigate</strong><small>Connect related repositories and free vulnerability intelligence.</small></span><span aria-hidden="true">→</span></button></div>
    <div className="home-method"><strong>A clear path from review to action</strong><ol><li><span>1</span>Choose a target</li><li><span>2</span>Review evidence and coverage</li><li><span>3</span>Prioritize and verify fixes</li></ol><p>Checks are bounded and read-only. Source coverage and model output do not guarantee that every issue has been found.</p></div>
  </section>;
}

export function ScoreCard({ report, onExplain, explaining, onPrint, onCapture, captureBusy, canCapture, includeTechnical, onToggleTechnical }) {
  if (!report) return null;
  const tone = GRADE_TONE[report.grade] || "good";
  return (
    <div className={`score-card tone-${tone}`}>
      <div className="score-head">
        <div className="score-dial" aria-label={`Observed-check score: ${report.score} out of 100`}>
          <strong>{report.score}</strong>
          <span>check score</span>
        </div>
        <div className="score-verdict">
          <span className="score-grade">Observed checks · grade {report.grade} · {GRADE_LABEL[report.grade] || ""}</span>
          <h3>{report.total === 0 ? "No common problems found" : `${report.total} thing${report.total === 1 ? "" : "s"} to look at`}</h3>
          <p>{report.verdict}</p>
        </div>
      </div>

      <p className="score-scope">Based on findings in {report.pagesScanned || 0} checked page{report.pagesScanned === 1 ? "" : "s"}. This score is a triage aid, not a measure of the whole site’s security. Untested and authenticated areas remain unknown.</p>
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
