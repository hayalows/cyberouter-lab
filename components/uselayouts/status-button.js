"use client";
// Completion can mean success or failure. The workflow owns outcome feedback.
export default function UseLayoutsStatusButton({ busy = false, disabled = false, idleLabel, busyLabel = "Working…", onClick, className = "" }) {
  return <div className={`ul-status-wrap ${className}`}><button type="button" className="primary ul-status-button" disabled={disabled || busy} onClick={onClick} aria-busy={busy || undefined}><span className="button-progress" aria-hidden="true">{busy ? <span className="busy-dot" /> : "→"}</span><span>{busy ? busyLabel : idleLabel}</span></button></div>;
}
