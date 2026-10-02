"use client";
// Adapted from useLayouts Dynamic Toolbar with fixed geometry and visible labels.
export default function UseLayoutsDynamicToolbar({ onCopy, onDownload, onClear, onCopyMcp, copiedReport, copiedMcp }) {
  return <div className="ul-dynamic-toolbar" role="group" aria-label="Report actions"><button type="button" className="ghost" onClick={onCopy} aria-live="polite">{copiedReport ? "Copied" : "Copy"}</button><button type="button" className="ghost" onClick={onDownload}>Download</button><details className="report-more"><summary>More</summary><div><button type="button" onClick={onCopyMcp} aria-live="polite">{copiedMcp ? "Endpoint copied" : "Copy MCP endpoint"}</button><button type="button" className="danger-action" onClick={onClear}>Clear report</button></div></details></div>;
}
