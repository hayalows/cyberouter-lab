"use client";
// Adapted from useLayouts Discrete Tabs. Stable geometry replaces layout motion.
export const WORKSPACE_ITEMS = [
  { id: "home", label: "Overview", icon: "M3 10l9-7 9 7v10H3z M9 20v-7h6v7" },
  { id: "repositories", label: "Code review", icon: "M8 6L2 12l6 6 M16 6l6 6-6 6 M14 3l-4 18" },
  { id: "website", label: "Website checks", icon: "M3 3h18v18H3z M3 8h18 M8 3v5" },
  { id: "casebook", label: "Findings & evidence", icon: "M5 3h10l4 4v14H5z M9 11h6 M9 15h6 M15 3v5h4" },
  { id: "research", label: "Investigate", icon: "M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14 M15 15l6 6" },
  { id: "playground", label: "Model playground", icon: "M3 4h18v13H9l-6 4z M7 8h10 M7 12h6" },
  { id: "connection", label: "Connections", icon: "M8 3v5 M16 3v5 M6 8h12v4a6 6 0 0 1-12 0z M12 18v4" },
];
export function WorkspaceIcon({ path, size = 18 }) { return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={path} /></svg>; }
export default function Navigation({ value, onChange }) {
  return <nav className="ul-discrete-tabs" aria-label="Main workspace">{WORKSPACE_ITEMS.map((item, index) => <div key={item.id}>{index === 0 && <span className="nav-section-label">Workspace</span>}{index === 4 && <span className="nav-section-label">Tools</span>}<button type="button" className={`ul-discrete-tab ${value === item.id ? "active" : ""}`} aria-current={value === item.id ? "page" : undefined} onClick={() => onChange(item.id)}><WorkspaceIcon path={item.icon} /><span>{item.label}</span></button></div>)}</nav>;
}
