"use client";
import { useEffect, useRef, useState } from "react";
import Navigation, { WORKSPACE_ITEMS } from "@/components/uselayouts/discrete-tabs";
export function useWorkspaceNavigation() {
  const [surface, updateSurface] = useState("home");
  useEffect(() => {
    const readLocation = () => {
      const target = window.location.hash.slice(1) || "home";
      updateSurface(WORKSPACE_ITEMS.some(item => item.id === target) ? target : "home");
    };
    readLocation();
    window.addEventListener("popstate", readLocation);
    window.addEventListener("hashchange", readLocation);
    return () => { window.removeEventListener("popstate", readLocation); window.removeEventListener("hashchange", readLocation); };
  }, []);
  function navigate(target) {
    if (!WORKSPACE_ITEMS.some(item => item.id === target)) return;
    if (window.location.hash !== `#${target}`) window.history.pushState(null, "", `#${target}`);
    updateSurface(target);
  }
  return [surface, navigate];
}
export default function WorkspaceShell({ children, surface, onNavigate, viewMode, onViewMode, connected, status, backgroundTask, onOpenTask }) {
  const previousSurface = useRef(surface);
  useEffect(() => {
    if (previousSurface.current !== surface) {
      previousSurface.current = surface;
      window.scrollTo({ top: 0, behavior: "instant" });
      document.getElementById("page-title")?.focus({ preventScroll: true });
    }
  }, [surface]);
  return <div className="app-shell">
    <a className="skip-link" href="#workspace-content">Skip to workspace</a>
    <aside className="app-sidebar" aria-label="Workspace navigation">
      <button className="brand brand-link" onClick={() => onNavigate("home")} aria-label="Cyberouter Lab home"><span className="mark">C</span><span><span className="brand-title">Cyberouter Lab</span><span className="brand-sub">Security workspace</span></span></button>
      <Navigation value={surface} onChange={onNavigate} />
      <div className="sidebar-foot"><span className="sidebar-note">Read-only by design</span><p>Evidence first. Verify before you act.</p></div>
    </aside>
    <div className="app-main">
      <header className="app-topbar">
        <span className="workspace-location">Workspace <span aria-hidden="true">/</span> <strong>{WORKSPACE_ITEMS.find(i => i.id === surface)?.label}</strong></span>
        <div className="topbar-actions">
          <div className="view-toggle" role="group" aria-label="Interface detail level">{["simple", "expert"].map(mode => <button key={mode} aria-pressed={viewMode === mode} className={viewMode === mode ? "active" : ""} onClick={() => onViewMode(mode)}>{mode === "simple" ? "Simple" : "Expert"}</button>)}</div>
          <button className={`status-pill ${backgroundTask ? "active-job" : connected ? "ok" : ""}`} onClick={backgroundTask ? onOpenTask : () => onNavigate("connection")} aria-label={backgroundTask ? `${backgroundTask}. Open the active task` : `${status}. Open connection settings`} title={backgroundTask || status} aria-live="polite"><span className="status-dot" /><span>{backgroundTask ? backgroundTask.startsWith("Deep") ? "Audit running" : backgroundTask.startsWith("Website crawl") ? "Crawl running" : backgroundTask.startsWith("Code") ? "Review running" : backgroundTask.startsWith("Website") ? "Check running" : "Model request" : connected ? "Connected" : "Connect model"}</span></button>
        </div>
        <label className="mobile-navigation"><span className="sr-only">Go to workspace</span><select value={surface} onChange={e => onNavigate(e.target.value)}>{WORKSPACE_ITEMS.map(i => <option key={i.id} value={i.id}>{i.label}</option>)}</select></label>
      </header>
      <main id="workspace-content" className="shell" tabIndex={-1}>{children}</main>
    </div>
  </div>;
}
