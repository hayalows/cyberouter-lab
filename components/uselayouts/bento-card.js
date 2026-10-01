"use client";

import { AnimatePresence, LayoutGroup, motion, useReducedMotion } from "motion/react";
import { HugeiconsIcon } from "@hugeicons/react";
import {
  DashboardSquare01Icon,
  Folder02Icon,
  Settings02Icon,
  CircleArrowUpRight02Icon,
  BarChartIcon,
  File01Icon,
} from "@hugeicons/core-free-icons";
import { useMemo, useState } from "react";

export default function UseLayoutsBentoCard({ connected, model, repoName, siteTarget, onNavigate }) {
  const reduceMotion = useReducedMotion();
  const tabs = [
    {
      id: "connection",
      label: "Model",
      icon: Settings02Icon,
      header: connected ? "Cyberouter connected" : "Connection required",
      description: connected ? (model || "Model available") : "Add your Cyberouter API key to start.",
      badge: connected ? "ON" : "OFF",
    },
    {
      id: "repositories",
      label: "Source",
      icon: Folder02Icon,
      header: repoName || "No repository loaded",
      description: repoName ? "Ready for quick scan, deep audit, or PR review." : "Map a GitHub repository and choose the files that matter.",
      badge: repoName ? "READY" : undefined,
    },
    {
      id: "website",
      label: "Website",
      icon: DashboardSquare01Icon,
      header: siteTarget || "No target loaded",
      description: siteTarget ? "Ready for bounded live-surface checks." : "Assess a public or staging URL with ownership-gated active checks.",
      badge: siteTarget ? "READY" : undefined,
    },
  ];

  const [activeId, setActiveId] = useState(tabs[0].id);
  const active = tabs.find((tab) => tab.id === activeId) || tabs[0];

  const metric = useMemo(() => {
    if (active.id === "connection") return { value: connected ? "Ready" : "Setup", label: connected ? "model access" : "connect first", icon: BarChartIcon };
    if (active.id === "repositories") return { value: repoName ? "Mapped" : "Idle", label: repoName ? "source context" : "no repository", icon: Folder02Icon };
    return { value: siteTarget ? "Scoped" : "Idle", label: siteTarget ? "live target" : "no website", icon: File01Icon };
  }, [active.id, connected, repoName, siteTarget]);

  return (
    <section className="ul-bento-card" aria-label="Workspace overview">
      <div className="ul-bento-copy">
        <span>Security workspace</span>
        <strong>Keep source, live-surface evidence, and model context in one place.</strong>
      </div>

      <div className="ul-bento-stage">
        <div className="ul-bento-backdrop" />
        <div className="ul-bento-window">
          <div className="ul-bento-windowbar">
            <span /><span /><span />
            <small>Workspace</small>
          </div>
          <div className="ul-bento-body">
            <LayoutGroup>
              <aside className="ul-bento-sidebar">
                {tabs.map((tab) => {
                  const selected = active.id === tab.id;
                  return (
                    <button key={tab.id} type="button" onClick={() => setActiveId(tab.id)} className={selected ? "active" : ""}>
                      <HugeiconsIcon icon={tab.icon} width={14} height={14} />
                      <span>{tab.label}</span>
                      {tab.badge && <small>{tab.badge}</small>}
                      {selected && <motion.i layoutId="ul-bento-pill" transition={reduceMotion ? { duration: 0 } : { duration: 0.18, ease: [0.22, 1, 0.36, 1] }} />}
                      {selected && <motion.b layoutId="ul-bento-bg" transition={reduceMotion ? { duration: 0 } : { duration: 0.18, ease: [0.22, 1, 0.36, 1] }} />}
                    </button>
                  );
                })}
              </aside>
            </LayoutGroup>

            <div className="ul-bento-content">
              <header>
                <h3>{active.header}</h3>
                <p>{active.description}</p>
              </header>

              <AnimatePresence mode="popLayout" initial={false}>
                <motion.div
                  key={active.id}
                  className="ul-bento-content-card"
                  initial={reduceMotion ? false : { opacity: 0, y: 4, filter: "blur(2px)" }}
                  animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
                  exit={reduceMotion ? undefined : { opacity: 0, y: -4, filter: "blur(2px)" }}
                  transition={reduceMotion ? { duration: 0 } : { duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
                >
                  <div>
                    <span>{metric.label}</span>
                    <strong>{metric.value}</strong>
                  </div>
                  <HugeiconsIcon icon={metric.icon} width={24} height={24} />
                </motion.div>
              </AnimatePresence>

              <button type="button" className="ul-bento-open" onClick={() => onNavigate?.(active.id)}>
                Open {active.label.toLowerCase()}
                <HugeiconsIcon icon={CircleArrowUpRight02Icon} width={14} height={14} />
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
