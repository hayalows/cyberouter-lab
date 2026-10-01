"use client";

import { motion, useReducedMotion } from "motion/react";

function Card({ eyebrow, value, detail, state = "neutral", onClick, action }) {
  const reduceMotion = useReducedMotion();
  return (
    <motion.button
      type="button"
      className={`overview-card ${state}`}
      onClick={onClick}
      whileHover={reduceMotion ? undefined : { y: -2 }}
      whileTap={reduceMotion ? undefined : { scale: 0.99 }}
      transition={{ type: "spring", stiffness: 360, damping: 28 }}
    >
      <span className="overview-card-top">
        <span className="overview-eyebrow">{eyebrow}</span>
        <span className="overview-arrow" aria-hidden="true">↗</span>
      </span>
      <strong>{value}</strong>
      <span className="overview-detail">{detail}</span>
      <span className="overview-action">{action}</span>
    </motion.button>
  );
}

export default function WorkspaceOverview({
  connected,
  model,
  repoName,
  siteTarget,
  onNavigate,
}) {
  return (
    <section className="overview-grid" aria-label="Workspace status">
      <Card
        eyebrow="Cyberouter"
        value={connected ? "Connected" : "Not connected"}
        detail={connected ? (model || "Model available") : "Add your API key to start"}
        state={connected ? "good" : "attention"}
        action={connected ? "Manage connection" : "Connect"}
        onClick={() => onNavigate("connection")}
      />
      <Card
        eyebrow="Source"
        value={repoName || "No repository"}
        detail={repoName ? "Ready for quick, deep, or PR review" : "Map a GitHub codebase"}
        action={repoName ? "Open repository" : "Choose repository"}
        onClick={() => onNavigate("repositories")}
      />
      <Card
        eyebrow="Live target"
        value={siteTarget || "No website"}
        detail={siteTarget ? "Ready for bounded web testing" : "Assess a public or staging URL"}
        action={siteTarget ? "Open website scan" : "Add website"}
        onClick={() => onNavigate("website")}
      />
      <Card
        eyebrow="Workflow"
        value="Code + web"
        detail="Correlate source findings with live evidence"
        action="Run focused task"
        onClick={() => onNavigate(repoName ? "repositories" : "website")}
      />
    </section>
  );
}
