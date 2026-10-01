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
        eyebrow="MODEL CONNECTION"
        value={connected ? "Ready" : "Needs setup"}
        detail={connected ? (model || "Choose a model for your review") : "Connect your key to run an analysis"}
        state={connected ? "good" : "attention"}
        action={connected ? "Manage models" : "Connect a key"}
        onClick={() => onNavigate("connection")}
      />
      <Card
        eyebrow="SOURCE REVIEW"
        value={repoName || "No repository loaded"}
        detail={repoName ? "Quick scan, deep audit, or PR review" : "Map a GitHub repository"}
        action={repoName ? "Open source review" : "Load a repository"}
        onClick={() => onNavigate("repositories")}
      />
      <Card
        eyebrow="WEB ASSESSMENT"
        value={siteTarget || "No target loaded"}
        detail={siteTarget ? "Bounded checks for this public target" : "Assess a public or staging URL"}
        action={siteTarget ? "Open website assessment" : "Add a target"}
        onClick={() => onNavigate("website")}
      />
    </section>
  );
}
