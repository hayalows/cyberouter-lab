"use client";

import { motion, useReducedMotion } from "motion/react";

const ITEMS = [
  { id: "repositories", label: "Repositories", hint: "Source" },
  { id: "website", label: "Website", hint: "Live" },
  { id: "playground", label: "Playground", hint: "Prompt" },
  { id: "connection", label: "Connection", hint: "Setup" },
];

export default function WorkspaceTabs({ value, onChange }) {
  const reduceMotion = useReducedMotion();

  return (
    <nav className="workspace-tabs" aria-label="Cyberouter workspace" role="tablist">
      {ITEMS.map((item) => {
        const active = value === item.id;
        return (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={active}
            className={active ? "workspace-tab active" : "workspace-tab"}
            onClick={() => onChange(item.id)}
          >
            {active && (
              <motion.span
                aria-hidden="true"
                className="workspace-tab-indicator"
                layoutId="workspace-tab-indicator"
                transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 420, damping: 34, mass: 0.7 }}
              />
            )}
            <span className="workspace-tab-copy">
              <span>{item.label}</span>
              <small>{item.hint}</small>
            </span>
          </button>
        );
      })}
    </nav>
  );
}
