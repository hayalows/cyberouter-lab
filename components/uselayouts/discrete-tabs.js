"use client";

import { motion, useReducedMotion } from "motion/react";
import { HugeiconsIcon } from "@hugeicons/react";
import {
  Folder02Icon,
  DashboardSquare01Icon,
  Message01Icon,
  Settings02Icon,
  File01Icon,
} from "@hugeicons/core-free-icons";

const DEFAULT_ITEMS = [
  { id: "repositories", label: "Repositories", hint: "Source", icon: Folder02Icon },
  { id: "website", label: "Website", hint: "Live", icon: DashboardSquare01Icon },
  { id: "playground", label: "Playground", hint: "Prompt", icon: Message01Icon },
  { id: "casebook", label: "Casebook", hint: "Act & verify", icon: File01Icon },
  { id: "research", label: "Investigate", hint: "Connect", icon: DashboardSquare01Icon },
  { id: "connection", label: "Connection", hint: "Setup", icon: Settings02Icon },
];

export default function UseLayoutsDiscreteTabs({ value, onChange, items = DEFAULT_ITEMS }) {
  const reduceMotion = useReducedMotion();

  return (
    <nav className="ul-discrete-tabs" aria-label="Main workspace">
      {items.map((item) => {
        const active = value === item.id;
        return (
          <motion.button
            key={item.id}
            type="button"
            className={`ul-discrete-tab ${active ? "active" : ""}`}
            aria-label={item.label}
            aria-current={active ? "page" : undefined}
            onClick={() => onChange(item.id)}
            layout
            transition={reduceMotion ? { duration: 0 } : {
              layout: {
                duration: 0.18,
                ease: [0.22, 1, 0.36, 1],
              },
            }}
          >
            <motion.span
              layoutId={`ul-discrete-icon-${item.id}`}
              className="ul-discrete-tab-icon"
            >
              <HugeiconsIcon icon={item.icon} width={18} height={18} />
            </motion.span>
            {(
              <motion.span
                className="ul-discrete-tab-label"
                initial={reduceMotion ? false : { opacity: 0, filter: "blur(2px)" }}
                animate={{ opacity: 1, filter: "blur(0px)" }}
                transition={reduceMotion ? { duration: 0 } : { duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
              >
                <strong>{item.label}</strong>
                {active && <small>{item.hint}</small>}
              </motion.span>
            )}
          </motion.button>
        );
      })}
    </nav>
  );
}
