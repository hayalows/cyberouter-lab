"use client";

import { motion, useReducedMotion } from "motion/react";
import { HugeiconsIcon } from "@hugeicons/react";
import {
  Folder02Icon,
  DashboardSquare01Icon,
  Message01Icon,
  Settings02Icon,
} from "@hugeicons/core-free-icons";

const DEFAULT_ITEMS = [
  { id: "repositories", label: "Repositories", hint: "Source", icon: Folder02Icon },
  { id: "website", label: "Website", hint: "Live", icon: DashboardSquare01Icon },
  { id: "playground", label: "Playground", hint: "Prompt", icon: Message01Icon },
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
            aria-current={active ? "page" : undefined}
            onClick={() => onChange(item.id)}
            layout
            transition={reduceMotion ? { duration: 0 } : {
              layout: {
                type: "spring",
                damping: 20,
                stiffness: 230,
                mass: 1.2,
              },
            }}
          >
            <motion.span
              layoutId={`ul-discrete-icon-${item.id}`}
              className="ul-discrete-tab-icon"
            >
              <HugeiconsIcon icon={item.icon} width={18} height={18} />
            </motion.span>
            {active && (
              <motion.span
                className="ul-discrete-tab-label"
                initial={reduceMotion ? false : { opacity: 0, filter: "blur(4px)" }}
                animate={{ opacity: 1, filter: "blur(0px)" }}
                transition={reduceMotion ? { duration: 0 } : { duration: 0.2, ease: [0.86, 0, 0.07, 1] }}
              >
                <strong>{item.label}</strong>
                <small>{item.hint}</small>
              </motion.span>
            )}
          </motion.button>
        );
      })}
    </nav>
  );
}
