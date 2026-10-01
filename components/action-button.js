"use client";

import { AnimatePresence, motion, useReducedMotion } from "motion/react";

export default function ActionButton({
  busy = false,
  idleLabel,
  busyLabel = "Working…",
  disabled = false,
  onClick,
  className = "",
  type = "button",
}) {
  const reduceMotion = useReducedMotion();
  const label = busy ? busyLabel : idleLabel;

  return (
    <motion.button
      type={type}
      className={`primary status-action ${className}`.trim()}
      disabled={disabled || busy}
      onClick={onClick}
      whileTap={reduceMotion || disabled || busy ? undefined : { scale: 0.985 }}
      transition={{ duration: 0.12 }}
      aria-busy={busy || undefined}
    >
      <span className="status-action-inner">
        <AnimatePresence mode="popLayout" initial={false}>
          <motion.span
            key={label}
            className="status-action-label"
            initial={reduceMotion ? false : { opacity: 0, y: 5, filter: "blur(3px)" }}
            animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
            exit={reduceMotion ? undefined : { opacity: 0, y: -5, filter: "blur(3px)" }}
            transition={{ duration: reduceMotion ? 0 : 0.16 }}
          >
            {label}
          </motion.span>
        </AnimatePresence>
        <span className={busy ? "status-action-orbit busy" : "status-action-orbit"} aria-hidden="true">
          <span />
        </span>
      </span>
    </motion.button>
  );
}
