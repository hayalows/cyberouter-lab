"use client";

import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { HugeiconsIcon } from "@hugeicons/react";
import { Tick02Icon } from "@hugeicons/core-free-icons";
import { useEffect, useMemo, useRef, useState } from "react";

export default function UseLayoutsStatusButton({
  busy = false,
  disabled = false,
  idleLabel,
  busyLabel = "Working",
  successLabel = "Done",
  onClick,
  className = "",
}) {
  const reduceMotion = useReducedMotion();
  const previousBusy = useRef(false);
  const [showSuccess, setShowSuccess] = useState(false);

  useEffect(() => {
    let timer;
    if (previousBusy.current && !busy) {
      setShowSuccess(true);
      timer = setTimeout(() => setShowSuccess(false), 1200);
    }
    previousBusy.current = busy;
    return () => clearTimeout(timer);
  }, [busy]);

  const state = busy ? "loading" : showSuccess ? "success" : "idle";
  const text = useMemo(() => state === "loading" ? busyLabel : state === "success" ? successLabel : idleLabel, [state, busyLabel, successLabel, idleLabel]);

  return (
    <div className={`ul-status-wrap ${className}`.trim()}>
      <motion.button
        type="button"
        className={`ul-status-button ${state !== "idle" ? "working" : ""}`}
        disabled={disabled || busy}
        onClick={onClick}
        whileTap={reduceMotion || disabled || busy ? undefined : { scale: 0.985 }}
        aria-busy={busy || undefined}
      >
        <span className="ul-status-text" aria-live="polite">
          <AnimatePresence mode="popLayout" initial={false}>
            {String(text || "").split("").map((char, index) => (
              <motion.span
                key={`${char}-${index}-${state}`}
                layout
                initial={reduceMotion ? false : { opacity: 0, scale: 0, filter: "blur(4px)" }}
                animate={{ opacity: 1, scale: 1, filter: "blur(0px)" }}
                exit={reduceMotion ? undefined : { opacity: 0, scale: 0, filter: "blur(4px)" }}
                transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 500, damping: 30, mass: 1 }}
              >
                {char === " " ? "\u00A0" : char}
              </motion.span>
            ))}
          </AnimatePresence>
        </span>
      </motion.button>

      <AnimatePresence mode="wait">
        {state !== "idle" && (
          <motion.span
            className={`ul-status-indicator ${state}`}
            initial={reduceMotion ? false : { opacity: 0, scale: 0, x: -8, filter: "blur(4px)" }}
            animate={{ opacity: 1, scale: 1, x: 0, filter: "blur(0px)" }}
            exit={reduceMotion ? undefined : { opacity: 0, scale: 0, x: -8, filter: "blur(4px)" }}
            transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 300, damping: 20 }}
            aria-hidden="true"
          >
            {state === "loading" ? (
              <svg width="20" height="20" viewBox="0 0 24 24">
                <path fill="currentColor" d="M12 2A10 10 0 1 0 22 12A10 10 0 0 0 12 2Zm0 18a8 8 0 1 1 8-8A8 8 0 0 1 12 20Z" opacity=".45" />
                <path fill="currentColor" d="M20 12h2A10 10 0 0 0 12 2V4A8 8 0 0 1 20 12Z">
                  <animateTransform attributeName="transform" dur="1s" from="0 12 12" repeatCount="indefinite" to="360 12 12" type="rotate" />
                </path>
              </svg>
            ) : (
              <HugeiconsIcon icon={Tick02Icon} width={15} height={15} />
            )}
          </motion.span>
        )}
      </AnimatePresence>
    </div>
  );
}
