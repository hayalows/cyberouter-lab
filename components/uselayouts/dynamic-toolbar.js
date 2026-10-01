"use client";

import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import useMeasure from "react-use-measure";
import { HugeiconsIcon } from "@hugeicons/react";
import {
  InboxIcon,
  Archive02Icon,
  ArrowReloadHorizontalIcon,
  Delete02Icon,
  ArrowRight01Icon,
  ArrowLeft01Icon,
  Message01Icon,
} from "@hugeicons/core-free-icons";

function Tool({ icon, label, onClick, danger = false, blurred = false }) {
  return (
    <button type="button" className={`ul-toolbar-tool ${danger ? "danger" : ""}`} title={label} aria-label={label} onClick={onClick}>
      <motion.span animate={{ filter: blurred ? "blur(1px)" : "blur(0px)" }}>
        <HugeiconsIcon icon={icon} width={20} height={20} />
      </motion.span>
    </button>
  );
}

export default function UseLayoutsDynamicToolbar({ onCopy, onDownload, onClear, onCopyMcp }) {
  const [expanded, setExpanded] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [primaryRef, primaryBounds] = useMeasure();
  const [secondaryRef, secondaryBounds] = useMeasure();
  const reduceMotion = useReducedMotion();

  useEffect(() => setMounted(true), []);

  const hasMeasurements = primaryBounds.width > 0;
  const width = expanded ? secondaryBounds.width : primaryBounds.width;
  const transition = reduceMotion || !mounted ? { duration: 0 } : {
    type: "spring",
    stiffness: 200,
    damping: 20,
    mass: 0.8,
    bounce: 0.9,
    duration: expanded ? 0.4 : 1.2,
    delay: expanded ? 0 : 0.015,
  };

  return (
    <motion.div
      className="ul-dynamic-toolbar"
      initial={{ width: hasMeasurements ? primaryBounds.width : "auto" }}
      animate={hasMeasurements ? { width } : undefined}
      transition={transition}
    >
      <motion.div
        className="ul-dynamic-toolbar-track"
        initial={false}
        animate={{ x: expanded ? -primaryBounds.width : 0 }}
        transition={transition}
      >
        <div ref={primaryRef} className="ul-dynamic-toolbar-panel">
          <Tool icon={InboxIcon} label="Copy report" onClick={onCopy} blurred={expanded} />
          <Tool icon={Archive02Icon} label="Download report" onClick={onDownload} blurred={expanded} />
          <Tool icon={Message01Icon} label="Copy MCP endpoint" onClick={onCopyMcp} blurred={expanded} />
          <motion.button type="button" className="ul-toolbar-next" whileTap={{ scale: 0.9 }} onClick={() => setExpanded(true)} aria-label="More report actions">
            <HugeiconsIcon icon={ArrowRight01Icon} width={22} height={22} />
          </motion.button>
        </div>
        <div
          ref={secondaryRef}
          className="ul-dynamic-toolbar-panel secondary"
          style={{
            position: expanded ? "relative" : "absolute",
            opacity: expanded ? 1 : 0,
            pointerEvents: expanded ? "auto" : "none",
          }}
        >
          <motion.button type="button" className="ul-toolbar-next" whileTap={{ scale: 0.9 }} onClick={() => setExpanded(false)} aria-label="Back to primary report actions">
            <HugeiconsIcon icon={ArrowLeft01Icon} width={22} height={22} />
          </motion.button>
          <Tool icon={ArrowReloadHorizontalIcon} label="Back to report actions" onClick={() => setExpanded(false)} blurred={!expanded} />
          <Tool icon={Delete02Icon} label="Clear report" onClick={onClear} danger blurred={!expanded} />
        </div>
      </motion.div>
    </motion.div>
  );
}
