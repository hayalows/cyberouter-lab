"use client";

import { useEffect, useRef, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import useMeasure from "react-use-measure";
import { HugeiconsIcon } from "@hugeicons/react";
import {
  FolderIcon,
  File01Icon,
  SettingsIcon,
  HelpCircleIcon,
  MoreHorizontalCircle01Icon,
  Message01Icon,
} from "@hugeicons/core-free-icons";

const easeOutQuint = [0.23, 1, 0.32, 1];

export default function UseLayoutsSmoothDropdown({ onNavigate, onCopyMcp, activeSurface }) {
  const [isOpen, setIsOpen] = useState(false);
  const [hoveredItem, setHoveredItem] = useState(null);
  const containerRef = useRef(null);
  const [contentRef, bounds] = useMeasure();
  const reduceMotion = useReducedMotion();

  const items = [
    { id: "home", label: "Home", icon: FolderIcon },
    { id: "repositories", label: "Repository review", icon: FolderIcon },
    { id: "website", label: "Website assessment", icon: File01Icon },
    { id: "playground", label: "Playground", icon: Message01Icon },
    { id: "casebook", label: "Security casebook", icon: File01Icon },
    { id: "research", label: "Investigate", hint: "Connect", icon: FolderIcon },
    { id: "connection", label: "Connection", icon: SettingsIcon },
    { id: "divider" },
    { id: "mcp", label: "Copy MCP endpoint", icon: HelpCircleIcon },
  ];

  useEffect(() => {
    function outside(event) {
      if (containerRef.current && !containerRef.current.contains(event.target)) setIsOpen(false);
    }
    function keydown(event) {
      if (event.key === "Escape") setIsOpen(false);
    }
    if (isOpen) {
      document.addEventListener("mousedown", outside);
      document.addEventListener("keydown", keydown);
    }
    return () => {
      document.removeEventListener("mousedown", outside);
      document.removeEventListener("keydown", keydown);
    };
  }, [isOpen]);

  const openHeight = Math.max(40, Math.ceil(bounds.height));

  return (
    <div ref={containerRef} className="ul-smooth-dropdown">
      <motion.div
        layout
        initial={false}
        animate={{
          width: isOpen ? 236 : 40,
          height: isOpen ? openHeight : 40,
          borderRadius: isOpen ? 14 : 12,
        }}
        transition={reduceMotion ? { duration: 0 } : { duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
        className="ul-smooth-dropdown-shell"
      >
        <button
          type="button"
          className="ul-smooth-dropdown-trigger"
          aria-label="Open quick menu"
          aria-expanded={isOpen}
          onClick={() => setIsOpen((value) => !value)}
        >
          <motion.span
            animate={{ opacity: isOpen ? 0 : 1, scale: isOpen ? 0.94 : 1 }}
            transition={{ duration: reduceMotion ? 0 : 0.14, ease: [0.22, 1, 0.36, 1] }}
          >
            <HugeiconsIcon icon={MoreHorizontalCircle01Icon} width={22} height={22} />
          </motion.span>
        </button>

        <div ref={contentRef} className="ul-smooth-dropdown-content-wrap">
          <motion.div
            className="ul-smooth-dropdown-content"
            initial={false}
            animate={{ opacity: isOpen ? 1 : 0 }}
            transition={{ duration: reduceMotion ? 0 : 0.2, delay: isOpen && !reduceMotion ? 0.025 : 0 }}
            style={{ pointerEvents: isOpen ? "auto" : "none" }}
          >
            <ul>
              {items.map((item, index) => {
                if (item.id === "divider") return <motion.hr key="divider" initial={{ opacity: 0 }} animate={{ opacity: isOpen ? 1 : 0 }} transition={{ delay: isOpen ? 0.12 : 0 }} />;
                const active = activeSurface === item.id;
                const showIndicator = hoveredItem ? hoveredItem === item.id : active;
                return (
                  <motion.li
                    key={item.id}
                    initial={reduceMotion ? false : { opacity: 0, x: 8 }}
                    animate={{ opacity: isOpen ? 1 : 0, x: isOpen ? 0 : 8 }}
                    transition={{ delay: isOpen && !reduceMotion ? 0.02 + index * 0.012 : 0, duration: reduceMotion ? 0 : 0.13, ease: easeOutQuint }}
                    onMouseEnter={() => setHoveredItem(item.id)}
                    onMouseLeave={() => setHoveredItem(null)}
                  >
                    <button
                      type="button"
                      onClick={() => {
                        if (item.id === "mcp") onCopyMcp?.();
                        else onNavigate?.(item.id);
                        setIsOpen(false);
                      }}
                    >
                      {showIndicator && <motion.span layoutId="ul-dropdown-active" className="ul-smooth-dropdown-active" transition={reduceMotion ? { duration: 0 } : { duration: 0.14, ease: [0.22, 1, 0.36, 1] }} />}
                      {showIndicator && <motion.span layoutId="ul-dropdown-bar" className="ul-smooth-dropdown-bar" transition={reduceMotion ? { duration: 0 } : { duration: 0.14, ease: [0.22, 1, 0.36, 1] }} />}
                      <HugeiconsIcon icon={item.icon} width={18} height={18} />
                      <span>{item.label}</span>
                    </button>
                  </motion.li>
                );
              })}
            </ul>
          </motion.div>
        </div>
      </motion.div>
    </div>
  );
}
