import React, { useCallback, useState } from "react";

// Side panel widths the person drags to taste. Kept in this browser only: it is
// a per-viewer convenience, never part of a topology.
// One width for the right panel, whichever tab is open, so switching between
// Inspector and Export never jumps.
export const PANEL_DEFAULTS = { palette: 250, right: 480 };
export const PANEL_LIMITS = {
  palette: [200, 520],
  right: [320, 960],
};
const KEY = "rsp.panelWidths";
const STEP = 16;

export function clampWidth(panel, width) {
  const [min, max] = PANEL_LIMITS[panel];
  return Math.round(Math.min(max, Math.max(min, width)));
}

function load() {
  try {
    const saved = JSON.parse(window.localStorage.getItem(KEY) || "{}");
    const out = { ...PANEL_DEFAULTS };
    for (const panel of Object.keys(PANEL_DEFAULTS)) {
      if (Number.isFinite(saved[panel])) out[panel] = clampWidth(panel, saved[panel]);
    }
    return out;
  } catch {
    return { ...PANEL_DEFAULTS };
  }
}

function save(widths) {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(widths));
  } catch {
    // Private windows and blocked storage: the widths just do not persist.
  }
}

export function usePanelWidths() {
  const [widths, setWidths] = useState(load);
  const setWidth = useCallback((panel, width) => {
    setWidths((cur) => {
      const next = { ...cur, [panel]: clampWidth(panel, width) };
      save(next);
      return next;
    });
  }, []);
  const reset = useCallback((panel) => setWidth(panel, PANEL_DEFAULTS[panel]), [setWidth]);
  return { widths, setWidth, reset };
}

// A drag handle on a panel's inner edge. `side` is the panel's side of the
// canvas: a left panel grows as the handle moves right, a right panel as it
// moves left. Width is measured from the body's edge, so it tracks the pointer.
export function PanelResizer({ side, panel, width, label, onResize, onReset }) {
  const [dragging, setDragging] = useState(false);

  const onPointerDown = (event) => {
    if (event.button !== 0) return;
    event.preventDefault();
    const handle = event.currentTarget;
    const body = handle.parentElement.getBoundingClientRect();
    handle.setPointerCapture(event.pointerId);
    setDragging(true);
    const move = (ev) => {
      onResize(panel, side === "left" ? ev.clientX - body.left : body.right - ev.clientX);
    };
    const up = (ev) => {
      handle.releasePointerCapture(ev.pointerId);
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", up);
      handle.removeEventListener("pointercancel", up);
      setDragging(false);
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up);
    handle.addEventListener("pointercancel", up);
  };

  const onKeyDown = (event) => {
    const grow = side === "left" ? "ArrowRight" : "ArrowLeft";
    const shrink = side === "left" ? "ArrowLeft" : "ArrowRight";
    if (event.key === grow) onResize(panel, width + STEP);
    else if (event.key === shrink) onResize(panel, width - STEP);
    else if (event.key === "Home") onReset(panel);
    else return;
    event.preventDefault();
  };

  const [min, max] = PANEL_LIMITS[panel];
  return (
    <div
      className={`rg-resizer is-${side}${dragging ? " is-dragging" : ""}`}
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      aria-valuenow={width}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      title={`${label}. Drag to resize, double-click to reset.`}
      onPointerDown={onPointerDown}
      onDoubleClick={() => onReset(panel)}
      onKeyDown={onKeyDown}
    />
  );
}
