import React from "react";
import { beforeEach, describe, expect, test } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import {
  CANVAS_MIN, PANEL_LIMITS, PanelResizer, clampWidth, defaultWidths, usePanelWidths,
} from "./PanelResizer.jsx";

const PANEL_DEFAULTS = defaultWidths();

function Harness() {
  const { widths, setWidth, reset } = usePanelWidths();
  return (
    <div>
      <PanelResizer side="left" panel="palette" width={widths.palette}
        label="Resize the palette" onResize={setWidth} onReset={reset} />
      <PanelResizer side="right" panel="right" width={widths.right}
        label="Resize the side panel" onResize={setWidth} onReset={reset} />
    </div>
  );
}

const handle = (name) => screen.getByRole("separator", { name });
const now = (name) => Number(handle(name).getAttribute("aria-valuenow"));

describe("side panel resizing", () => {
  beforeEach(() => window.localStorage.clear());

  test("panels open at their widest when the screen has room", () => {
    expect(defaultWidths(2560)).toEqual({ palette: PANEL_LIMITS.palette[1], right: PANEL_LIMITS.right[1] });
  });

  test("on a narrower screen both shrink together and the canvas keeps its minimum", () => {
    for (const vw of [1920, 1438, 1280, 1100]) {
      const w = defaultWidths(vw);
      expect(w.palette + w.right).toBeLessThanOrEqual(vw - CANVAS_MIN + 1);
      expect(w.palette).toBeGreaterThanOrEqual(PANEL_LIMITS.palette[0]);
      expect(w.right).toBeGreaterThanOrEqual(PANEL_LIMITS.right[0]);
      expect(w.right).toBeGreaterThan(w.palette);
    }
  });

  test("starts at the defaults, one right width for both tabs", () => {
    render(<Harness />);
    expect(now("Resize the palette")).toBe(PANEL_DEFAULTS.palette);
    expect(now("Resize the side panel")).toBe(PANEL_DEFAULTS.right);
  });

  test("arrow keys grow toward the canvas and shrink away from it", () => {
    render(<Harness />);
    fireEvent.keyDown(handle("Resize the palette"), { key: "ArrowRight" });
    expect(now("Resize the palette")).toBe(PANEL_DEFAULTS.palette + 16);
    // The right panel grows as its handle moves left.
    fireEvent.keyDown(handle("Resize the side panel"), { key: "ArrowLeft" });
    expect(now("Resize the side panel")).toBe(PANEL_DEFAULTS.right + 16);
    fireEvent.keyDown(handle("Resize the side panel"), { key: "ArrowRight" });
    fireEvent.keyDown(handle("Resize the side panel"), { key: "ArrowRight" });
    expect(now("Resize the side panel")).toBe(PANEL_DEFAULTS.right - 16);
  });

  test("double-click resets, and the width survives a reload", () => {
    const { unmount } = render(<Harness />);
    fireEvent.keyDown(handle("Resize the palette"), { key: "ArrowRight" });
    unmount();
    render(<Harness />);
    expect(now("Resize the palette")).toBe(PANEL_DEFAULTS.palette + 16);
    fireEvent.doubleClick(handle("Resize the palette"));
    expect(now("Resize the palette")).toBe(PANEL_DEFAULTS.palette);
  });

  test("widths stay inside their limits, and junk in storage is ignored", () => {
    expect(clampWidth("right", 10)).toBe(PANEL_LIMITS.right[0]);
    expect(clampWidth("right", 5000)).toBe(PANEL_LIMITS.right[1]);
    window.localStorage.setItem("rsp.panelWidths", "{not json");
    render(<Harness />);
    expect(now("Resize the side panel")).toBe(PANEL_DEFAULTS.right);
  });
});
