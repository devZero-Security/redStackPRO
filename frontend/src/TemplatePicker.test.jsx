// The template picker, rendered.
//
// Eight of the nine range templates are the GOAD family and one is ours. The
// picker grouped the eight under a "GOAD" heading and then rendered Harbor with
// no heading at all, so it sat directly under that one and read as a ninth GOAD
// lab. Which is the opposite of the point: Harbor is the range that is not.

import React from "react";
import { describe, expect, test, vi } from "vitest";
import { render, screen } from "@testing-library/react";

import { TemplatePicker } from "./TemplatePicker.jsx";
import { UNGROUPED_LABEL, groupedTemplates } from "./templates.js";

// queryAll, not getAll: the ops canvas is meant to have none, and getAll throws
// on an empty result rather than returning one.
function headings() {
  return screen.queryAllByRole("heading", { level: 3 }).map((h) => h.textContent);
}

// Card names specifically. "GOAD" is both a group heading and a template, so a
// plain text lookup finds two elements and cannot tell which it meant.
function cardNames() {
  return [...document.querySelectorAll(".rg-chooser-name")].map((e) => e.textContent);
}

describe("the range picker", () => {
  test("labels the templates that belong to no family", () => {
    render(<TemplatePicker mode="range" onPick={vi.fn()} onDismiss={vi.fn()} />);
    expect(headings()).toEqual(["GOAD", UNGROUPED_LABEL]);
  });

  test("Harbor is under that heading and not under GOAD", () => {
    render(<TemplatePicker mode="range" onPick={vi.fn()} onDismiss={vi.fn()} />);
    const sections = document.querySelectorAll(".rg-template-group");
    const goad = [...sections].find((s) => s.querySelector("h3").textContent === "GOAD");
    const ours = [...sections].find(
      (s) => s.querySelector("h3").textContent === UNGROUPED_LABEL);

    expect(goad.textContent).not.toContain("Harbor");
    expect(ours.textContent).toContain("Harbor");
    // And the family really is the eight, so the slide that says so is right.
    expect(goad.querySelectorAll(".rg-chooser-card")).toHaveLength(8);
    expect(ours.querySelectorAll(".rg-chooser-card")).toHaveLength(1);
  });

  test("the Red Infra canvas gets no heading, having no family to contrast", () => {
    // Every ops template is ungrouped, so a lone heading over the whole list
    // would name a distinction that is not being drawn.
    render(<TemplatePicker mode="ops" onPick={vi.fn()} onDismiss={vi.fn()} />);
    expect(headings()).toEqual([]);
    expect(cardNames()).toContain("redStack");
  });

  test("every template in the data reaches the screen", () => {
    // A grouping change that dropped a section would still satisfy the
    // assertions above.
    render(<TemplatePicker mode="range" onPick={vi.fn()} onDismiss={vi.fn()} />);
    const expected = groupedTemplates("range").flatMap((g) => g.templates);
    expect(cardNames()).toEqual(expected.map((t) => t.name));
  });
});
