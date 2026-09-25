import React from "react";
import { GROUP_NOTES, groupedTemplates } from "./templates.js";

// The range templates, with a family folded into one call-out.
//
// There are nine of them and eight are the GOAD family, so a flat list read as
// "redStackPRO is a GOAD launcher" and buried the one range that is ours. The
// family now collapses to a single row, closed, and Harbor sits beside it at the
// same level rather than ninth in a list of GOAD labs.
//
// Rendered by both the palette and the read-only template view, which used to
// carry two copies of the same list and could drift apart.

const OPEN_KEY = "rsp.labgroups.open";

function readOpen() {
  try {
    const raw = window.localStorage.getItem(OPEN_KEY);
    return raw ? new Set(JSON.parse(raw)) : new Set();
  } catch (err) {
    // Private windows and blocked site data both throw. A group that forgets it
    // was open is a smaller problem than a palette that does not render.
    return new Set();
  }
}

function writeOpen(open) {
  try {
    window.localStorage.setItem(OPEN_KEY, JSON.stringify([...open]));
  } catch (err) {
    // See above: the choice still applies for this session.
  }
}

function LabButton({ lab, onLoad }) {
  return (
    <button
      className="rg-palette-item rg-palette-lab"
      onClick={() => onLoad?.(lab.file)}
      title={lab.teaches || lab.blurb}
    >
      <span className="rg-palette-label">{lab.name}</span>
      {lab.blurb ? <span className="rg-palette-lab-blurb">{lab.blurb}</span> : null}
    </button>
  );
}

export function LabList({ mode, onLoad }) {
  const groups = groupedTemplates(mode);
  const [open, setOpen] = React.useState(readOpen);

  const toggle = (group, isOpen) => {
    const next = new Set(open);
    if (isOpen) next.add(group);
    else next.delete(group);
    setOpen(next);
    writeOpen(next);
  };

  return (
    <>
      {groups.map(({ group, templates }) =>
        group ? (
          <details
            key={group}
            className="rg-lab-group"
            open={open.has(group)}
            onToggle={(e) => toggle(group, e.currentTarget.open)}
          >
            <summary>
              <span className="rg-lab-group-name">{group}</span>
              <span className="rg-lab-group-count">{templates.length}</span>
            </summary>
            {GROUP_NOTES[group] ? (
              <p className="rg-muted rg-labs-note">{GROUP_NOTES[group]}</p>
            ) : null}
            {templates.map((lab) => (
              <LabButton key={lab.file} lab={lab} onLoad={onLoad} />
            ))}
          </details>
        ) : (
          templates.map((lab) => (
            <LabButton key={lab.file} lab={lab} onLoad={onLoad} />
          ))
        )
      )}
    </>
  );
}
