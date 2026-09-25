import React from "react";

// The topology picker.
//
// A select rather than a popover, because the list is the person's own topologies
// plus whatever their org made visible, and that is a short list that the
// existing header chrome already knows how to draw.
//
// Org visible topologies owned by someone else are read only, and reuse is by copy.
// Saying so in the row is cheaper than letting Save fail. See 0009.

export function TopologyPicker({ topologies, current, dirty, onOpen, onNew, onDuplicate, onBrowse }) {
  // A topology opened by URL is listed by the API, but a stale list would drop the
  // open one out of the select and make it look like nothing is open.
  const rows = current && !topologies.some((g) => g.id === current.id)
    ? [...topologies, current]
    : topologies;

  return (
    <div className="rg-picker">
      <select
        aria-label="Open topology"
        value={current?.id || ""}
        title={current ? `version ${current.version}` : "Not saved yet"}
        onChange={(event) => {
          if (event.target.value) onOpen(event.target.value);
          else onNew();
        }}
      >
        {current ? null : <option value="">Unsaved topology</option>}
        {rows.map((topology) => (
          <option key={topology.id} value={topology.id}>
            {topology.name}
            {topology.editable ? "" : " (read only)"}
          </option>
        ))}
      </select>

      <button onClick={onBrowse} title="Browse blueprints and manage your topologies">
        Library
      </button>
      <button onClick={onNew} title="Start an empty topology">
        New
      </button>
      <button
        onClick={onDuplicate}
        disabled={!current}
        title={
          dirty
            ? "Copies the last saved revision. Your unsaved changes stay here."
            : "A private copy you own, with no link back to this one"
        }
      >
        Duplicate
      </button>
    </div>
  );
}
