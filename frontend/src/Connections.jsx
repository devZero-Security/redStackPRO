import React, { useState } from "react";
import "./widgets.css";
import { DRAWN_ROLES, roleColor } from "./topology.js";
import {
  ROLE_TEXT, connectOptions, defaultTrustPatch, nodeName, optionSentence,
} from "./edgeRoles.js";
import { edgeId } from "./idscheme.js";

// A node's drawn relationships, listed as rows you click to open and edit rather
// than hunting for a thin line to hit on the canvas. Each row reads as a short
// sentence about the other end, coloured the same as the line. Below the list,
// a small form adds a new connection from this node without drawing it: pick
// the other end and the line it can carry is worked out from the two kinds.
export function Connections({ node, document, onSelect, onAddEdge, onEdgeChange, readOnly }) {
  const [target, setTarget] = useState("");
  const [choice, setChoice] = useState(0);
  const rows = document.edges
    .filter(
      (e) => DRAWN_ROLES.includes(e.role) && (e.source === node.id || e.target === node.id)
    )
    .map((e) => {
      const outgoing = e.source === node.id;
      const other = outgoing ? e.target : e.source;
      const text = ROLE_TEXT[e.role] || {};
      const phrase = (outgoing ? text.to : text.from) || e.role;
      const detail = e.role === "fronts" ? e.uri_prefix || "" : "";
      return { id: e.id, role: e.role, phrase, other, detail };
    });

  const candidates = document.nodes
    .filter((n) => n.id !== node.id)
    .map((n) => ({ node: n, options: connectOptions(document, node, n) }))
    .filter((c) => c.options.length);
  const picked = candidates.find((c) => c.node.id === target);
  const options = picked ? picked.options : [];
  const option = options[Math.min(choice, options.length - 1)];

  const add = () => {
    if (!option) return;
    onAddEdge?.(option.source, option.target, option.role);
    // A new trust gets its type straight away, the same as opening it would.
    if (option.role === "trusts" && onEdgeChange) {
      const patch = defaultTrustPatch(document, { source: option.source, target: option.target });
      if (patch) onEdgeChange(edgeId(option.source, option.target, "trusts"), patch);
    }
    setTarget("");
    setChoice(0);
  };

  return (
    <div className="rg-connections">
      <h3>Connections</h3>
      {rows.length === 0 ? (
        <p className="rg-hint">No connections yet.</p>
      ) : (
        rows.map((r) => (
          <button
            key={r.id}
            type="button"
            className="rg-connection"
            onClick={() => onSelect?.(r.id)}
          >
            <span className="rg-connection-dot" style={{ background: roleColor(r.role) }} />
            <span className="rg-connection-role">{r.phrase}</span>
            <span className="rg-connection-other">{nodeName(document, r.other)}</span>
            {r.detail ? <span className="rg-connection-detail">{r.detail}</span> : null}
          </button>
        ))
      )}
      {readOnly ? null : (
        <>
          <div className="rg-connection-add">
            <select
              value={target}
              aria-label="connect to"
              onChange={(e) => {
                setTarget(e.target.value);
                setChoice(0);
              }}
            >
              <option value="">connect to...</option>
              {candidates.map((c) => (
                <option key={c.node.id} value={c.node.id}>
                  {nodeName(document, c.node.id)}
                </option>
              ))}
            </select>
            {options.length > 1 ? (
              <select
                value={choice}
                aria-label="line"
                onChange={(e) => setChoice(Number(e.target.value))}
              >
                {options.map((o, i) => (
                  <option key={`${o.role}:${o.source}`} value={i}>
                    {optionSentence(document, o)}
                  </option>
                ))}
              </select>
            ) : null}
            <button type="button" onClick={add} disabled={!option}>
              Add
            </button>
          </div>
          {option ? (
            <span className="rg-field-help">Adds: {optionSentence(document, option)}.</span>
          ) : candidates.length ? null : (
            <span className="rg-field-help">Nothing on the canvas can take a line from this node.</span>
          )}
        </>
      )}
    </div>
  );
}
