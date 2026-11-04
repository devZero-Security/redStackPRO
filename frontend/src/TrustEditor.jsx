import React, { useEffect, useRef } from "react";
import "./widgets.css";
import { defaultTrustPatch, parentChild } from "./edgeRoles.js";

export const TRUST_TYPES = [
  { value: "parent_child", label: "Parent and child" },
  { value: "forest", label: "Forest" },
  { value: "external", label: "External" },
  { value: "tree_root", label: "Tree root" },
];

const NOT_BUILT = new Set(["external", "tree_root"]);

// A domain reads as its FQDN when it has one.
function domainLabel(document, id) {
  const fqdn = document.nodes.find((n) => n.id === id)?.overlay?.fqdn;
  return fqdn || id;
}

// The editor for a trusts edge: what kind of trust, which way, and whether it
// is transitive. The dc role builds a parent and child trust by promoting the
// target as a child of the source, and a forest trust after both roots are
// up; the other two types are recorded but not built.
export function TrustEditor({ edge, document, onEdgeChange, readOnly }) {
  const source = domainLabel(document, edge.source);
  const target = domainLabel(document, edge.target);
  const type = edge.trust_type || "";

  // An untyped trust gets the type the compiler would give it, once per edge
  // while this editor is open, so undo can step back past it.
  const defaulted = useRef(new Set());
  useEffect(() => {
    if (readOnly || edge.trust_type || defaulted.current.has(edge.id)) return;
    const patch = defaultTrustPatch(document, edge);
    if (!patch) return;
    defaulted.current.add(edge.id);
    onEdgeChange(edge.id, patch);
  }, [edge.id, edge.trust_type, readOnly]);

  const changeType = (value) => {
    if (!value || value === edge.trust_type) return;
    const patch = { trust_type: value };
    if (value === "parent_child") {
      const pc = parentChild(document, edge.source, edge.target);
      if (pc && pc.parent !== edge.source) {
        patch.source = pc.parent;
        patch.target = pc.child;
      }
    }
    onEdgeChange(edge.id, patch);
  };
  const swap = () => onEdgeChange(edge.id, { source: edge.target, target: edge.source });

  const direction = edge.direction || "bidirectional";
  const directions = [
    { value: "bidirectional", label: "Two-way: each domain trusts the other" },
    { value: "outbound", label: `One-way: ${source} trusts ${target}` },
    { value: "inbound", label: `One-way: ${target} trusts ${source}` },
  ];

  return (
    <div className="rg-trust">
      <label className="rg-field">
        <span className="rg-field-label">type</span>
        <select
          value={type}
          aria-label="trust type"
          disabled={readOnly}
          onChange={(e) => changeType(e.target.value)}
        >
          {type ? null : <option value="">Not set</option>}
          {TRUST_TYPES.map((t) => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
        {type === "" ? (
          <span className="rg-field-help">
            Not set: the export makes it Parent and child when one domain&apos;s
            FQDN ends with the other&apos;s, else Forest.
            {source === edge.source || target === edge.target
              ? " Set both domains' FQDN and it is picked for you."
              : ""}
          </span>
        ) : null}
        {type === "parent_child" ? (
          <span className="rg-field-help">
            {target} is created as a child domain under {source}. AD makes this
            trust two-way and transitive by itself.
          </span>
        ) : null}
        {type === "forest" ? (
          <span className="rg-field-help">
            {source} and {target} stay separate forests, joined by a forest trust
            built once both are promoted.
          </span>
        ) : null}
        {NOT_BUILT.has(type) ? (
          <span className="rg-widget-warn">
            Not built yet: this trust type is recorded but not created.
          </span>
        ) : null}
      </label>

      {type === "parent_child" ? (
        <div className="rg-field">
          <p className="rg-kv">
            <span>parent</span>
            <span>{source}</span>
          </p>
          <p className="rg-kv">
            <span>child</span>
            <span>{target}</span>
          </p>
          {readOnly ? null : (
            <button type="button" className="rg-inline-btn" onClick={swap}>
              Swap parent and child
            </button>
          )}
        </div>
      ) : null}

      {type === "forest" || type === "external" ? (
        <>
          <label className="rg-field">
            <span className="rg-field-label">direction</span>
            <select
              value={direction}
              aria-label="trust direction"
              disabled={readOnly}
              onChange={(e) => onEdgeChange(edge.id, { direction: e.target.value })}
            >
              {directions.map((d) => (
                <option key={d.value} value={d.value}>{d.label}</option>
              ))}
            </select>
            <span className="rg-field-help">
              Users of the trusted domain can reach resources in the domain that
              trusts it.
            </span>
          </label>
          <label className="rg-field">
            <span className="rg-check-row">
              <input
                type="checkbox"
                checked={edge.transitive ?? true}
                aria-label="transitive"
                disabled={readOnly}
                onChange={(e) => onEdgeChange(edge.id, { transitive: e.target.checked })}
              />
              <span className="rg-field-label">transitive</span>
            </span>
            <span className="rg-field-help">
              Recorded with the trust. The trust is built the same way either way.
            </span>
          </label>
        </>
      ) : null}
    </div>
  );
}
