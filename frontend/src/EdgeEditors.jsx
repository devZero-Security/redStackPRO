import React from "react";
import "./widgets.css";
import { ROLE_TEXT, roleTitle, rolesFor } from "./edgeRoles.js";

const FRONTS_DEFAULTS = { protocol: "https", listen_port: 443, upstream_port: 443 };
const FRONTS_FIELDS = { protocol: undefined, listen_port: undefined, upstream_port: undefined, uri_prefix: undefined };
const TRUST_FIELDS = { trust_type: undefined, direction: undefined, transitive: undefined };

// The patch that moves an edge to another role. Switching to fronts seeds the
// fields it needs so it validates; switching away drops the old role's fields
// so a stale prefix or trust type does not linger.
export function rolePatch(edge, role) {
  const patch = { role, ...(edge.role === "trusts" ? TRUST_FIELDS : {}) };
  if (role === "fronts") {
    return {
      ...patch,
      protocol: edge.protocol || "https",
      listen_port: edge.listen_port || 443,
      upstream_port: edge.upstream_port || 443,
      uri_prefix: edge.uri_prefix || "/cdn/assets",
    };
  }
  return { ...patch, ...FRONTS_FIELDS };
}

// The role of a drawn line. Only the roles the two endpoint kinds allow are
// offered; with one, it is shown rather than asked. A trust has its own editor,
// so nothing is shown for it here.
export function EdgeRole({ edge, document, readOnly, onEdgeChange }) {
  const kindOf = (id) => document.nodes.find((n) => n.id === id)?.kind;
  const sourceKind = kindOf(edge.source);
  const targetKind = kindOf(edge.target);
  const valid = rolesFor(sourceKind, targetKind);
  if (edge.role === "trusts" && valid.includes("trusts")) return null;

  const options = valid.includes(edge.role) ? valid : [edge.role, ...valid];
  const about = ROLE_TEXT[edge.role]?.about;

  // The heading already names the only role these ends can carry.
  if (options.length === 1) {
    return about ? <p className="rg-field-help">{about}</p> : null;
  }

  return (
    <label className="rg-field">
      <span className="rg-field-label">role</span>
      <select
        value={edge.role}
        aria-label="role"
        disabled={readOnly}
        onChange={(e) => {
          const role = e.target.value;
          if (!role || role === edge.role) return;
          onEdgeChange(edge.id, rolePatch(edge, role));
        }}
      >
        {options.map((r) => (
          <option key={r} value={r}>
            {roleTitle(r)}
            {valid.includes(r) ? "" : ` (not valid from a ${sourceKind} to a ${targetKind})`}
          </option>
        ))}
      </select>
      <span className="rg-field-help">
        {valid.includes(edge.role)
          ? about
          : `A ${sourceKind} to a ${targetKind} cannot carry this role. Pick one it can.`}
      </span>
    </label>
  );
}

const atDefault = (edge) =>
  (edge.protocol ?? "https") === "https" &&
  (edge.listen_port ?? 443) === 443 &&
  (edge.upstream_port ?? 443) === 443;

// A redirector serves HTTPS on 443 and proxies to the teamserver on 443, so the
// protocol and ports of a fronts edge are shown rather than edited. A document
// carrying other values is told what they do and offered the reset.
export function FrontsPorts({ edge, readOnly, onEdgeChange }) {
  const protocol = (edge.protocol ?? "https").toUpperCase();
  const listen = edge.listen_port ?? 443;
  const upstream = edge.upstream_port ?? 443;
  const ok = atDefault(edge);
  return (
    <div className="rg-field">
      <span className="rg-field-label">protocol and ports</span>
      <span className="rg-fronts-ports">
        {protocol}, {listen} to {upstream}
      </span>
      {ok ? (
        <span className="rg-field-help">
          The redirector answers HTTPS on 443 and forwards to the teamserver on 443.
        </span>
      ) : (
        <>
          <span className="rg-widget-warn">
            Redirectors serve HTTPS on 443 only; other values open a port nothing answers on.
          </span>
          {readOnly ? null : (
            <button
              type="button"
              className="rg-inline-btn"
              onClick={() => onEdgeChange(edge.id, FRONTS_DEFAULTS)}
            >
              Reset to HTTPS 443
            </button>
          )}
        </>
      )}
    </div>
  );
}
