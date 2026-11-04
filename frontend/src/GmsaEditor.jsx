import React, { useState } from "react";
import "./widgets.css";
import { joinedHosts } from "./domainDirectory.js";

const splitList = (text) =>
  text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

function SpnInput({ value, placeholder, disabled, onChange }) {
  const [text, setText] = useState((value || []).join(", "));
  const committed = (value || []).join(", ");
  const shown = splitList(text).join(", ") === committed ? text : committed;
  return (
    <input
      value={shown}
      placeholder={placeholder}
      aria-label="SPNs"
      disabled={disabled}
      onChange={(e) => {
        setText(e.target.value);
        const list = splitList(e.target.value);
        onChange(list.length ? list : undefined);
      }}
    />
  );
}

// Group-managed service accounts on a domain and the computers allowed to read
// their passwords: the readable gMSA path. The domain_vulns role creates each
// one after the members join, and skips one that no listed host resolves for.
export function GmsaEditor({ node, document, onChange, readOnly }) {
  const overlay = node.overlay || {};
  const fqdn = overlay.fqdn || "example.local";
  const list = Array.isArray(overlay.gmsa) ? overlay.gmsa : [];
  const hosts = joinedHosts(document, node.id);

  const set = (next) => onChange({ ...overlay, gmsa: next.length ? next : undefined });
  const patch = (i, p) => {
    const merged = { ...list[i], ...p };
    for (const k of Object.keys(p)) if (merged[k] === undefined) delete merged[k];
    set(list.map((g, j) => (j === i ? merged : g)));
  };
  const toggleHost = (i, name) => {
    const cur = list[i].hosts || [];
    const next = cur.some((h) => h.toLowerCase() === name.toLowerCase())
      ? cur.filter((h) => h.toLowerCase() !== name.toLowerCase())
      : [...cur, name];
    patch(i, { hosts: next.length ? next : undefined });
  };
  const add = () => {
    const taken = new Set(list.map((g) => (g.name || "").toLowerCase()));
    let name = "gmsaService";
    let n = 1;
    while (taken.has(name.toLowerCase())) name = `gmsaService${(n += 1)}`;
    set([...list, { name }]);
  };

  return (
    <div className="rg-acls rg-gmsa">
      <h3>Group-managed service accounts{list.length ? ` (${list.length})` : ""}</h3>
      <p className="rg-hint">
        A gMSA whose password the ticked computers can read. Whoever controls one
        of those computers can read it and act as the account, which shows up in
        ACLs as name$.
      </p>
      {list.map((g, i) => {
        const named = new Set((g.hosts || []).map((h) => h.toLowerCase()));
        const strays = (g.hosts || []).filter(
          (h) => !hosts.some((x) => x.name.toLowerCase() === h.toLowerCase())
        );
        return (
          <div key={i} className="rg-widget-card">
            <div className="rg-widget-card-head">
              <label className="rg-field rg-widget-grow">
                <span className="rg-field-label">name</span>
                <input
                  value={g.name || ""}
                  placeholder="gmsaDragon"
                  aria-label="gMSA name"
                  disabled={readOnly}
                  onChange={(e) => patch(i, { name: e.target.value })}
                />
              </label>
              {readOnly ? null : (
                <button
                  type="button"
                  className="rg-user-del"
                  title="Remove gMSA"
                  aria-label="Remove gMSA"
                  onClick={() => set(list.filter((_, j) => j !== i))}
                >
                  &times;
                </button>
              )}
            </div>
            <div className="rg-field">
              <span className="rg-field-label">computers that can read the password</span>
              <div className="rg-checks">
                {hosts.map((h) => (
                  <label key={h.id} className="rg-check">
                    <input
                      type="checkbox"
                      checked={named.has(h.name.toLowerCase())}
                      disabled={readOnly}
                      onChange={() => toggleHost(i, h.name)}
                    />
                    {h.name}
                  </label>
                ))}
                {strays.map((h) => (
                  <label key={h} className="rg-check is-noop" title="Not joined to this domain, so it does not resolve.">
                    <input type="checkbox" checked disabled={readOnly} onChange={() => toggleHost(i, h)} />
                    {h} (not on this domain)
                  </label>
                ))}
              </div>
              {hosts.length ? null : (
                <span className="rg-field-help">Join a host to this domain to pick it here.</span>
              )}
              {named.size && strays.length < named.size ? null : (
                <span className="rg-widget-warn">
                  No computer on this domain is ticked, so this account is not created.
                </span>
              )}
            </div>
            <label className="rg-field">
              <span className="rg-field-label">SPNs</span>
              <SpnInput
                value={g.spns}
                placeholder={`HTTP/${hosts[0]?.name || "srv01"}.${fqdn}`}
                disabled={readOnly}
                onChange={(v) => patch(i, { spns: v })}
              />
              <span className="rg-field-help">Comma separated. Optional.</span>
            </label>
            <label className="rg-field">
              <span className="rg-field-label">DNS name</span>
              <input
                value={g.dns || ""}
                placeholder={`${g.name || "gmsa"}.${fqdn}`}
                aria-label="gMSA DNS name"
                disabled={readOnly}
                onChange={(e) => patch(i, { dns: e.target.value || undefined })}
              />
              <span className="rg-field-help">Empty uses {g.name || "name"}.{fqdn}.</span>
            </label>
          </div>
        );
      })}
      {readOnly ? null : (
        <button type="button" className="rg-inline-btn" onClick={add}>
          + Add gMSA
        </button>
      )}
    </div>
  );
}
