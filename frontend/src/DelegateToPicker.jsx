import React, { useState } from "react";
import "./widgets.css";

const same = (a, b) => a.toLowerCase() === b.toLowerCase();

// Pick the SPNs an account may delegate to from the services in its domain, or
// add one by hand. `groups` comes from spnChoices().
export function DelegateToPicker({ label = "Delegate to", value, groups, help, disabled, onChange }) {
  const selected = Array.isArray(value) ? value : [];
  const [draft, setDraft] = useState("");
  const known = groups.flatMap((g) => g.spns.map((s) => s.spn));
  const custom = selected.filter((v) => !known.some((k) => same(k, v)));
  const has = (spn) => selected.some((v) => same(v, spn));
  const set = (next) => onChange(next.length ? next : undefined);
  const toggle = (spn) => set(has(spn) ? selected.filter((v) => !same(v, spn)) : [...selected, spn]);
  const addDraft = () => {
    const spn = draft.trim();
    if (!spn || has(spn)) return;
    set([...selected, spn]);
    setDraft("");
  };

  return (
    <div className="rg-field rg-delegate">
      <span className="rg-field-label">{label}</span>
      {groups.length ? (
        groups.map((g) => (
          <div key={g.host} className="rg-delegate-host">
            <span className="rg-delegate-hostname">{g.host}</span>
            <div className="rg-checks">
              {g.spns.map((s) => (
                <label key={s.spn} className="rg-check" title={`${s.spn}: ${s.about}`}>
                  <input
                    type="checkbox"
                    aria-label={`${s.label} on ${g.host}`}
                    checked={has(s.spn)}
                    disabled={disabled}
                    onChange={() => toggle(s.spn)}
                  />
                  {s.label}
                </label>
              ))}
            </div>
          </div>
        ))
      ) : (
        <span className="rg-field-help">
          No other Windows host in this domain yet. Add one, or type an SPN below.
        </span>
      )}
      {custom.length ? (
        <div className="rg-chips">
          {custom.map((v) => (
            <span key={v} className="rg-chip" title="Typed by hand, not a service in this domain">
              {v}
              {disabled ? null : (
                <button
                  type="button"
                  className="rg-chip-del"
                  aria-label={`Remove ${v}`}
                  onClick={() => set(selected.filter((x) => x !== v))}
                >
                  x
                </button>
              )}
            </span>
          ))}
        </div>
      ) : null}
      {disabled ? null : (
        <div className="rg-delegate-add">
          <input
            value={draft}
            placeholder="Other SPN, e.g. HTTP/web01.corp.local"
            aria-label="Other SPN"
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addDraft();
              }
            }}
          />
          <button type="button" onClick={addDraft} disabled={!draft.trim()}>
            Add
          </button>
        </div>
      )}
      <span className="rg-field-help">
        {selected.length ? `Delegates to: ${selected.join(", ")}.` : "Nothing picked yet."}
        {help ? ` ${help}` : ""}
      </span>
    </div>
  );
}
