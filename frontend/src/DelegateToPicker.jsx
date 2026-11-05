import React, { useState } from "react";
import "./widgets.css";
import { spnOptionGroups } from "./spnChoices.js";

const same = (a, b) => a.toLowerCase() === b.toLowerCase();

// A list of values picked from grouped checkboxes, or added by hand. `groups` is
// [{label, options: [{value, label, about}]}]; `checkLabel(option, group)` names
// each checkbox, and must say which group it is in, since the same label repeats.
export function CheckListPicker({
  label, value, groups, help, disabled, onChange, checkLabel, emptyText, otherLabel,
  otherPlaceholder, addLabel, customTitle, summary, className = "rg-field rg-delegate", children,
}) {
  const selected = Array.isArray(value) ? value : [];
  const [draft, setDraft] = useState("");
  const known = groups.flatMap((g) => g.options.map((o) => o.value));
  const custom = selected.filter((v) => !known.some((k) => same(k, v)));
  const has = (v) => selected.some((s) => same(s, v));
  const set = (next) => onChange(next.length ? next : undefined);
  const toggle = (v) => set(has(v) ? selected.filter((s) => !same(s, v)) : [...selected, v]);
  const addDraft = () => {
    const v = draft.trim();
    if (!v || has(v)) return;
    set([...selected, v]);
    setDraft("");
  };

  return (
    <div className={className}>
      {label ? <span className="rg-field-label">{label}</span> : null}
      {groups.length ? (
        groups.map((g) => (
          <div key={g.label} className="rg-delegate-host">
            <span className="rg-delegate-hostname">{g.label}</span>
            <div className="rg-checks">
              {g.options.map((o) => (
                <label key={o.value} className="rg-check" title={`${o.value}: ${o.about}`}>
                  <input
                    type="checkbox"
                    aria-label={checkLabel(o, g)}
                    checked={has(o.value)}
                    disabled={disabled}
                    onChange={() => toggle(o.value)}
                  />
                  {o.label}
                </label>
              ))}
            </div>
          </div>
        ))
      ) : (
        <span className="rg-field-help">{emptyText}</span>
      )}
      {custom.length ? (
        <div className="rg-chips">
          {custom.map((v) => (
            <span key={v} className="rg-chip" title={customTitle}>
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
            placeholder={otherPlaceholder}
            aria-label={otherLabel}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addDraft();
              }
            }}
          />
          <button type="button" aria-label={addLabel} onClick={addDraft} disabled={!draft.trim()}>
            Add
          </button>
        </div>
      )}
      <span className="rg-field-help">
        {summary(selected)}
        {help ? ` ${help}` : ""}
      </span>
      {children}
    </div>
  );
}

// Pick the SPNs an account may delegate to from the services in its domain, or
// add one by hand. `groups` comes from spnChoices().
export function DelegateToPicker({ groups, ...rest }) {
  return (
    <CheckListPicker
      label="Delegate to"
      {...rest}
      groups={spnOptionGroups(groups)}
      checkLabel={(o, g) => `${o.label} on ${g.label}`}
      emptyText="No other Windows host in this domain yet. Add one, or type an SPN below."
      otherLabel="Other SPN"
      otherPlaceholder="Other SPN, e.g. HTTP/web01.corp.local"
      customTitle="Typed by hand, not a service in this domain"
      summary={(selected) =>
        selected.length ? `Delegates to: ${selected.join(", ")}.` : "Nothing picked yet."
      }
    />
  );
}
