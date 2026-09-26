import React from "react";
import { availableExtensions, activeExtensions, canAdd } from "./extensions.js";

// The GOAD extensions as a toggle list on a range. Ticking one adds its box and
// wires its agents; unticking removes them. Because a read-only GOAD template is
// pristine, turning an extension on forks it into an editable range first.
export function Extensions({ document, readOnly, onToggle, onDismiss }) {
  const active = activeExtensions(document);
  const available = availableExtensions(document);
  return (
    <div className="rg-modal-backdrop" onClick={onDismiss}>
      <div
        className="rg-modal rg-mode-haven rg-extensions"
        role="dialog"
        aria-label="GOAD extensions"
        onClick={(event) => event.stopPropagation()}
      >
        <h2>Extensions</h2>
        <p className="rg-muted">
          The GOAD extensions. Toggle one to add its box and wire its agents.
          {readOnly ? " Turning one on makes an editable copy of this template." : ""}
        </p>
        <ul className="rg-ext-list">
          {available.map((ext) => {
            const on = active.has(ext.key);
            const disabled = !on && !canAdd(document, ext.key);
            return (
              <li
                key={ext.key}
                className={`rg-ext ${on ? "is-on" : ""} ${disabled ? "is-disabled" : ""}`}
              >
                <label>
                  <input
                    type="checkbox"
                    checked={on}
                    disabled={disabled}
                    onChange={() => onToggle(ext.key, !on)}
                  />
                  <span className="rg-ext-body">
                    <span className="rg-ext-title">
                      {ext.title}
                      {disabled ? <span className="rg-ext-hint">needs a domain</span> : null}
                    </span>
                    <span className="rg-ext-blurb">{ext.blurb}</span>
                  </span>
                </label>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
