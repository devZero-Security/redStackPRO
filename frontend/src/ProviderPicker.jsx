import React, { useEffect, useRef, useState } from "react";
import { ProviderMark } from "./providerIcons.jsx";
import { labelFor } from "./providers.js";

// The deploy target chooser.
//
// A popover rather than a select, unlike TopologyPicker next to it, for one blunt
// reason: an <option> renders text and nothing else, in every browser. A native
// select cannot show a vendor mark, and the mark is most of what makes this row
// readable at a glance -- five names in a row all look alike, five marks do not.
//
// The mark is decorative and the label is the content. A provider with no mark
// renders as its label alone, so a registry entry we have not drawn yet still
// appears rather than becoming an invisible row.

export function ProviderPicker({ provider, providers, selectable, onChange, title }) {
  const canPick = (name) => !selectable || selectable.includes(name);
  const [open, setOpen] = useState(false);
  const box = useRef(null);

  // Close on a click anywhere else and on Escape. Both are registered only while
  // the popover is open, so the canvas is not paying for listeners that spend
  // nearly all their time doing nothing.
  useEffect(() => {
    if (!open) return undefined;
    const onDown = (event) => {
      if (!box.current?.contains(event.target)) setOpen(false);
    };
    const onKey = (event) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const choose = (name) => {
    onChange(name);
    setOpen(false);
  };

  return (
    <div className="rg-provider" ref={box}>
      <button
        type="button"
        className="rg-provider-current"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={`Deploy target: ${labelFor(provider)}`}
        title={title}
        onClick={() => setOpen((v) => !v)}
      >
        <ProviderMark provider={provider} />
        <span className="rg-provider-label">{labelFor(provider)}</span>
        <span className="rg-provider-caret" aria-hidden="true">
          {"▾"}
        </span>
      </button>

      {open ? (
        <ul className="rg-provider-menu" role="listbox">
          {providers.map((name) => {
            // A pending backend is shown but not choosable. Greyed rather than
            // hidden because the compiler really does build it, so hiding would
            // understate what is here; disabled rather than selectable because
            // none of them has been through a real range end to end.
            const ready = canPick(name);
            return (
              <li key={name}>
                <button
                  type="button"
                  role="option"
                  aria-selected={name === provider}
                  aria-disabled={!ready}
                  disabled={!ready}
                  title={ready ? undefined : `${labelFor(name)} compiles, but no range has been deployed on it yet`}
                  className={`rg-provider-item ${name === provider ? "is-active" : ""} ${ready ? "" : "is-pending"}`}
                  onClick={() => ready && choose(name)}
                >
                  <ProviderMark provider={name} />
                  <span className="rg-provider-label">{labelFor(name)}</span>
                  {/* The badge reads "pending", not "preview". The maturity
                      VALUE stays `preview` because that is the wire contract
                      the API sends; this is the label only. "Preview" invites
                      you to try it, which is the wrong promise for a backend
                      that compiles but has never had a range stood up on it.
                      "Pending" says the work is not finished, which is what
                      the tooltip below has always said in full. */}
                  {ready ? null : <span className="rg-provider-tag">pending</span>}
                </button>
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}
