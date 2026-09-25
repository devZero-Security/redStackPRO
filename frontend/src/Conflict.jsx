import React from "react";

import { conflictProse } from "./session.js";

// Compare and swap is explicit in the request body, and a mismatch is a 409
// carrying both version numbers so a client can show the person what happened
// rather than silently reloading. See 0017.
//
// Both offers keep both sides. Reloading throws away the local edits, so it
// says so; keeping a copy creates a new topology from the document in the canvas,
// because the duplicate endpoint copies what is stored, which is the revision
// that just won.

export function ConflictDialog({ details, onReload, onFork, onDismiss, busy }) {
  return (
    <div className="rg-modal-backdrop">
      <div className="rg-modal">
        <h2>This topology moved</h2>
        <p>{conflictProse(details)}</p>
        <p className="rg-muted">
          Someone else, or another tab, saved over the revision you opened.
          Your canvas still holds your version.
        </p>

        <div className="rg-modal-actions">
          <button onClick={onDismiss} disabled={busy}>
            Keep editing
          </button>
          <button onClick={onReload} disabled={busy}>
            Discard mine and reload
          </button>
          <button className="rg-primary" onClick={onFork} disabled={busy}>
            Save mine as a new topology
          </button>
        </div>
      </div>
    </div>
  );
}
