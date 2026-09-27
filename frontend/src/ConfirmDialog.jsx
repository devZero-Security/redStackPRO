import React, { useEffect, useRef } from "react";

// A styled stand-in for window.confirm, for actions where the native prompt's
// lack of styling, or a browser auto-suppressing it after repeated calls,
// would let something irreversible or server-visible through unconfirmed.
// window.confirm is synchronous; this is not, so App.jsx awaits a Promise
// that this dialog resolves when a button is clicked. Visually matches
// ConflictDialog (Conflict.jsx), reusing the same rg-modal classes.

export function ConfirmDialog({
  title,
  message,
  danger,
  confirmLabel = "Continue",
  cancelLabel = "Cancel",
  onConfirm,
  onCancel,
}) {
  const cancelRef = useRef(null);

  // The cancel button gets focus, since the safe default under an accidental
  // Enter is to leave state untouched. Esc is the same cancel path.
  useEffect(() => {
    cancelRef.current?.focus();
    const onKeyDown = (event) => {
      if (event.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onCancel]);

  return (
    <div className="rg-modal-backdrop">
      <div
        className="rg-modal rg-confirm"
        role="alertdialog"
        aria-modal="true"
        aria-label={title}
      >
        <h2>{title}</h2>
        <p>{message}</p>

        <div className="rg-modal-actions">
          <button ref={cancelRef} onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            className={danger ? "rg-danger" : "rg-primary"}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
