// A bounded undo/redo stack over the in-canvas topology document. Framework
// free, so it is testable with plain node (see history.test.mjs); useHistory.js
// wraps this for React and adds the browser-specific gesture and coalescing
// glue that decides when a mutation pushes a step versus rides along with one
// already on the stack.
//
// past/future hold documents, present is the live one. past[past.length - 1]
// is the step immediately behind present.

export const MAX_HISTORY = 50;

export function initHistory(doc) {
  return { past: [], present: doc, future: [] };
}

// Records the current present as a step, then moves to `next`. Redo is
// discarded: once a person edits again, whatever they had undone past is
// gone, the ordinary rule everywhere undo/redo shows up. A no-op update (the
// same reference back) records nothing, so a callback that decided there was
// nothing to change never pollutes the stack.
export function pushHistory(state, next) {
  if (next === state.present) return state;
  const past =
    state.past.length >= MAX_HISTORY
      ? [...state.past.slice(1), state.present]
      : [...state.past, state.present];
  return { past, present: next, future: [] };
}

// Replaces present without recording a step. Used for a gesture's
// intermediate frames once its start already pushed the baseline (a drag, a
// resize, a dragged waypoint), and for automatic corrections, such as id
// retitling, that should ride along with the edit that triggered them rather
// than becoming their own undo step.
export function amendHistory(state, next) {
  if (next === state.present) return state;
  return { ...state, present: next };
}

export function undoHistory(state) {
  if (!state.past.length) return state;
  const previous = state.past[state.past.length - 1];
  const future = [state.present, ...state.future].slice(0, MAX_HISTORY);
  return { past: state.past.slice(0, -1), present: previous, future };
}

export function redoHistory(state) {
  if (!state.future.length) return state;
  const [next, ...rest] = state.future;
  const past =
    state.past.length >= MAX_HISTORY
      ? [...state.past.slice(1), state.present]
      : [...state.past, state.present];
  return { past, present: next, future: rest };
}

// Starts a fresh document: a topology opens, a template loads, New starts
// one. Not a step to undo back through, since this is a session boundary,
// not an edit to the document that was open.
export function resetHistory(doc) {
  return { past: [], present: doc, future: [] };
}

// Clears the stacks without changing the document: Save, Duplicate, Publish,
// Clone. What led up to a save is not something to undo past.
export function clearHistory(state) {
  if (!state.past.length && !state.future.length) return state;
  return { past: [], present: state.present, future: [] };
}

export function canUndo(state) {
  return state.past.length > 0;
}

export function canRedo(state) {
  return state.future.length > 0;
}
