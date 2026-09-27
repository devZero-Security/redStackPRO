import { useCallback, useMemo, useRef, useState } from "react";

import {
  initHistory,
  pushHistory,
  amendHistory,
  undoHistory,
  redoHistory,
  resetHistory,
  clearHistory,
  canUndo,
  canRedo,
} from "./history.js";

// The undo/redo stack over the canvas document, wired for React. history.js
// holds the plain past/present/future logic (tested standalone); this adds
// the two pieces of glue that only make sense against a live canvas:
//
// - gesture(key, updater): a continuous drag (a node move, a container
//   resize, a dragged waypoint) calls this on every frame. The first call in
//   a gesture pushes a step; every call after it, until the pointer is
//   released, amends that same step instead of adding one per frame. A
//   window "pointerup" ends the gesture, so the caller never has to signal
//   drag-stop itself.
// - coalesce(key, updater, windowMs): a typed field (a node id, a hostname,
//   the topology name) calls this on every keystroke. Consecutive calls with
//   the same key inside the window amend the last step; a pause starts a new
//   one. There is no keyup here to bound it exactly, so this is a timing
//   heuristic rather than the gesture's precise boundary, and merges edits to
//   the same key even across a short pause, which is the right tradeoff for
//   typing.
export function useHistory(initial) {
  const [state, setState] = useState(() => initHistory(
    typeof initial === "function" ? initial() : initial
  ));
  const gestureKeys = useRef(new Set());
  const coalesceAt = useRef(new Map());

  const runUpdater = (present, updater) =>
    typeof updater === "function" ? updater(present) : updater;

  const mutate = useCallback((updater) => {
    setState((s) => pushHistory(s, runUpdater(s.present, updater)));
  }, []);

  const amend = useCallback((updater) => {
    setState((s) => amendHistory(s, runUpdater(s.present, updater)));
  }, []);

  const gesture = useCallback((key, updater) => {
    if (gestureKeys.current.has(key)) {
      amend(updater);
      return;
    }
    gestureKeys.current.add(key);
    const end = () => gestureKeys.current.delete(key);
    window.addEventListener("pointerup", end, { once: true });
    mutate(updater);
  }, [mutate, amend]);

  const coalesce = useCallback((key, updater, windowMs = 800) => {
    const now = Date.now();
    const last = coalesceAt.current.get(key);
    coalesceAt.current.set(key, now);
    if (last !== undefined && now - last < windowMs) {
      amend(updater);
    } else {
      mutate(updater);
    }
  }, [mutate, amend]);

  const reset = useCallback((doc) => {
    gestureKeys.current.clear();
    coalesceAt.current.clear();
    setState(resetHistory(doc));
  }, []);

  const clear = useCallback(() => {
    setState((s) => clearHistory(s));
  }, []);

  const undo = useCallback(() => setState((s) => undoHistory(s)), []);
  const redo = useCallback(() => setState((s) => redoHistory(s)), []);

  return useMemo(
    () => ({
      document: state.present,
      canUndo: canUndo(state),
      canRedo: canRedo(state),
      mutate,
      amend,
      gesture,
      coalesce,
      reset,
      clear,
      undo,
      redo,
    }),
    [state, mutate, amend, gesture, coalesce, reset, clear, undo, redo]
  );
}
