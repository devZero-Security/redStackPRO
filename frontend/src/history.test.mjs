import assert from "node:assert/strict";
import {
  MAX_HISTORY,
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

// A push records the present as a step and moves to the next document. Undo
// walks back to it, redo walks forward again.
{
  let s = initHistory("a");
  s = pushHistory(s, "b");
  s = pushHistory(s, "c");
  assert.equal(s.present, "c");
  assert.deepEqual(s.past, ["a", "b"]);
  assert.equal(canUndo(s), true);
  assert.equal(canRedo(s), false);

  s = undoHistory(s);
  assert.equal(s.present, "b");
  assert.deepEqual(s.past, ["a"]);
  assert.deepEqual(s.future, ["c"]);

  s = undoHistory(s);
  assert.equal(s.present, "a");
  assert.deepEqual(s.past, []);
  assert.equal(canUndo(s), false);

  s = redoHistory(s);
  s = redoHistory(s);
  assert.equal(s.present, "c");
  assert.equal(canRedo(s), false);
}

// A push with the same reference back records nothing: a callback that found
// no actual change never pollutes the stack.
{
  let s = initHistory("a");
  const same = pushHistory(s, "a");
  assert.equal(same, s);
  assert.equal(canUndo(same), false);
}

// A fresh edit after an undo throws away the redo branch, the ordinary rule.
{
  let s = initHistory("a");
  s = pushHistory(s, "b");
  s = undoHistory(s);
  assert.equal(canRedo(s), true);
  s = pushHistory(s, "z");
  assert.equal(canRedo(s), false);
  assert.equal(s.present, "z");
  assert.deepEqual(s.past, ["a"]);
}

// Bounded: pushing past MAX_HISTORY drops the oldest step rather than growing
// forever, so a long session does not leak memory.
{
  let s = initHistory(0);
  for (let i = 1; i <= MAX_HISTORY + 10; i++) {
    s = pushHistory(s, i);
  }
  assert.equal(s.past.length, MAX_HISTORY);
  assert.equal(s.present, MAX_HISTORY + 10);
  // The oldest surviving step is 10 (0..9 were pushed off), the last is
  // MAX_HISTORY + 9 (the step right before the current present).
  assert.equal(s.past[0], 10);
  assert.equal(s.past[s.past.length - 1], MAX_HISTORY + 9);
}

// Redo is bounded too.
{
  let s = initHistory(0);
  for (let i = 1; i <= MAX_HISTORY + 10; i++) {
    s = pushHistory(s, i);
  }
  for (let i = 0; i < MAX_HISTORY + 10; i++) {
    s = undoHistory(s);
  }
  assert.ok(s.future.length <= MAX_HISTORY);
}

// Coalescing: a gesture pushes its baseline once, then amends its
// intermediate frames without adding further steps. One undo reverts the
// whole gesture, not one frame of it.
{
  let s = initHistory({ x: 0 });
  s = pushHistory(s, { x: 1 }); // gesture start: baseline {x:0} recorded
  s = amendHistory(s, { x: 2 }); // frame
  s = amendHistory(s, { x: 3 }); // frame
  s = amendHistory(s, { x: 4 }); // final frame at gesture end
  assert.deepEqual(s.present, { x: 4 });
  assert.equal(s.past.length, 1, "the whole gesture is one step");
  assert.deepEqual(s.past[0], { x: 0 });

  s = undoHistory(s);
  assert.deepEqual(s.present, { x: 0 }, "undo reverts the entire gesture at once");
  assert.equal(canUndo(s), false);
}

// An amend with the same reference back is a no-op, same as a push.
{
  let s = initHistory("a");
  s = pushHistory(s, "b");
  const same = amendHistory(s, "b");
  assert.equal(same, s);
}

// Reset starts a fresh document and drops both stacks: a template load or an
// opened topology is a session boundary, not an undo step.
{
  let s = initHistory("a");
  s = pushHistory(s, "b");
  s = undoHistory(s);
  s = pushHistory(s, "c");
  assert.ok(s.past.length || s.future.length || s.present !== "a");

  s = resetHistory("fresh");
  assert.equal(s.present, "fresh");
  assert.deepEqual(s.past, []);
  assert.deepEqual(s.future, []);
  assert.equal(canUndo(s), false);
  assert.equal(canRedo(s), false);
}

// Clear keeps the current document but drops both stacks: Save, Duplicate,
// Publish and Clone are not undone past.
{
  let s = initHistory("a");
  s = pushHistory(s, "b");
  s = pushHistory(s, "c");
  s = undoHistory(s);
  assert.equal(canRedo(s), true);

  s = clearHistory(s);
  assert.equal(s.present, "b");
  assert.deepEqual(s.past, []);
  assert.deepEqual(s.future, []);
  assert.equal(canUndo(s), false);
  assert.equal(canRedo(s), false);

  // Clearing an already-clear state is a no-op (same reference back).
  const same = clearHistory(s);
  assert.equal(same, s);
}

console.log("history.test.mjs: all passed");
