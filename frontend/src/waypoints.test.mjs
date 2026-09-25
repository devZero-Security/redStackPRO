import assert from "node:assert/strict";
import {
  moveWaypoint,
  insertWaypoint,
  removeWaypoint,
  edgePoints,
  segmentMidpoints,
  roundedPath,
} from "./waypoints.js";

// Move rewrites one point and leaves the rest, returning a new list.
{
  const list = [{ x: 0, y: 0 }, { x: 10, y: 10 }];
  const next = moveWaypoint(list, 1, { x: 5, y: 7 });
  assert.deepEqual(next, [{ x: 0, y: 0 }, { x: 5, y: 7 }]);
  assert.notEqual(next, list, "returns a new array");
  assert.deepEqual(list[1], { x: 10, y: 10 }, "original is untouched");
}

// Insert drops a point at the given index, so a bend on segment k becomes
// waypoint k and pushes the later ones along.
{
  const list = [{ x: 0, y: 0 }, { x: 20, y: 20 }];
  assert.deepEqual(insertWaypoint(list, 1, { x: 10, y: 5 }), [
    { x: 0, y: 0 },
    { x: 10, y: 5 },
    { x: 20, y: 20 },
  ]);
  assert.deepEqual(insertWaypoint([], 0, { x: 1, y: 2 }), [{ x: 1, y: 2 }]);
}

// Remove drops exactly the one, straightening the line back through the rest.
{
  const list = [{ x: 0, y: 0 }, { x: 10, y: 10 }, { x: 20, y: 0 }];
  assert.deepEqual(removeWaypoint(list, 1), [{ x: 0, y: 0 }, { x: 20, y: 0 }]);
}

// Segment midpoints tag the insertion index: with one waypoint there are two
// segments, and a bend on the first takes index 0, on the second index 1.
{
  const points = edgePoints({ x: 0, y: 0 }, [{ x: 10, y: 0 }], { x: 20, y: 0 });
  const mids = segmentMidpoints(points);
  assert.deepEqual(mids, [
    { index: 0, x: 5, y: 0 },
    { index: 1, x: 15, y: 0 },
  ]);
}

// Two points draw a straight line; three round the corner with a quadratic at
// the interior point.
{
  assert.equal(
    roundedPath([{ x: 0, y: 0 }, { x: 10, y: 0 }]),
    "M 0,0 L 10,0"
  );
  const d = roundedPath([{ x: 0, y: 0 }, { x: 10, y: 0 }, { x: 10, y: 10 }], 4);
  assert.match(d, /^M 0,0 /, "starts at the source anchor");
  assert.match(d, /Q 10,0 /, "curves through the corner");
  assert.match(d, /L 10,10$/, "ends at the target anchor");
}

console.log("waypoints.test.mjs: all passed");
