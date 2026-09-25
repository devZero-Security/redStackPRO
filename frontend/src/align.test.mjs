import assert from "node:assert/strict";
import { alignment, bounds } from "./align.js";

// A bounds object from a plain rectangle, the shape onNodesChange builds for the
// dragged node.
function rect(x, y, w, h) {
  return {
    left: x,
    top: y,
    right: x + w,
    bottom: y + h,
    centerX: x + w / 2,
    centerY: y + h / 2,
    width: w,
    height: h,
  };
}

// Left edges two pixels apart snap the left edge to the neighbour and draw a
// vertical guide there.
{
  const active = rect(102, 300, 160, 60);
  const other = rect(100, 40, 160, 60);
  const snap = alignment(active, [other], 6);
  assert.equal(snap.vertical, 100, "guide sits on the shared left edge");
  assert.equal(snap.x, 100, "left edge snaps to the neighbour's left");
  assert.equal(snap.horizontal, undefined, "no horizontal match");
  assert.equal(snap.y, undefined);
}

// Centres within threshold snap the centre, so a node can be centred under
// another of a different width.
{
  const active = rect(0, 200, 100, 40); // centreX 50
  const other = rect(20, 0, 160, 40); // centreX 100
  const snap = alignment(active, [other], 6);
  assert.equal(snap.vertical, undefined, "centres 50 apart, edges do not match");
  // Move active so its centre reaches 100: left should be 100 - 50 = 50.
  const near = rect(46, 200, 100, 40); // centreX 96, four from 100
  const snap2 = alignment(near, [other], 6);
  assert.equal(snap2.vertical, 100, "guide on the shared centre line");
  assert.equal(snap2.x, 50, "left placed so centres line up");
}

// A node butting its right edge against a neighbour's left edge.
{
  const active = rect(0, 0, 100, 40); // right 100
  const other = rect(103, 0, 80, 40); // left 103
  const snap = alignment(active, [other], 6);
  assert.equal(snap.vertical, 103, "guide on the neighbour's left edge");
  assert.equal(snap.x, 3, "right edge butts the neighbour, left = 103 - 100");
}

// Beyond the threshold nothing snaps.
{
  const active = rect(200, 200, 100, 40);
  const other = rect(0, 0, 100, 40);
  const snap = alignment(active, [other], 6);
  assert.deepEqual(snap, {
    x: undefined,
    y: undefined,
    vertical: undefined,
    horizontal: undefined,
  });
}

// The two axes resolve independently: top aligns while left does not.
{
  const active = rect(200, 42, 100, 40);
  const other = rect(0, 40, 100, 40);
  const snap = alignment(active, [other], 6);
  assert.equal(snap.horizontal, 40, "tops align");
  assert.equal(snap.y, 40);
  assert.equal(snap.vertical, undefined, "lefts are 200 apart");
  assert.equal(snap.x, undefined);
}

// bounds() reads a React Flow node's absolute position and measured size, and
// falls back to relative position and style width when those are absent.
{
  const b = bounds({ positionAbsolute: { x: 10, y: 20 }, width: 100, height: 40 });
  assert.equal(b.right, 110);
  assert.equal(b.centerY, 40);
  const fallback = bounds({ position: { x: 5, y: 5 }, style: { width: 50 } });
  assert.equal(fallback.left, 5);
  assert.equal(fallback.width, 50);
  assert.equal(fallback.height, 0);
}

console.log("align.test.mjs: all passed");
