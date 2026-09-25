import assert from "node:assert";
import { crossesAny, clearLPath, routeEdge, obstaclesFor } from "./route.js";

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

const box = { x: 80, y: 0, w: 40, h: 100 };

// Does any segment of a polyline cross a rect interior?
function pathCrosses(points, rect) {
  for (let i = 0; i < points.length - 1; i += 1) {
    if (crossesAny(points[i], points[i + 1], [rect])) return true;
  }
  return false;
}

test("crossesAny sees a wall in the path but not one beside it", () => {
  assert.ok(crossesAny({ x: 0, y: 50 }, { x: 200, y: 50 }, [box]));
  assert.ok(!crossesAny({ x: 0, y: 200 }, { x: 200, y: 200 }, [box]));
  // running along the border is not crossing the interior
  assert.ok(!crossesAny({ x: 0, y: 0 }, { x: 200, y: 0 }, [box]));
});

test("clearLPath is true when an L gets around, false when boxed both ways", () => {
  // a wall dead between two points at the same height blocks both Ls
  assert.ok(!clearLPath({ x: 0, y: 50 }, { x: 200, y: 50 }, [box]));
  // with the target below the wall, the down-then-across L is clear
  assert.ok(clearLPath({ x: 0, y: 50 }, { x: 200, y: 200 }, [box]));
});

test("routeEdge returns null when the plain line is already clear", () => {
  const routed = routeEdge(
    { x: 0, y: 200, side: "right" },
    { x: 200, y: 200, side: "left" },
    [box]
  );
  assert.equal(routed, null);
});

test("routeEdge steers around a wall and still reaches both ends", () => {
  const source = { x: 0, y: 50, side: "right" };
  const target = { x: 200, y: 50, side: "left" };
  const routed = routeEdge(source, target, [box]);
  assert.ok(routed, "a route exists");
  assert.deepEqual(routed[0], { x: 0, y: 50 });
  assert.deepEqual(routed[routed.length - 1], { x: 200, y: 50 });
  assert.ok(!pathCrosses(routed, box), "the routed line clears the wall");
  // it is an orthogonal path: every segment is horizontal or vertical
  for (let i = 0; i < routed.length - 1; i += 1) {
    const a = routed[i];
    const b = routed[i + 1];
    assert.ok(a.x === b.x || a.y === b.y, "segment is axis aligned");
  }
});

test("routeEdge never returns a path that crosses a box", () => {
  // A box overlapping the source: the endpoint sits inside a wall, so there is no
  // clean route. routeEdge falls back to null rather than draw a crossing line.
  const onSource = { x: -10, y: 40, w: 40, h: 20 };
  const routed = routeEdge(
    { x: 0, y: 50, side: "right" },
    { x: 200, y: 50, side: "left" },
    [box, onSource]
  );
  if (routed) {
    for (let i = 0; i < routed.length - 1; i += 1) {
      assert.ok(!crossesAny(routed[i], routed[i + 1], [box, onSource]), "no segment crosses");
    }
  }
});

test("obstaclesFor drops the endpoints' own boxes and their ancestors", () => {
  const boxes = [
    { id: "net-a", parentId: undefined, kind: "network", x: 0, y: 0, w: 100, h: 100 },
    { id: "sub-a", parentId: "net-a", kind: "segment", x: 10, y: 10, w: 40, h: 40 },
    { id: "net-b", parentId: undefined, kind: "network", x: 200, y: 0, w: 100, h: 100 },
    { id: "sub-b", parentId: "net-b", kind: "segment", x: 210, y: 10, w: 40, h: 40 },
    { id: "sub-mid", parentId: "net-b", kind: "segment", x: 260, y: 10, w: 30, h: 40 },
  ];
  // a line from a host in sub-a to a host in sub-b: its own boxes and ancestors
  // (net-a, sub-a, net-b, sub-b) are not walls; the unrelated sub-mid is.
  const walls = obstaclesFor(boxes, "sub-a", "sub-b");
  assert.equal(walls.length, 1);
  assert.deepEqual(walls[0], { x: 260, y: 10, w: 30, h: 40 });
});

console.log(`\n${passed} passed`);
