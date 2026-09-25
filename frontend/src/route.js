// Orthogonal edge routing that steers a line clear of the boxes it would
// otherwise cut straight through.
//
// A line with hand-dropped waypoints is left exactly where it was put (that is
// waypoints.js). This is the automatic case: given where a line leaves its
// source and lands on its target, and the container boxes in the way, find an
// orthogonal path around them. The boxes a line is allowed to cross, the source
// and target's own ancestors, are excluded by the caller, so a redirector's line
// leaves its subnet and network and enters the teamserver's without treating
// them as walls.
//
// The method is the textbook one for orthogonal connectors: build a sparse grid
// from the obstacle borders (the Hanan grid), then A* across it preferring
// straight runs over bends. Graphs here are small, so the grid is tiny.

const MARGIN = 14; // gap kept between a routed line and a box it rounds

// Does the axis-aligned segment a->b cross the interior of rect r? Touching a
// border does not count, so a line may run along a box edge, and an endpoint may
// sit on its own (excluded) box.
function hitsRect(a, b, r) {
  const x0 = r.x;
  const x1 = r.x + r.w;
  const y0 = r.y;
  const y1 = r.y + r.h;
  if (a.x === b.x) {
    const x = a.x;
    if (x <= x0 || x >= x1) return false;
    const lo = Math.min(a.y, b.y);
    const hi = Math.max(a.y, b.y);
    return lo < y1 && hi > y0;
  }
  const y = a.y;
  if (y <= y0 || y >= y1) return false;
  const lo = Math.min(a.x, b.x);
  const hi = Math.max(a.x, b.x);
  return lo < x1 && hi > x0;
}

export function crossesAny(a, b, rects) {
  return rects.some((r) => hitsRect(a, b, r));
}

// Either simple L between two points that clears every obstacle. When one does,
// the plain orthogonal line is fine and there is nothing to route around.
export function clearLPath(s, t, rects) {
  const corner1 = { x: t.x, y: s.y };
  const corner2 = { x: s.x, y: t.y };
  const clear = (c) => !crossesAny(s, c, rects) && !crossesAny(c, t, rects);
  return clear(corner1) || clear(corner2);
}

const uniqSorted = (nums) => [...new Set(nums)].sort((a, b) => a - b);

function simplify(pts) {
  if (pts.length <= 2) return pts;
  const out = [pts[0]];
  for (let i = 1; i < pts.length - 1; i += 1) {
    const a = out[out.length - 1];
    const b = pts[i];
    const c = pts[i + 1];
    const collinear = (a.x === b.x && b.x === c.x) || (a.y === b.y && b.y === c.y);
    if (!collinear && !(a.x === b.x && a.y === b.y)) out.push(b);
  }
  out.push(pts[pts.length - 1]);
  return out;
}

// A* over the grid whose lines are the endpoints and the padded obstacle
// borders. Returns the point list from start to end, or null if boxed in.
function routeOrthogonal(start, end, rects, opts = {}) {
  const pad = opts.margin ?? MARGIN;
  const bend = opts.bend ?? 24;
  const xs = uniqSorted([
    start.x, end.x,
    ...rects.flatMap((r) => [r.x - pad, r.x + r.w + pad]),
  ]);
  const ys = uniqSorted([
    start.y, end.y,
    ...rects.flatMap((r) => [r.y - pad, r.y + r.h + pad]),
  ]);
  const xi = new Map(xs.map((v, i) => [v, i]));
  const yi = new Map(ys.map((v, i) => [v, i]));
  const sx = xi.get(start.x);
  const sy = yi.get(start.y);
  const ex = xi.get(end.x);
  const ey = yi.get(end.y);

  const pt = (i, j) => ({ x: xs[i], y: ys[j] });
  const key = (i, j) => i * 100000 + j;
  const heur = (i, j) => Math.abs(xs[i] - end.x) + Math.abs(ys[j] - end.y);

  const open = new Map();
  open.set(key(sx, sy), { i: sx, j: sy, g: 0, f: heur(sx, sy), dir: null, prev: null });
  const best = new Map([[key(sx, sy), 0]]);
  const closed = new Set();

  while (open.size) {
    let cur = null;
    for (const n of open.values()) if (!cur || n.f < cur.f) cur = n;
    open.delete(key(cur.i, cur.j));
    if (cur.i === ex && cur.j === ey) {
      const pts = [];
      for (let n = cur; n; n = n.prev) pts.push(pt(n.i, n.j));
      return pts.reverse();
    }
    closed.add(key(cur.i, cur.j));
    const nbrs = [
      [cur.i - 1, cur.j], [cur.i + 1, cur.j],
      [cur.i, cur.j - 1], [cur.i, cur.j + 1],
    ];
    for (const [ni, nj] of nbrs) {
      if (ni < 0 || nj < 0 || ni >= xs.length || nj >= ys.length) continue;
      if (closed.has(key(ni, nj))) continue;
      if (crossesAny(pt(cur.i, cur.j), pt(ni, nj), rects)) continue;
      const dir = ni !== cur.i ? "h" : "v";
      const step = Math.abs(xs[ni] - xs[cur.i]) + Math.abs(ys[nj] - ys[cur.j]);
      const g = cur.g + step + (cur.dir && cur.dir !== dir ? bend : 0);
      const k = key(ni, nj);
      if (best.has(k) && best.get(k) <= g) continue;
      best.set(k, g);
      open.set(k, { i: ni, j: nj, g, f: g + heur(ni, nj), dir, prev: cur });
    }
  }
  return null;
}

const stub = (p, pad) => {
  switch (p.side) {
    case "top": return { x: p.x, y: p.y - pad };
    case "bottom": return { x: p.x, y: p.y + pad };
    case "left": return { x: p.x - pad, y: p.y };
    default: return { x: p.x + pad, y: p.y };
  }
};

// The routed point list from source to target, leaving and landing straight out
// of each border, or null when the plain line is already clear or no route
// exists. `source`/`target` are { x, y, side }.
export function routeEdge(source, target, rects, opts = {}) {
  if (!rects.length) return null;
  const s = { x: source.x, y: source.y };
  const t = { x: target.x, y: target.y };
  if (clearLPath(s, t, rects)) return null;
  const pad = opts.margin ?? MARGIN;
  const mid = routeOrthogonal(stub(source, pad), stub(target, pad), rects, opts);
  if (!mid) return null;
  const full = simplify([s, ...mid, t]);
  // Never hand back a path that still crosses a box. It can happen when an
  // endpoint sits inside a box overlapping its own, a degenerate hand-drag: the
  // routed middle is clear but the stub in or out is not. Fall back to the plain
  // line rather than draw a worse one.
  for (let i = 0; i < full.length - 1; i += 1) {
    if (crossesAny(full[i], full[i + 1], rects)) return null;
  }
  return full;
}

// The container rectangles a line from sourceId to targetId must avoid: every
// network and segment except the two endpoints and their ancestors, which the
// line is meant to cross. `boxes` are absolute { id, parentId, kind, x, y, w, h }.
export function obstaclesFor(boxes, sourceId, targetId) {
  const parentOf = Object.fromEntries(boxes.map((b) => [b.id, b.parentId]));
  const ancestors = (id) => {
    const set = new Set();
    let c = parentOf[id];
    while (c) { set.add(c); c = parentOf[c]; }
    return set;
  };
  const keep = new Set([sourceId, targetId, ...ancestors(sourceId), ...ancestors(targetId)]);
  return boxes
    .filter((b) => (b.kind === "network" || b.kind === "segment") && !keep.has(b.id))
    .map(({ x, y, w, h }) => ({ x, y, w, h }));
}
