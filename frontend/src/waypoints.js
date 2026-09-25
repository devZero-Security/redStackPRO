// Manual edge routing. A drawn line runs from its source node to its target
// node; between them the user can drop bend points and drag them, to route a
// line clear of a box or another line for the sake of a clean diagram. The
// endpoints stay attached to the nodes: a waypoint moves the line, never what it
// connects. See FloatingEdge.
//
// Waypoints are flow (absolute) coordinates, the same space node positions and
// edge anchors live in, so a point drawn here lands where the path is drawn.
// They are view state, not part of the document: the schema is provider neutral
// and says nothing about how a line is drawn, the same reason node positions are
// presentation. A point list is keyed by edge id on the client.

export function moveWaypoint(list, index, point) {
  return list.map((p, i) => (i === index ? { x: point.x, y: point.y } : p));
}

export function insertWaypoint(list, index, point) {
  const next = list.slice();
  next.splice(index, 0, { x: point.x, y: point.y });
  return next;
}

export function removeWaypoint(list, index) {
  return list.filter((_, i) => i !== index);
}

// The ordered points a path runs through: the source anchor, the waypoints, then
// the target anchor.
export function edgePoints(sourceAnchor, waypoints, targetAnchor) {
  return [sourceAnchor, ...waypoints, targetAnchor];
}

// The midpoint of every segment, tagged with the waypoint index an insertion
// there would take. Segment k runs points[k] to points[k+1]; a bend dropped on
// it becomes waypoint k, because points[0] is the source anchor.
export function segmentMidpoints(points) {
  const mids = [];
  for (let k = 0; k < points.length - 1; k += 1) {
    const a = points[k];
    const b = points[k + 1];
    mids.push({ index: k, x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 });
  }
  return mids;
}

// A point pulled from `from` toward `toward` by `r`, clamped to half the segment
// so a short segment does not overshoot its own midpoint. Used to round corners.
function trim(from, toward, r) {
  const dx = toward.x - from.x;
  const dy = toward.y - from.y;
  const len = Math.hypot(dx, dy) || 1;
  const d = Math.min(r, len / 2);
  return { x: from.x + (dx / len) * d, y: from.y + (dy / len) * d };
}

// An SVG path through the points, straight segments with the interior corners
// rounded so a bent line reads as deliberate wiring rather than a kink.
export function roundedPath(points, radius = 8) {
  if (points.length < 2) return "";
  if (points.length === 2) {
    return `M ${points[0].x},${points[0].y} L ${points[1].x},${points[1].y}`;
  }
  let d = `M ${points[0].x},${points[0].y}`;
  for (let i = 1; i < points.length - 1; i += 1) {
    const cur = points[i];
    const p1 = trim(cur, points[i - 1], radius);
    const p2 = trim(cur, points[i + 1], radius);
    d += ` L ${p1.x},${p1.y} Q ${cur.x},${cur.y} ${p2.x},${p2.y}`;
  }
  const last = points[points.length - 1];
  d += ` L ${last.x},${last.y}`;
  return d;
}
