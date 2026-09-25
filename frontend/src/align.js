// Smart alignment guides, the draw.io and Visio gesture: while a node is
// dragged, a guide line appears the moment one of its edges or its centre lines
// up with a sibling, and the drag snaps to that line. This is the "clean
// diagram" half of the product's promise, the part a hard grid cannot do
// because a grid aligns to itself, not to the other shapes.
//
// Everything here works in absolute flow coordinates. The caller compares a
// dragged node only against its siblings (same parent), so nesting never mixes
// coordinate spaces: a teamserver aligns to the other teamservers in its subnet,
// a subnet to the other subnets in its network.

// The bounds a comparison needs, derived from a node's absolute position and
// measured size.
export function bounds(node) {
  const left = node.positionAbsolute?.x ?? node.position?.x ?? 0;
  const top = node.positionAbsolute?.y ?? node.position?.y ?? 0;
  const width = node.width ?? node.style?.width ?? 0;
  const height = node.height ?? node.style?.height ?? 0;
  return {
    left,
    top,
    right: left + width,
    bottom: top + height,
    centerX: left + width / 2,
    centerY: top + height / 2,
    width,
    height,
  };
}

// The candidate snap points along one axis. Each is a line coordinate paired
// with the offset that turns a matched line back into the moving node's left or
// top. Edges match edges (left-left, right-right, and the two crossed pairs so a
// node can butt up against a neighbour) and centre matches centre.
function verticalCandidates(active, other) {
  return [
    { line: other.left, place: other.left }, // left aligns to left
    { line: other.right, place: other.right - active.width }, // right to right
    { line: other.left, place: other.left - active.width }, // right to left (butt)
    { line: other.right, place: other.right }, // left to right (butt)
    { line: other.centerX, place: other.centerX - active.width / 2 }, // centre to centre
  ];
}

function horizontalCandidates(active, other) {
  return [
    { line: other.top, place: other.top },
    { line: other.bottom, place: other.bottom - active.height },
    { line: other.top, place: other.top - active.height },
    { line: other.bottom, place: other.bottom },
    { line: other.centerY, place: other.centerY - active.height / 2 },
  ];
}

// The distance from the moving node to a candidate line, measured on the same
// three reference points that produced the candidates (edges and centre), so a
// left-left candidate is scored by how far the left edges are apart.
function verticalProbes(b) {
  return [b.left, b.right, b.right, b.left, b.centerX];
}
function horizontalProbes(b) {
  return [b.top, b.bottom, b.bottom, b.top, b.centerY];
}

// The nearest alignment of `active` (its bounds) to any of `others` (their
// bounds), within `distance` pixels on each axis independently. Returns the
// snapped absolute left/top to move to (undefined on an axis with no match) and
// the guide line coordinates to draw (vertical is an x, horizontal is a y).
export function alignment(active, others, distance = 5) {
  const result = {
    x: undefined,
    y: undefined,
    vertical: undefined,
    horizontal: undefined,
  };
  let bestV = distance;
  let bestH = distance;

  for (const other of others) {
    const vCands = verticalCandidates(active, other);
    const vProbe = verticalProbes(active);
    for (let i = 0; i < vCands.length; i += 1) {
      const gap = Math.abs(vProbe[i] - vCands[i].line);
      if (gap < bestV) {
        bestV = gap;
        result.x = vCands[i].place;
        result.vertical = vCands[i].line;
      }
    }

    const hCands = horizontalCandidates(active, other);
    const hProbe = horizontalProbes(active);
    for (let i = 0; i < hCands.length; i += 1) {
      const gap = Math.abs(hProbe[i] - hCands[i].line);
      if (gap < bestH) {
        bestH = gap;
        result.y = hCands[i].place;
        result.horizontal = hCands[i].line;
      }
    }
  }

  return result;
}
