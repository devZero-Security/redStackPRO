import React, { useCallback } from "react";
import {
  BaseEdge,
  getSmoothStepPath,
  Position,
  useReactFlow,
  useStore,
} from "reactflow";
import {
  edgePoints,
  roundedPath,
  segmentMidpoints,
} from "./waypoints.js";
import { obstaclesFor, routeEdge } from "./route.js";

// A line carries no on-canvas label at all: its colour is its role, read off the
// legend, and clicking it opens the inspector with the role and, for a URI line,
// its prefix and ports. Nothing pops up over the board. A transparent wide path
// painted on top of the line gives that click a target wider than the 2px line.
function HitPath({ path, onSelect, title }) {
  return (
    <path
      d={path}
      fill="none"
      stroke="transparent"
      strokeWidth={16}
      style={{ pointerEvents: "stroke", cursor: "pointer" }}
      onClick={onSelect}
    >
      {title ? <title>{title}</title> : null}
    </path>
  );
}

// A short hover label so a line reads without clicking into the inspector or
// cross-referencing the legend. Still no persistent on-canvas label.
const ROLE_TITLE = {
  logs_to: "logs to the collector",
  peers: "network peering",
  manages: "management path",
  joins: "joined to domain",
  attached: "attached",
  fronts: "redirector fronts teamserver",
};
function edgeTitle(edge) {
  if (!edge) return undefined;
  if (edge.role === "trusts") {
    const kind = (edge.trust_type || "trust").replace(/_/g, " ");
    return `${kind} trust`;
  }
  if (edge.role === "fronts") {
    return edge.uri_prefix ? `fronts on ${edge.uri_prefix}` : ROLE_TITLE.fronts;
  }
  return ROLE_TITLE[edge.role] || edge.role;
}

// A drawn edge whose endpoints are computed from where the two nodes actually
// are, not from a fixed handle on each. With fixed left/right handles a line
// from a node on the right to a node on its left had to wrap all the way
// around, which read as the wiring "joining at the wrong points". Here the line
// leaves and lands on the border facing the other node, or facing the first and
// last waypoint once the line has been routed by hand.
//
// A line with no waypoints is routed orthogonally by React Flow. Once the user
// drops a bend it is drawn as straight segments through the waypoints with the
// corners rounded, because manual routing should go exactly where it was put.

function center(node) {
  return {
    x: node.positionAbsolute.x + node.width / 2,
    y: node.positionAbsolute.y + node.height / 2,
  };
}

// Where this edge leaves a node, and on which border, aiming at `point`. The
// border is chosen by the dominant direction to that point: mostly-below leaves
// the bottom, mostly-right leaves the right, and so on. The exit then slides
// along that border to line up with the point, clamped to stay on the face.
// That is what fans three lines out of one redirector into three teamservers as
// three parallel drops instead of one bundle that wraps around the boxes.
const INSET = 14;
function attach(node, point) {
  const c = center(node);
  const dx = point.x - c.x;
  const dy = point.y - c.y;
  const left = node.positionAbsolute.x;
  const right = left + node.width;
  const top = node.positionAbsolute.y;
  const bottom = top + node.height;
  const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi);

  if (Math.abs(dy) >= Math.abs(dx)) {
    return {
      x: clamp(point.x, left + INSET, right - INSET),
      y: dy >= 0 ? bottom : top,
      side: dy >= 0 ? Position.Bottom : Position.Top,
    };
  }
  return {
    x: dx >= 0 ? right : left,
    y: clamp(point.y, top + INSET, bottom - INSET),
    side: dx >= 0 ? Position.Right : Position.Left,
  };
}

export function FloatingEdge({ id, source, target, selected, markerEnd, markerStart, style, data }) {
  const sourceNode = useStore(useCallback((s) => s.nodeInternals.get(source), [source]));
  const targetNode = useStore(useCallback((s) => s.nodeInternals.get(target), [target]));
  const nodeInternals = useStore((s) => s.nodeInternals);
  const { screenToFlowPosition } = useReactFlow();

  // A pointer drag on a handle: `onStart` runs once at pointer down (so a bend is
  // dropped exactly once, not on every move), then `onMove` runs for each move
  // with the flow coordinate. Window listeners rather than the element's own, so
  // the drag survives the pointer leaving the small circle.
  const dragWith = useCallback(
    (onMove, onStart) => (event) => {
      event.stopPropagation();
      const at = (ev) => screenToFlowPosition({ x: ev.clientX, y: ev.clientY });
      if (onStart) onStart(at(event));
      const move = (ev) => onMove(at(ev));
      const up = () => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", up);
      };
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", up);
    },
    [screenToFlowPosition]
  );

  // Until React Flow has measured both nodes there is no geometry to draw from,
  // which is also the case in a headless test where nothing has a size.
  if (!sourceNode?.width || !targetNode?.width) return null;

  const waypoints = data?.waypoints || [];
  const first = waypoints[0] || center(targetNode);
  const last = waypoints[waypoints.length - 1] || center(sourceNode);
  const s = attach(sourceNode, first);
  const t = attach(targetNode, last);

  // The polyline the line is actually drawn through, so the path and the
  // editing dots agree on where the line is.
  let points;
  let path;
  if (waypoints.length > 0) {
    // Hand-drawn: the line goes exactly through the bends it was given.
    points = edgePoints(s, waypoints, t);
    path = roundedPath(points, 10);
  } else {
    // Automatic: route around the container boxes in the way. The line may cross
    // its own source and target boxes (and their ancestors), so those are left
    // out of the obstacles; every other network and segment is a wall.
    const boxes = [];
    for (const n of nodeInternals.values()) {
      const kind = n.data?.node?.kind;
      if ((kind === "network" || kind === "segment") && n.width && n.positionAbsolute) {
        boxes.push({
          id: n.id,
          parentId: n.parentId ?? n.parentNode,
          kind,
          x: n.positionAbsolute.x,
          y: n.positionAbsolute.y,
          w: n.width,
          h: n.height,
        });
      }
    }
    const routed = routeEdge(s, t, obstaclesFor(boxes, source, target));
    if (routed) {
      points = routed;
      path = roundedPath(routed, 10);
    } else {
      // Nothing in the way: the plain orthogonal line React Flow draws.
      points = edgePoints(s, waypoints, t);
      [path] = getSmoothStepPath({
        sourceX: s.x,
        sourceY: s.y,
        sourcePosition: s.side,
        targetX: t.x,
        targetY: t.y,
        targetPosition: t.side,
        borderRadius: 10,
      });
    }
  }

  // The app decides when the handles show: the line is selected, or the node it
  // touches is selected and its lines are lifted. Falls back to React Flow's own
  // selected flag if the app did not say.
  const showHandles = data?.showHandles ?? selected;

  return (
    <>
      <BaseEdge id={id} path={path} markerEnd={markerEnd} markerStart={markerStart} style={style} />
      <HitPath path={path} onSelect={() => data?.onSelect?.(id)} title={edgeTitle(data?.edge)} />
      {showHandles ? (
        <>
          {/* A faint dot at each segment's midpoint: drag it to drop a new bend
              and route the line by hand. */}
          {segmentMidpoints(points).map((m) => (
            <circle
              key={`ghost-${m.index}`}
              className="rg-wp-ghost"
              cx={m.x}
              cy={m.y}
              r={5}
              onPointerDown={dragWith(
                (p) => data?.onWaypointMove?.(id, m.index, p),
                // Drop the bend once where the drag starts, then move that one.
                (start) => data?.onWaypointInsert?.(id, m.index, start)
              )}
            />
          ))}
          {/* A solid dot on each bend: drag to move it, double-click to drop it
              and let the line straighten back through the rest. */}
          {waypoints.map((p, i) => (
            <circle
              key={`wp-${i}`}
              className="rg-wp"
              cx={p.x}
              cy={p.y}
              r={5}
              onPointerDown={dragWith((next) => data?.onWaypointMove?.(id, i, next))}
              onDoubleClick={(event) => {
                event.stopPropagation();
                data?.onWaypointRemove?.(id, i);
              }}
            />
          ))}
        </>
      ) : null}
    </>
  );
}

export const edgeTypes = { floating: FloatingEdge };
