import React, { useRef } from "react";
import { Handle, NodeToolbar, Position, useReactFlow } from "@xyflow/react";
import { Icon } from "./icons.jsx";

// The resize frame around a selected container: eight zones on its border, each
// with a window-style resize cursor, that expand or shrink the box on drag. This
// replaces React Flow's NodeResizer, whose drag control quietly did not respond
// to a plain pointer drag here (grabbing it moved the box instead of resizing
// it). These are ordinary pointer handlers, the same kind the edge waypoints
// use, so the drag is ours to control: it never starts a node move, and it
// floors the size at the box's contents so a child is never cropped out.
//
// `node` is the document node (position and any hand-set width/height), `fit` is
// the smallest the box may be, and onResize writes the new geometry back.
const ZONES = [
  { key: "t", edges: { top: true } },
  { key: "b", edges: { bottom: true } },
  { key: "l", edges: { left: true } },
  { key: "r", edges: { right: true } },
  { key: "tl", edges: { top: true, left: true } },
  { key: "tr", edges: { top: true, right: true } },
  { key: "bl", edges: { bottom: true, left: true } },
  { key: "br", edges: { bottom: true, right: true } },
];

function ResizeFrame({ node, fit, onResize }) {
  const { screenToFlowPosition } = useReactFlow();
  const minW = fit?.width || 220;
  const minH = fit?.height || 140;
  const curW = Math.max(node.width || 420, minW);
  const curH = Math.max(node.height || 260, minH);

  const begin = (edges) => (event) => {
    // Ours, not React Flow's: stop the event so no node move or pane pan starts.
    event.stopPropagation();
    const start = screenToFlowPosition({ x: event.clientX, y: event.clientY });
    const base = { x: node.position?.x || 0, y: node.position?.y || 0, w: curW, h: curH };
    const move = (ev) => {
      const p = screenToFlowPosition({ x: ev.clientX, y: ev.clientY });
      const dx = p.x - start.x;
      const dy = p.y - start.y;
      let { x, y, w, h } = base;
      if (edges.right) w = base.w + dx;
      if (edges.left) w = base.w - dx;
      if (edges.bottom) h = base.h + dy;
      if (edges.top) h = base.h - dy;
      w = Math.max(w, minW);
      h = Math.max(h, minH);
      // Dragging a top or left edge keeps the opposite edge pinned, so the box
      // grows away from where it is anchored. The clamp above stops the moving
      // edge once the box hits its minimum.
      if (edges.left) x = base.x + (base.w - w);
      if (edges.top) y = base.y + (base.h - h);
      onResize(node.id, {
        width: Math.round(w),
        height: Math.round(h),
        x: Math.round(x),
        y: Math.round(y),
      });
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  return (
    <div className="rg-resize-frame nodrag nopan">
      {ZONES.map((z) => (
        <div key={z.key} className={`rg-rz rg-rz-${z.key}`} onPointerDown={begin(z.edges)} />
      ))}
    </div>
  );
}

// The actions that sit on a node when it is selected. Delete used to live only
// in the inspector, which meant selecting first, and selecting was the thing
// that was hard. A toolbar on the node itself is the direct affordance.
function NodeActions({ selected, node, onDelete }) {
  // No delete handler means a read only template, so there is nothing to show.
  if (!onDelete) return null;
  return (
    <NodeToolbar isVisible={selected} position={Position.Top} className="rg-node-toolbar">
      <button
        type="button"
        className="rg-danger-text"
        onClick={() => onDelete({ type: "node", id: node.id })}
      >
        Delete
      </button>
    </NodeToolbar>
  );
}

// A host. The chip is the rendered name, which is the prefix plus the id and
// the only name a node has. See 0016.
const MAX_BADGES = 4;

export function HostNode({ data, selected }) {
  const { display, name, node, findings, onRequestDelete, public: reachable, manages, managesLabel, domain, edr, vulnCount, hardeningCount } = data;
  const worst = findings?.[0]?.severity;
  // Host-security badges lead, network badges follow. Capped so a busy host does
  // not wrap its badges onto a second row the card has no height for; the rest
  // collapse into a +N chip that lists them on hover.
  const badges = [];
  if (edr) badges.push({ key: "edr", cls: "is-edr", title: `EDR: ${edr}`, text: edr });
  if (vulnCount) badges.push({ key: "vuln", cls: "is-vuln", title: `${vulnCount} planted vulnerabilities`, text: `${vulnCount} vuln${vulnCount === 1 ? "" : "s"}` });
  if (hardeningCount) badges.push({ key: "hardened", cls: "is-hardened", title: `${hardeningCount} hardening controls`, text: `${hardeningCount} hardened` });
  if (reachable) badges.push({ key: "public", cls: "is-public", title: "Holds a public address on an internet segment", text: "public" });
  if (domain) badges.push({ key: "domain", cls: "is-domain", title: `Joined to ${domain}`, text: domain });
  const shownBadges = badges.slice(0, MAX_BADGES);
  const hiddenBadges = badges.slice(MAX_BADGES);
  return (
    <div
      className={`rg-node ${selected ? "is-selected" : ""} ${worst ? `has-${worst}` : ""}`}
      style={{ borderColor: worst === "error" ? undefined : display.color }}
    >
      <NodeActions selected={selected} node={node} onDelete={onRequestDelete} />
      <Handle type="target" position={Position.Left} />
      {/* Name and what the host is lead the card, the way the jumpbox reads;
          the badges follow on their own row so a long hostname is never pushed
          off the edge behind them. */}
      <div className="rg-node-row">
        <span className="rg-node-icon" style={{ color: display.color }}>
          <Icon icon={display.icon} color={display.color} />
        </span>
        <span className="rg-node-body">
          <span className="rg-node-name">{name}</span>
          <span className="rg-node-sub">{overlaySummary(node)}</span>
        </span>
        {worst ? <span className={`rg-dot is-${worst}`} /> : null}
      </div>
      {badges.length ? (
        <div className="rg-node-badges">
          {shownBadges.map((b) => (
            <span key={b.key} className={`rg-badge ${b.cls}`} title={b.title}>
              {b.text}
            </span>
          ))}
          {hiddenBadges.length ? (
            <span
              className="rg-badge is-more"
              title={hiddenBadges.map((b) => b.text).join(", ")}
            >
              +{hiddenBadges.length}
            </span>
          ) : null}
        </div>
      ) : null}
      {manages?.length ? (
        <span className="rg-node-manages" title={`Manages ${manages.join(", ")}`}>
          <span className="rg-manages-label">manages</span>
          {managesLabel}
        </span>
      ) : null}
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

// A network or a segment. Hosts are dropped inside it, and that nesting is the
// attachment edge.
export function ContainerNode({ data, selected }) {
  const { display, name, node, findings, onRequestDelete, onResizeNode, fit, solo } = data;
  const worst = findings?.[0]?.severity;
  return (
    <>
      {selected && onResizeNode ? (
        <ResizeFrame node={node} fit={fit} onResize={onResizeNode} />
      ) : null}
      <NodeActions selected={selected} node={node} onDelete={onRequestDelete} />
      {/* A network takes the peers edge and a domain takes the trusts edge, so
          both carry handles for an edge to anchor to. A segment has no drawn
          edge, so it carries none; nesting a host into it is a drop. */}
      {node.kind === "network" || node.kind === "domain" ? (
        <Handle type="target" position={Position.Left} />
      ) : null}
      <div
        className={`rg-container is-${node.kind} ${selected ? "is-selected" : ""} ${
          solo && !selected ? "is-solo" : ""
        } ${worst ? `has-${worst}` : ""}`}
      >
        <div className="rg-container-head">
          <span className="rg-container-icon">
            <Icon icon={display.icon} size={15} />
          </span>
          <span className="rg-container-name" title={name}>{name}</span>
          <span className="rg-container-type">{display.label}</span>
          <span className="rg-container-meta" title={overlaySummary(node)}>{overlaySummary(node)}</span>
          {worst ? <span className={`rg-dot is-${worst}`} /> : null}
        </div>
      </div>
      {node.kind === "network" || node.kind === "domain" ? (
        <Handle type="source" position={Position.Right} />
      ) : null}
    </>
  );
}

// Compact an OS id for the card: windows_server_2019 is redundant and eats the
// whole line, so it reads as WS2019, windows_10 as Win10, and so on. The full
// value stays in the inspector.
function osLabel(os) {
  if (!os) return "";
  let m;
  if ((m = /^windows_server_(\d{4})$/.exec(os))) return `WS${m[1]}`;
  if ((m = /^windows_(\d+)$/.exec(os))) return `Win${m[1]}`;
  if ((m = /^ubuntu_(\d\d)(\d\d)$/.exec(os))) return `Ubuntu ${m[1]}.${m[2]}`;
  if ((m = /^debian_(\d+)$/.exec(os))) return `Debian ${m[1]}`;
  return os.replace(/_/g, " ");
}

function overlaySummary(node) {
  const o = node.overlay || {};
  switch (node.kind) {
    case "network":
      return o.cidr || "";
    case "segment":
      return [o.cidr, o.exposure, o.egress === "none" ? "no egress" : null]
        .filter(Boolean)
        .join("  ");
    case "teamserver":
      return o.c2 || "";
    case "redirector":
      // Hostname first: the cover domain is what identifies a redirector at a
      // glance; the server (apache/nginx) is secondary detail.
      return [o.hostname, o.server].filter(Boolean).join("  ");
    case "collector":
      return o.sink || "";
    case "operator":
      return osLabel(o.os);
    case "jumpbox":
      return (o.services || []).join(", ");
    case "domain":
      return [
        o.fqdn,
        o.users?.length ? `${o.users.length} users` : null,
        o.acls?.length ? `${o.acls.length} rights` : null,
      ]
        .filter(Boolean)
        .join("  ·  ");
    case "dc":
    case "srv":
    case "wks":
    case "fw":
    case "appliance":
      return [osLabel(o.os), (o.services || []).join(", ")].filter(Boolean).join("  ");
    case "siem":
      return [o.product, o.hostname].filter(Boolean).join("  ");
    default:
      return "";
  }
}

export const nodeTypes = { host: HostNode, container: ContainerNode };
