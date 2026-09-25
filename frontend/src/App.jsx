import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, {
  Background,
  ConnectionMode,
  Controls,
  MiniMap,
  Panel,
  ReactFlowProvider,
  useReactFlow,
} from "reactflow";

import { api } from "./api.js";
import { FindingBadge } from "./FindingBadge.jsx";
import { LabList } from "./LabList.jsx";
import { Palette } from "./Palette.jsx";
import { Icon } from "./icons.jsx";
import { Inspector } from "./Inspector.jsx";
import { ExportPanel } from "./Export.jsx";
import { TopologyPicker } from "./TopologyPicker.jsx";
import { ProviderPicker } from "./ProviderPicker.jsx";
import { providersFor, resolveProvider, selectableProviders } from "./providers.js";
import { Library } from "./Library.jsx";
import { ConflictDialog } from "./Conflict.jsx";
import { TemplatePicker } from "./TemplatePicker.jsx";
import { templateFor } from "./templates.js";
import { Extensions } from "./Extensions.jsx";
import { applyExtension, removeExtension } from "./extensions.js";
import { nodeTypes } from "./nodes.jsx";
import { edgeTypes } from "./FloatingEdge.jsx";
import { HelperLines } from "./HelperLines.jsx";
import { CanvasErrorBoundary } from "./ErrorBoundary.jsx";
import { alignment, bounds } from "./align.js";
import { insertWaypoint, moveWaypoint, removeWaypoint } from "./waypoints.js";
import { inspect, record, snapshot } from "./diagnostics.js";
import { coverFor, uriFor } from "./profiles.js";
import { retitle } from "./idscheme.js";
import { autoLayout, layoutIfNeeded } from "./layout.js";
import {
  copyName,
  topologyIdFromUrl,
  sameDocument,
  saveBlockedReason,
  saveMode,
  urlForTopology,
} from "./session.js";
import {
  addEdge,
  addHostPreset,
  addNode,
  applyPositions,
  emptyDocument,
  inferRole,
  isContainer,
  legendItems,
  removeEdge,
  removeNode,
  setJoin,
  setParent,
  toFlow,
  updateEdge,
  updateOverlay,
} from "./topology.js";
import { presetsFor } from "./presets.js";

function useDebounced(value, delay) {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return settled;
}

// The idempotency key for a create. Only the caller knows which attempts are
// the same save, so it owns the key rather than the API wrapper generating one.
function newIdempotencyKey() {
  return window.crypto?.randomUUID
    ? window.crypto.randomUUID()
    : `rg-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function Editor() {
  const [document, setDocument] = useState(() => emptyDocument());

  // Saved state. The backend has no active topology concept: which topology is open
  // is a client concern carried by the URL, because the platform never deploys
  // and holds no reference to a running thing. See 0009.
  //
  // `topology` is the summary the API returned, or null when nothing is saved yet.
  // `saved` is the document as last persisted, and the only thing the unsaved
  // indicator compares against.
  const [topology, setTopology] = useState(null);
  const [topologies, setTopologies] = useState([]);
  const [saved, setSaved] = useState(document);
  const [saving, setSaving] = useState(false);
  const [conflict, setConflict] = useState(null);
  const [libraryOpen, setLibraryOpen] = useState(false);
  const pendingCreate = useRef(null);

  const [palette, setPalette] = useState({});
  const [schema, setSchema] = useState(null);
  const [providers, setProviders] = useState([]);
  const [provider, setProvider] = useState("gcp");
  const [selection, setSelection] = useState(null);
  const [findings, setFindings] = useState([]);
  const [status, setStatus] = useState("");
  // The export panel is the point of the product, so it is a peer of the
  // inspector rather than something buried behind a download button.
  const [panel, setPanel] = useState("inspector");
  const [busy, setBusy] = useState(false);
  // The alignment guides shown while a node is dragged, or null at rest.
  const [guides, setGuides] = useState(null);
  // Canvas telemetry: any document invariant the last change broke. When this is
  // non-empty a banner offers the diagnostics and a way to recover the view. See
  // diagnostics.js.
  const [problems, setProblems] = useState([]);
  // The operator's own registered domains as the raw typed string, so typing a
  // comma is not eaten by a round trip through an array. The parsed list is
  // mirrored to document.domains, which is what saves and reloads with the topology;
  // this string is re-seeded from there whenever a topology opens. See 0043.
  const [domainsText, setDomainsText] = useState("");
  const wrapper = useRef(null);
  const flow = useReactFlow();

  // The current document, reachable from handlers and the error boundary without
  // threading it through their dependencies.
  const docRef = useRef(document);
  docRef.current = document;

  // A loaded GOAD template is viewed, not edited (read-only); a custom range the
  // person builds is editable. templateView is set when a range template loads
  // and cleared when a custom range starts. readOnly gates dragging, connecting,
  // deleting, resizing, and the inspector. See 0047.
  const [templateView, setTemplateView] = useState(false);
  // The template a loaded document came from, while its summary card is on
  // screen. Cleared when the card is dismissed, so it is not document state.
  const [summary, setSummary] = useState(null);
  const readOnly = document.mode === "range" && templateView;

  // Copy the full diagnostics (recent events, document shape, environment) to the
  // clipboard, or log them if the clipboard is unavailable, so a canvas problem
  // can be handed over verbatim.
  const copyDiagnostics = useCallback(async (extra) => {
    const payload = snapshot(docRef.current, extra);
    try {
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
      setStatus("Diagnostics copied. Paste them into the bug report.");
    } catch {
      setStatus("Clipboard blocked; diagnostics logged to the console.");
      // eslint-disable-next-line no-console
      console.log("[redstackpro] diagnostics", payload);
    }
  }, []);

  // Watch the document for a broken invariant on every change, so a coordinate
  // going bad, an orphaned edge, or a missing position is caught the instant it
  // happens rather than after the canvas has silently gone blank. Only a change
  // in the problem set records or re-renders, so a steady bad state is quiet.
  const lastProblems = useRef("");
  useEffect(() => {
    const found = inspect(document);
    const sig = found.join("|");
    if (sig === lastProblems.current) return;
    lastProblems.current = sig;
    if (found.length) {
      record("corruption", { problems: found.slice(0, 8), nodes: document.nodes.length });
    }
    setProblems(found);
  }, [document]);

  // Ids the person has renamed by hand. The default scheme owns every other id
  // and re-derives it when contents change; a pinned id is left alone. Held in a
  // ref because it steers the retitle effect below without needing to re-render.
  // The pin also persists on the node itself (node.pinned), so a hand-picked name
  // survives a reload; retitle honours either source. See idscheme.js and 0043.
  const pinned = useRef(new Set());

  // Keep every unpinned node's id on the default scheme. Adding a redirector to a
  // subnet makes it a redirector subnet; swapping it for a teamserver renames it
  // again; a jumpbox next to the operators makes the network "main". retitle is a
  // no-op once the ids already agree, so this settles in one pass and does not
  // loop. It also follows the selection onto the renamed node. See idscheme.js.
  useEffect(() => {
    // Range naming is deferred: the GOAD templates keep their canonical names,
    // so the auto-rename runs on ops only. See 0047.
    if (document.mode === "range") return;
    const { document: next, renamed } = retitle(document, pinned.current);
    const moved = Object.keys(renamed);
    if (moved.length === 0) return;
    record("retitle", renamed);
    setDocument(next);
    setSelection((sel) =>
      sel?.type === "node" && renamed[sel.id] ? { ...sel, id: renamed[sel.id] } : sel
    );
  }, [document]);

  // Ctrl+Shift+D copies the diagnostics from anywhere, so a report can be grabbed
  // even when the canvas is misbehaving.
  useEffect(() => {
    const onKey = (event) => {
      if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key.toLowerCase() === "d") {
        event.preventDefault();
        record("copy-diagnostics", { via: "shortcut" });
        copyDiagnostics();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [copyDiagnostics]);

  useEffect(() => {
    api.schema().then(setSchema).catch(() => {});
    api
      .providers()
      .then((body) => setProviders(body.providers))
      .catch(() => {});
  }, []);

  // Keep the chosen provider one this mode can actually build. The toolbar used
  // to correct only what it DREW -- a range pointed at a provider with no Windows
  // image displayed "aws" while the state behind it stayed put, so the canvas
  // showed one target and compiled for another. Correcting the state instead
  // means what is on screen is what gets compiled.
  useEffect(() => {
    if (!providers.length) return;
    setProvider((current) => resolveProvider(document.mode, providers, current));
  }, [document.mode, providers]);

  // The palette is the current canvas's kinds, so it re-fetches when the mode
  // changes: redStackPRO shows the red-team kinds, Cyber Ranges the range kinds.
  useEffect(() => {
    api.palette(document.mode).then((body) => setPalette(body.groups)).catch(() => {});
  }, [document.mode]);

  // ---------------------------------------------------------------- saving
  //
  // Save is explicit. 0008 records that revision growth needs a debounce on the
  // client so that dragging nodes for an hour does not produce hundreds of
  // rows, and an explicit save is the version of that with no rows nobody
  // asked for. See 0018.

  const dirty = useMemo(() => !sameDocument(saved, document), [saved, document]);

  // The summary card is orientation, and orientation stops being wanted the
  // moment somebody starts working, so the first edit takes it away.
  //
  // Keyed on the document's identity rather than on `dirty`: loading a template
  // makes the document dirty against an empty baseline immediately, so `dirty`
  // is already true while the card is still wanted and never changes again.
  // Every edit replaces the document object, which is the signal that fires
  // once per change.
  const summaryDocRef = useRef(null);
  useEffect(() => {
    if (summary && document !== summaryDocRef.current) setSummary(null);
  }, [document, summary]);
  const blocked = saveBlockedReason({ conflict, compiling: busy, saving, dirty });

  const refreshTopologies = useCallback(() => {
    api.listTopologies().then(setTopologies).catch(() => {});
  }, []);

  const pushUrl = useCallback((id) => {
    if (topologyIdFromUrl(window.location.search) === id) return;
    window.history.pushState(
      { topology: id },
      "",
      urlForTopology(id, window.location.search, window.location.pathname)
    );
  }, []);

  // Every write path ends here: the summary the API returned becomes the open
  // topology, the document that was sent becomes the clean baseline, and the URL
  // names it so a reload comes back to the same place.
  const adopt = useCallback(
    (summary, sent) => {
      setTopology(summary);
      setSaved(sent);
      setConflict(null);
      pushUrl(summary.id);
    },
    [pushUrl]
  );

  const openTopology = useCallback(
    async (id, { push = true } = {}) => {
      try {
        const body = await api.getTopology(id);
        // A saved topology carries its positions, so it is not laid out again.
        // Only a document that never had any gets arranged, and that layout is
        // deterministic, so what is on screen is what a reload reproduces.
        const doc = layoutIfNeeded(body.document);
        setDocument(doc);
        setSaved(doc);
        setDomainsText((doc.domains || []).join(", "));
        setTopology(body.topology);
        setSelection(null);
        setConflict(null);
        setStatus("");
        if (push) pushUrl(id);
        setTimeout(() => flow.fitView({ padding: 0.15, duration: 300 }), 60);
      } catch (error) {
        setStatus(error.message);
      }
    },
    [flow, pushUrl]
  );

  const confirmDiscard = useCallback(() => {
    if (!dirty) return true;
    return window.confirm(
      "This topology has unsaved changes. Leaving it discards them."
    );
  }, [dirty]);

  const resetToEmpty = useCallback((mode = "ops") => {
    const doc = emptyDocument(mode);
    setDocument(doc);
    setSaved(doc);
    setDomainsText("");
    setTopology(null);
    setSelection(null);
    setConflict(null);
    setStatus("");
    setTemplateView(false); // a fresh topology is editable; a range template sets this true on load
  }, []);

  // New opens the canvas chooser; picking a canvas starts a fresh topology in that
  // mode. The mode is fixed at creation, so this never converts the open topology.
  // Cyber Ranges opens straight into its template picker, since range mode is
  // read-only templates for now.
  const [templatePickerOpen, setTemplatePickerOpen] = useState(false);
  const [extensionsOpen, setExtensionsOpen] = useState(false);
  const newTopology = useCallback(() => {
    if (!confirmDiscard()) return;
    resetToEmpty(docRef.current.mode); // a fresh topology in the current canvas
    pushUrl(null);
  }, [confirmDiscard, resetToEmpty, pushUrl]);
  // Switch canvas from the header. Clicking the active canvas keeps the open
  // topology; switching starts a fresh one in that mode (a GOAD template is loaded
  // read-only from Load template, Cyber Ranges otherwise opens a custom range).
  const chooseMode = useCallback(
    (mode) => {
      if (docRef.current.mode === mode) return;
      if (!confirmDiscard()) return;
      resetToEmpty(mode);
      pushUrl(null);
    },
    [confirmDiscard, resetToEmpty, pushUrl]
  );

  const pickTopology = useCallback(
    (id) => {
      if (id === topology?.id) return;
      if (!confirmDiscard()) return;
      openTopology(id);
    },
    [confirmDiscard, topology, openTopology]
  );

  const create = useCallback(async (doc, name) => {
    // The key stays the same while the document does, so a retry after a
    // timeout returns the topology the first attempt made rather than a second
    // one. An edit in between is a different save and takes a fresh key.
    if (pendingCreate.current?.document !== doc) {
      pendingCreate.current = { key: newIdempotencyKey(), document: doc };
    }
    const summary = await api.createTopology(name, doc, pendingCreate.current.key);
    pendingCreate.current = null;
    return summary;
  }, []);

  // Forking is a create carrying the document in the canvas, not the duplicate
  // endpoint, which copies what is stored. On a conflict that stored document
  // is the revision that just won, so duplicating it would throw away the one
  // thing worth keeping.
  const fork = useCallback(
    async (suffix) => {
      const doc = { ...document, name: copyName(document.name, suffix) };
      setSaving(true);
      try {
        const summary = await create(doc, doc.name);
        setDocument(doc);
        adopt(summary, doc);
        refreshTopologies();
        setStatus(`Kept your version as ${summary.name}. You own it, and it is private.`);
      } catch (error) {
        setStatus(error.message);
      } finally {
        setSaving(false);
      }
    },
    [adopt, create, document, refreshTopologies]
  );

  const save = useCallback(async () => {
    if (blocked) {
      setStatus(blocked);
      return;
    }
    const mode = saveMode(topology);
    // An org visible topology owned by someone else is read only, and reuse is by
    // copy rather than a failed write. See 0009.
    if (mode === "fork") {
      await fork("copy");
      return;
    }

    setSaving(true);
    try {
      if (mode === "update") {
        // The name is a column as well as a document field, so both go on
        // every write or the picker drifts from the header input.
        const summary = await api.saveTopology(topology.id, document, topology.version, {
          name: document.name,
        });
        adopt(summary, document);
        setStatus(`Saved version ${summary.version}. Nothing was deployed.`);
      } else {
        const summary = await create(document, document.name);
        adopt(summary, document);
        setStatus(`Saved version ${summary.version}. Nothing was deployed.`);
      }
      refreshTopologies();
    } catch (error) {
      if (error.status === 409) setConflict(error.details || {});
      else setStatus(error.message);
    } finally {
      setSaving(false);
    }
  }, [adopt, blocked, create, document, fork, topology, refreshTopologies]);

  const duplicate = useCallback(async () => {
    if (!topology) return;
    if (
      dirty &&
      !window.confirm(
        "Duplicate copies the last saved revision. Your unsaved changes are not copied and stay here."
      )
    ) {
      return;
    }
    try {
      const summary = await api.duplicateTopology(topology.id);
      refreshTopologies();
      await openTopology(summary.id);
      setStatus(`Duplicated as ${summary.name}. It is private and you own it.`);
    } catch (error) {
      setStatus(error.message);
    }
  }, [dirty, topology, openTopology, refreshTopologies]);

  // ---------------------------------------------------------------- library
  //
  // The library returns true when it navigated, so it knows to close, and false
  // when the discard prompt was declined, so it stays open on the topology the
  // person kept. Delete and publish stay open and let the library reload.

  const openFromLibrary = useCallback(
    async (id) => {
      if (id === topology?.id) return true;
      if (!confirmDiscard()) return false;
      await openTopology(id);
      return true;
    },
    [confirmDiscard, topology, openTopology]
  );

  const cloneBlueprint = useCallback(
    async (id) => {
      if (!confirmDiscard()) return false;
      const summary = await api.cloneBlueprint(id);
      refreshTopologies();
      await openTopology(summary.id);
      setStatus(`Cloned as ${summary.name}. It is private and you own it.`);
      return true;
    },
    [confirmDiscard, openTopology, refreshTopologies]
  );

  // Delete is owner only and hard: the topology and every revision go, and an
  // orphaned compile result ages out on its own. Deleting the open topology leaves
  // the canvas on an empty document rather than a dangling id. See 0026.
  const removeTopology = useCallback(
    async (id) => {
      const isOpen = id === topology?.id;
      const warning = isOpen
        ? "Delete the topology you have open? It and every revision are removed for good. This cannot be undone."
        : "Delete this topology? It and every revision are removed for good. This cannot be undone.";
      if (!window.confirm(warning)) return;
      await api.deleteTopology(id);
      if (isOpen) {
        resetToEmpty();
        pushUrl(null);
      }
      refreshTopologies();
      setStatus("Deleted. Nothing was deployed.");
    },
    [topology, pushUrl, refreshTopologies, resetToEmpty]
  );

  // Publishing flags the live topology rather than snapshotting it, so it leaves
  // the personal list and joins the blueprint library, still owned and still
  // editable. Unpublishing reverses that. See 0025.
  const publishTopology = useCallback(
    async (id) => {
      if (
        !window.confirm(
          "Offer this topology as a blueprint? Anyone can clone it into their own copy. " +
            "It stays yours and editable, but it leaves your topologies list for the blueprint library."
        )
      ) {
        return;
      }
      await api.publishBlueprint(id);
      setTopology((current) =>
        current && current.id === id ? { ...current, is_blueprint: true } : current
      );
      refreshTopologies();
      setStatus("Published as a blueprint. Anyone can clone it.");
    },
    [refreshTopologies]
  );

  const unpublishTopology = useCallback(
    async (id) => {
      await api.unpublishBlueprint(id);
      setTopology((current) =>
        current && current.id === id ? { ...current, is_blueprint: false } : current
      );
      refreshTopologies();
      setStatus("Unpublished. It is back in your topologies list.");
    },
    [refreshTopologies]
  );

  const reloadOverMine = useCallback(async () => {
    if (!topology) return;
    setConflict(null);
    await openTopology(topology.id, { push: false });
    setStatus("Reloaded the saved version. Your edits are gone.");
  }, [topology, openTopology]);

  // Read the URL on mount, so a reload restores what was open and a link opens
  // the topology it names.
  useEffect(() => {
    refreshTopologies();
    const id = topologyIdFromUrl(window.location.search);
    if (id) {
      openTopology(id, { push: false });
    }
  }, []);

  // Back and forward move between topologies, because the URL is what says which
  // one is open. Declining the prompt puts the URL back.
  useEffect(() => {
    const onPop = () => {
      const id = topologyIdFromUrl(window.location.search);
      if (id === (topology?.id || null)) return;
      if (!confirmDiscard()) {
        window.history.pushState(
          { topology: topology?.id || null },
          "",
          urlForTopology(topology?.id || null, window.location.search, window.location.pathname)
        );
        return;
      }
      if (id) openTopology(id, { push: false });
      else resetToEmpty();
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [confirmDiscard, topology, openTopology, resetToEmpty]);

  // The browser's own prompt. It cannot be worded or styled, and it is the only
  // thing that survives a tab close.
  useEffect(() => {
    if (!dirty) return undefined;
    const warn = (event) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);

  useEffect(() => {
    const onKey = (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        save();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [save]);

  // Validation runs against the API on every settled change, so what the canvas
  // shows and what the compiler will refuse are the same rules. Debounced,
  // because a drag produces a change per frame.
  const settled = useDebounced(document, 350);
  useEffect(() => {
    if (!settled.nodes.length) {
      setFindings([]);
      return;
    }
    let cancelled = false;
    api
      .validate(settled, provider)
      .then((body) => {
        if (!cancelled) setFindings(body.findings);
      })
      .catch((error) => {
        if (!cancelled) {
          setFindings([]);
          setStatus(error.message);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [settled, provider]);

  const findingsFor = useCallback(
    (id) => findings.filter((f) => f.target_ids.includes(id)),
    [findings]
  );

  // Deleting straight from a node's toolbar, without going through the
  // inspector first. Stable, because it goes into every node's data and an
  // identity that changed every render would defeat the cache below.
  const requestDelete = useCallback((target) => {
    record("delete", { type: target.type, id: target.id });
    setDocument((current) =>
      target.type === "edge"
        ? removeEdge(current, target.id)
        : removeNode(current, target.id)
    );
    setSelection((current) => (current?.id === target.id ? null : current));
  }, []);

  // Resizing a container writes its new geometry straight to the document. Width
  // and height are floored by the resize frame at the box's contents, so this
  // never crops a child; position moves only when a top or left edge is dragged.
  const resizeNode = useCallback((id, box) => {
    setDocument((current) => ({
      ...current,
      nodes: current.nodes.map((n) =>
        n.id === id
          ? { ...n, width: box.width, height: box.height, position: { x: box.x, y: box.y } }
          : n
      ),
    }));
  }, []);

  // Apply a themed cover profile to a redirector: fill its hostname, gating
  // header, and decoy, and re-roll the URI prefix on every fronts edge it serves
  // from the theme's pool, unique so no two upstreams collide. One click makes a
  // redirector read convincingly as one kind of site. See profiles.js.
  const applyCover = useCallback((id, themeKey) => {
    record("apply-cover", { redirector: id, theme: themeKey });
    setDocument((current) => {
      const cover = coverFor(themeKey, undefined, current.domains || []);
      const nodes = current.nodes.map((n) =>
        n.id === id
          ? {
              ...n,
              overlay: {
                ...(n.overlay || {}),
                // Only when the cover had a domain of the operator's to build on.
                // Otherwise leave the field as it is, which is usually empty, and
                // let RDR001 hold the compile until they supply a name they own.
                ...(cover.hostname ? { hostname: cover.hostname } : {}),
                gating: {
                  ...(n.overlay?.gating || {}),
                  header_name: cover.header_name,
                  header_value: cover.header_value,
                  decoy: cover.decoy,
                },
              },
            }
          : n
      );
      const taken = [];
      const edges = current.edges.map((e) => {
        if (e.role !== "fronts" || e.source !== id) return e;
        const uri = uriFor(themeKey, taken);
        taken.push(uri);
        return { ...e, uri_prefix: uri };
      });
      return { ...current, nodes, edges };
    });
  }, []);

  // Editing the operator's own domains: keep the raw text for the field, and
  // mirror the parsed list to document.domains so it saves with the topology.
  const changeDomains = useCallback((text) => {
    setDomainsText(text);
    const list = text
      .split(",")
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean);
    setDocument((current) => ({ ...current, domains: list }));
  }, []);

  // Re-roll one fronts edge's URI prefix, themed by its redirector's decoy, and
  // kept clear of the prefixes its siblings already use.
  const randomizeUri = useCallback((edgeId) => {
    record("randomize-uri", { edge: edgeId });
    setDocument((current) => {
      const edge = current.edges.find((e) => e.id === edgeId);
      if (!edge) return current;
      const source = current.nodes.find((n) => n.id === edge.source);
      const theme = source?.overlay?.gating?.decoy || "cdn";
      const taken = current.edges
        .filter((e) => e.role === "fronts" && e.source === edge.source && e.id !== edgeId)
        .map((e) => e.uri_prefix)
        .filter(Boolean);
      const uri = uriFor(theme, taken);
      return {
        ...current,
        edges: current.edges.map((e) => (e.id === edgeId ? { ...e, uri_prefix: uri } : e)),
      };
    });
  }, []);

  // The base conversion depends only on the document and the palette, so it does
  // not rerun when findings arrive every third of a second. That is what used to
  // rebuild every node four times a second and drop clicks that landed mid
  // rebuild.
  const baseFlow = useMemo(() => toFlow(document, palette), [document, palette]);

  // Findings and selection are layered on top, and a node keeps its object
  // identity when neither changed, so React Flow sees a stable node and a click
  // is not interrupted by a rerender. The cache is keyed by the base node
  // identity, which only changes when the document does.
  const nodeCache = useRef(new Map());
  const nodes = useMemo(() => {
    const out = baseFlow.nodes.map((base) => {
      const nodeFindings = findingsFor(base.id);
      const selected = selection?.type === "node" && selection.id === base.id;
      const sig = `${selected}|${nodeFindings.map((f) => f.code + f.severity).join(",")}`;
      const cached = nodeCache.current.get(base.id);
      if (cached && cached.base === base && cached.sig === sig) return cached.node;
      const node = {
        ...base,
        selected,
        // A selected container rides above its own children so its resize frame
        // is grabbable on every edge. Otherwise a child (hosts sit at a higher
        // z) covers the border and the drag grabs the child instead of the box.
        zIndex: base.type === "container" && selected ? 20 : base.zIndex,
        data: {
          ...base.data,
          findings: nodeFindings,
          onRequestDelete: readOnly ? undefined : requestDelete,
          onResizeNode: readOnly ? undefined : resizeNode,
        },
      };
      nodeCache.current.set(base.id, { base, sig, node });
      return node;
    });
    const live = new Set(baseFlow.nodes.map((n) => n.id));
    for (const id of nodeCache.current.keys()) {
      if (!live.has(id)) nodeCache.current.delete(id);
    }
    return out;
  }, [baseFlow, findings, selection, findingsFor, requestDelete, resizeNode, readOnly]);

  // Clicking a line's label selects the edge, the same as clicking the line, so
  // the labels a person naturally aims at are a way into the inspector rather
  // than dead chips. Stable so it does not churn the edge objects.
  const selectEdge = useCallback((id) => {
    setSelection({ type: "edge", id });
    setPanel("inspector");
  }, []);

  // Routing a line by hand. The bend points live on the edge in the document, so
  // they save and reload with the topology; each edit works on that edge's own list,
  // so dragging one bend never touches another line or the edge's endpoints.
  const editWaypoints = useCallback((edgeId, fn) => {
    setDocument((current) => ({
      ...current,
      edges: current.edges.map((e) =>
        e.id === edgeId ? { ...e, waypoints: fn(e.waypoints || []) } : e
      ),
    }));
  }, []);
  const round = (point) => ({ x: Math.round(point.x), y: Math.round(point.y) });
  const moveWaypointAt = useCallback(
    (edgeId, index, point) => editWaypoints(edgeId, (list) => moveWaypoint(list, index, round(point))),
    [editWaypoints]
  );
  const insertWaypointAt = useCallback(
    (edgeId, index, point) => editWaypoints(edgeId, (list) => insertWaypoint(list, index, round(point))),
    [editWaypoints]
  );
  const removeWaypointAt = useCallback(
    (edgeId, index) => editWaypoints(edgeId, (list) => removeWaypoint(list, index)),
    [editWaypoints]
  );
  // Straighten: drop the whole list so the line routes itself again.
  const clearWaypoints = useCallback(
    (edgeId) => editWaypoints(edgeId, () => []),
    [editWaypoints]
  );

  const edges = useMemo(() => {
    // Selecting a node lifts its own lines and fades the rest, so the wiring for
    // the thing you clicked stands out of the whole web at once.
    const nodeSel = selection?.type === "node" ? selection.id : null;
    return baseFlow.edges.map((e) => {
      const worst = findingsFor(e.id)[0];
      const selected = selection?.type === "edge" && selection.id === e.id;
      const touches = nodeSel && (e.source === nodeSel || e.target === nodeSel);
      const dim = nodeSel && !touches;
      const data = {
        ...e.data,
        onSelect: selectEdge,
        // The bend handles show when the line itself is selected, and also when
        // the node it touches is selected and its lines are lifted, so a node's
        // logs_to lines can be routed straight from the node without hunting for
        // each line first.
        showHandles: selected || Boolean(touches),
        waypoints: e.data.edge.waypoints || [],
        onWaypointMove: moveWaypointAt,
        onWaypointInsert: insertWaypointAt,
        onWaypointRemove: removeWaypointAt,
      };
      const errorEdge = worst?.severity === "error";
      const base = errorEdge ? "#e03131" : e.style.stroke;
      // At rest every line is muted so the boxes read first; selecting a node
      // lifts its own lines and pushes the rest well back; selecting a line
      // lifts that one. An error line always stays fully visible. See the
      // dim-at-rest request.
      let opacity;
      if (errorEdge) opacity = 1;
      else if (!selection) opacity = 0.4;
      else if (nodeSel) opacity = touches ? 1 : 0.12;
      else opacity = selected ? 1 : 0.4;
      return {
        ...e,
        selected,
        data,
        style: {
          ...e.style,
          stroke: base,
          strokeWidth: touches || selected ? 3.5 : 2,
          opacity,
        },
      };
    });
  }, [
    baseFlow,
    findings,
    selection,
    findingsFor,
    selectEdge,
    moveWaypointAt,
    insertWaypointAt,
    removeWaypointAt,
  ]);

  // The display label per kind, so the inspector reads the same word the palette
  // does rather than the raw schema kind.
  const kindLabels = useMemo(
    () =>
      Object.fromEntries(
        Object.values(palette)
          .flat()
          .map((entry) => [entry.kind, entry.label])
      ),
    [palette]
  );

  // Smart guides. A single dragged node is snapped to its siblings (same parent,
  // so a teamserver lines up with the other teamservers in its subnet, never
  // with a node in a different box) and the matching guide line is shown. The
  // snap rewrites the change's position in place, so the existing writer below
  // stores the aligned value. Anything but a lone drag clears the guides.
  const snapToGuides = useCallback(
    (changes) => {
      const drags = changes.filter(
        (c) => c.type === "position" && c.dragging && c.position
      );
      if (drags.length !== 1) {
        if (changes.some((c) => c.type === "position" && !c.dragging)) {
          setGuides(null);
        }
        return;
      }
      const change = drags[0];
      const dragged = flow.getNode(change.id);
      if (!dragged) return;
      const parentId = dragged.parentId || undefined;
      const parentAbs = parentId
        ? flow.getNode(parentId)?.positionAbsolute || { x: 0, y: 0 }
        : { x: 0, y: 0 };
      const width = dragged.width ?? 0;
      const height = dragged.height ?? 0;
      const left = parentAbs.x + change.position.x;
      const top = parentAbs.y + change.position.y;
      const active = {
        left,
        top,
        right: left + width,
        bottom: top + height,
        centerX: left + width / 2,
        centerY: top + height / 2,
        width,
        height,
      };
      const siblings = flow
        .getNodes()
        .filter((n) => n.id !== change.id && (n.parentId || undefined) === parentId)
        .map(bounds);
      const snap = alignment(active, siblings, 6);
      if (snap.x !== undefined) {
        change.position = { ...change.position, x: snap.x - parentAbs.x };
      }
      if (snap.y !== undefined) {
        change.position = { ...change.position, y: snap.y - parentAbs.y };
      }
      setGuides(
        snap.vertical === undefined && snap.horizontal === undefined
          ? null
          : { vertical: snap.vertical, horizontal: snap.horizontal }
      );
    },
    [flow]
  );

  const onNodesChange = useCallback((changes) => {
    snapToGuides(changes);
    setDocument((current) => {
      let next = current;
      for (const change of changes) {
        if (change.type === "position" && change.position) {
          next = {
            ...next,
            nodes: next.nodes.map((n) =>
              n.id === change.id ? { ...n, position: change.position } : n
            ),
          };
        }
        // Dimensions changes here are React Flow's own DOM measurements, which
        // lag a render behind. Storing them would overwrite a container's
        // hand-set size with the pre-resize measurement mid-drag. Size is owned
        // by the resize frame (resizeNode) instead, so these are ignored.
        if (change.type === "remove") next = removeNode(next, change.id);
      }
      return next;
    });
  }, [snapToGuides]);

  const onEdgesChange = useCallback((changes) => {
    setDocument((current) => {
      let next = current;
      for (const change of changes) {
        if (change.type === "remove") next = removeEdge(next, change.id);
      }
      return next;
    });
  }, []);

  // The role follows from what the line connects, so the canvas never asks.
  // Dragging a line's end onto another node moves it there, the Visio gesture.
  // The role is kept; if the new pair no longer supports it the validator says
  // so, rather than the canvas silently refusing the drag.
  const onReconnect = useCallback((oldEdge, conn) => {
    if (!conn.source || !conn.target) return;
    setDocument((current) => ({
      ...current,
      edges: current.edges.map((e) =>
        e.id === oldEdge.id
          ? { ...e, source: conn.source, target: conn.target }
          : e
      ),
    }));
  }, []);

  // Adding a connection from the inspector, for people who would rather pick the
  // other end from a list than drag a line. The role is inferred from the two
  // kinds when left unset, the same as drawing it.
  const onAddEdge = useCallback((source, target, role) => {
    setDocument((current) => {
      const kinds = Object.fromEntries(current.nodes.map((n) => [n.id, n.kind]));
      const r = role || inferRole(kinds[source], kinds[target]);
      if (!r) {
        setStatus(
          `No role connects a ${kinds[source]} to a ${kinds[target]}. Pick one.`
        );
        return current;
      }
      const extra =
        r === "fronts"
          ? { protocol: "https", listen_port: 443, upstream_port: 443, uri_prefix: "/cdn/assets" }
          : {};
      return addEdge(current, source, target, r, extra);
    });
  }, []);

  // Range authoring without drawing lines: pick a host's domain or subnet from
  // the inspector and the joins or attached edge is rewritten in one step. See
  // setJoin and setParent.
  const onJoinDomain = useCallback((hostId, domainId) => {
    record("join-domain", { host: hostId, domain: domainId });
    setDocument((current) => setJoin(current, hostId, domainId));
  }, []);

  const onPlaceSubnet = useCallback((hostId, subnetId) => {
    record("place-subnet", { host: hostId, subnet: subnetId });
    setDocument((current) => setParent(current, hostId, subnetId));
  }, []);

  const onConnect = useCallback(
    ({ source, target }) => {
      setDocument((current) => {
        const kinds = Object.fromEntries(current.nodes.map((n) => [n.id, n.kind]));
        const role = inferRole(kinds[source], kinds[target]);
        if (!role) {
          setStatus(
            `No role connects a ${kinds[source]} to a ${kinds[target]}. Attachment is nesting, not a line.`
          );
          return current;
        }
        setStatus("");
        const extra =
          role === "fronts"
            ? { protocol: "https", listen_port: 443, upstream_port: 443, uri_prefix: "/cdn/assets" }
            : {};
        return addEdge(current, source, target, role, extra);
      });
    },
    []
  );

  // Dropping a node inside a container is the attachment edge.
  // A drop-to-delete bin. It appears while a node is being dragged; releasing a
  // node over it removes the node, which is quicker than selecting and pressing
  // Backspace when clearing several off the canvas.
  const binRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [binHot, setBinHot] = useState(false);

  const overBin = useCallback((event) => {
    const el = binRef.current;
    if (!el) return false;
    const r = el.getBoundingClientRect();
    return (
      event.clientX >= r.left && event.clientX <= r.right &&
      event.clientY >= r.top && event.clientY <= r.bottom
    );
  }, []);

  const onNodeDragStart = useCallback(() => setDragging(true), []);
  const onNodeDrag = useCallback(
    (event) => setBinHot(overBin(event)),
    [overBin]
  );

  const onNodeDragStop = useCallback(
    (_event, dragged) => {
      setGuides(null);
      // Dropped on the bin: delete the node instead of reparenting it. Read the
      // bin rect before clearing the dragging flag, which unmounts it.
      const droppedOnBin = overBin(_event);
      setDragging(false);
      setBinHot(false);
      if (droppedOnBin) {
        record("delete-bin", { node: dragged.id });
        setDocument((current) => removeNode(current, dragged.id));
        return;
      }
      const point = flow.screenToFlowPosition({
        x: _event.clientX,
        y: _event.clientY,
      });
      setDocument((current) => {
        const kinds = Object.fromEntries(current.nodes.map((n) => [n.id, n.kind]));
        // A subnet nests into a network, a host into a subnet. A network nests
        // into nothing.
        if (kinds[dragged.id] === "network") return current;
        const wants = kinds[dragged.id] === "segment" ? "network" : "segment";
        const container = flow
          .getNodes()
          .filter((n) => n.id !== dragged.id && kinds[n.id] === wants)
          .find((n) => {
            const origin = flow.getNode(n.id)?.positionAbsolute || n.position;
            const width = n.width || n.style?.width || 0;
            const height = n.height || n.style?.height || 0;
            return (
              point.x >= origin.x &&
              point.x <= origin.x + width &&
              point.y >= origin.y &&
              point.y <= origin.y + height
            );
          });

        // React Flow stores a child's position relative to its parent. The
        // dragged node's position was absolute (or relative to a former parent);
        // rewrite it relative to the new parent so it stays exactly where it was
        // dropped rather than jumping by the parent's offset. Dropping outside a
        // container makes the position absolute again. Without this, nesting a
        // subnet then a host compounds the offsets and flings nodes thousands of
        // pixels away, which then blows up a container's fit on resize.
        const abs = dragged.positionAbsolute || dragged.position || { x: 0, y: 0 };
        const parentAbs = container
          ? flow.getNode(container.id)?.positionAbsolute || { x: 0, y: 0 }
          : { x: 0, y: 0 };
        const position = {
          x: Math.round(abs.x - parentAbs.x),
          y: Math.round(abs.y - parentAbs.y),
        };
        record(container ? "nest" : "unnest", { node: dragged.id, into: container?.id, position });
        const reparented = setParent(current, dragged.id, container?.id);
        return {
          ...reparented,
          nodes: reparented.nodes.map((n) =>
            n.id === dragged.id ? { ...n, position } : n
          ),
        };
      });
    },
    [flow, overBin]
  );

  const addFromPalette = useCallback(
    (entry, position) => {
      setDocument((current) => {
        const spot =
          position ||
          (() => {
            // Stagger, so repeated clicks do not stack in one place.
            const loose = current.nodes.filter(
              (n) => !current.edges.some(
                (e) => e.role === "attached" && e.source === n.id
              )
            ).length;
            return { x: 40 + (loose % 5) * 210, y: 40 + Math.floor(loose / 5) * 80 };
          })();
        record("add-node", { kind: entry.kind, at: spot });
        return addNode(current, entry, spot);
      });
    },
    [document]
  );

  // A range starter dropped from the palette: same staggered placement as a bare
  // kind, but the node arrives with the preset's filled overlay. See presets.js.
  const addPreset = useCallback((preset, position) => {
    setDocument((current) => {
      const spot =
        position ||
        (() => {
          const loose = current.nodes.filter(
            (n) => !current.edges.some(
              (e) => e.role === "attached" && e.source === n.id
            )
          ).length;
          return { x: 40 + (loose % 5) * 210, y: 40 + Math.floor(loose / 5) * 80 };
        })();
      record("add-node", { kind: preset.kind, preset: preset.key, at: spot });
      return addHostPreset(current, preset, spot);
    });
  }, []);

  const onDrop = useCallback(
    (event) => {
      event.preventDefault();
      const presetKey = event.dataTransfer.getData("application/redstackpro-preset");
      const position = flow.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });
      if (presetKey) {
        const preset = presetsFor(document.mode).find((p) => p.key === presetKey);
        if (preset) addPreset(preset, position);
        return;
      }
      const kind = event.dataTransfer.getData("application/redstackpro");
      const entry = Object.values(palette)
        .flat()
        .find((e) => e.kind === kind);
      if (!entry) return;
      addFromPalette(entry, position);
    },
    [palette, flow, addFromPalette, addPreset, document.mode]
  );

  const rename = useCallback((oldId, newId) => {
    if (!newId) return;
    // The person owns this id now, so the default scheme stops re-deriving it.
    // Persist the pin on the node too, so the hand-picked name survives a reload
    // rather than being re-derived on the next retitle pass. See 0043.
    pinned.current.delete(oldId);
    pinned.current.add(newId);
    setDocument((current) => ({
      ...current,
      nodes: current.nodes.map((n) => (n.id === oldId ? { ...n, id: newId, pinned: true } : n)),
      edges: current.edges.map((e) => ({
        ...e,
        source: e.source === oldId ? newId : e.source,
        target: e.target === oldId ? newId : e.target,
      })),
    }));
    setSelection({ type: "node", id: newId });
  }, []);

  const download = useCallback(async () => {
    setBusy(true);
    setStatus("Compiling");
    try {
      const result = await api.compile(document, provider);
      const blob = await fetch(api.archiveUrl(result.compile_id)).then((r) =>
        r.blob()
      );
      const url = URL.createObjectURL(blob);
      const link = window.document.createElement("a");
      link.href = url;
      link.download = `${document.name || "redstackpro"}.zip`;
      link.click();
      URL.revokeObjectURL(url);
      setStatus(`Compiled ${result.files.length} files. Nothing was deployed.`);
    } catch (error) {
      const count = error.details?.findings?.filter(
        (f) => f.severity === "error"
      ).length;
      setStatus(count ? `${count} errors. The compiler refuses to run.` : error.message);
    } finally {
      setBusy(false);
    }
  }, [document, provider]);

  // Load a bundled document (the redStack example, or a GOAD range template).
  // A template ships with positions, so it is laid out only if it lacks them;
  // it opens as unsaved work rather than replacing a stored topology.
  const loadDocFromUrl = useCallback(
    async (url) => {
      if (!confirmDiscard()) return;
      const response = await fetch(url);
      if (!response.ok) {
        setStatus("Nothing bundled there. Paste a document instead.");
        return;
      }
      const doc = layoutIfNeeded(await response.json());
      record("load-template", { url, nodes: doc.nodes.length });
      setDocument(doc);
      // A GOAD range loads locked so the baseline stays intact while you explore
      // it; unlock (or add an extension) to customise. Ops templates open
      // editable. See 0047 and 0051.
      setTemplateView(doc.mode === "range");
      setSaved(emptyDocument(doc.mode));
      setDomainsText((doc.domains || []).join(", "));
      setTopology(null);
      setConflict(null);
      setStatus("");
      // What this range is for, shown once over the canvas. A template's shape
      // is visible in the topology; its point is not, and a person who has just
      // picked one from a list of nine is exactly the person who needs telling.
      // Undefined for a document that did not come from a template.
      summaryDocRef.current = doc;
      setSummary(templateFor(url));
      pushUrl(null);
      setTimeout(() => flow.fitView({ padding: 0.15, duration: 300 }), 60);
    },
    [confirmDiscard, flow, pushUrl]
  );


  // Toggle a GOAD extension on the current range. Adding or removing one edits
  // the document, so a read-only template forks into an editable range.
  const toggleExtension = useCallback((key, on) => {
    // Re-run the layout after the change so a newly added box lands in place
    // instead of overlapping whatever it was dropped on.
    setDocument((current) =>
      autoLayout(on ? applyExtension(current, key) : removeExtension(current, key)));
    setTemplateView(false);
    setStatus(on ? `Added the ${key} extension.` : `Removed the ${key} extension.`);
    setTimeout(() => flow.fitView({ padding: 0.15, duration: 300 }), 60);
  }, [flow]);

  // Tidy re-applies the deterministic tier hierarchy, the same clean top to
  // bottom arrangement a topology loads with. It used to run ELK, which did its own
  // 2D placement and orthogonal routing and left the lines in long staircases
  // that read worse than the hierarchy. The hierarchy is what people want back.
  //
  // The paragraph that used to sit above this one still described the ELK pass
  // in the present tense, years after it was taken out, and the button's own
  // tooltip promised an exposure axis that has never existed. Both are gone.
  const tidy = useCallback(() => {
    setDocument((current) => {
      const next = autoLayout(current);
      record("tidy", { nodes: next.nodes.length });
      return next;
    });
    setStatus("");
    setTimeout(() => flow.fitView({ padding: 0.15, duration: 300 }), 60);
  }, [flow]);

  const errors = findings.filter((f) => f.severity === "error");
  const warnings = findings.filter((f) => f.severity === "warning");

  return (
    <div className={`rg-app rg-mode-${document.mode || "ops"}`}>
      <header className="rg-header">
        <span className="rg-brand">
          red<b>Stack</b>PRO
        </span>
        <div className="rg-mode-switch" role="tablist" aria-label="Canvas">
          <button
            type="button"
            role="tab"
            aria-selected={document.mode !== "range"}
            className={`rg-mode-seg rg-mode-ops ${document.mode !== "range" ? "is-active" : ""}`}
            onClick={() => chooseMode("ops")}
          >
            Offense
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={document.mode === "range"}
            className={`rg-mode-seg rg-mode-range ${document.mode === "range" ? "is-active" : ""}`}
            onClick={() => chooseMode("range")}
          >
            Defense
          </button>
        </div>
        <TopologyPicker
          topologies={topologies}
          current={topology}
          dirty={dirty}
          onOpen={pickTopology}
          onNew={newTopology}
          onDuplicate={duplicate}
          onBrowse={() => setLibraryOpen(true)}
        />
        <input
          className="rg-name"
          aria-label="Topology name"
          value={document.name}
          onChange={(e) =>
            setDocument((current) => ({ ...current, name: e.target.value }))
          }
        />
        <label className="rg-prefix">
          prefix
          <input
            value={document.prefix}
            size={6}
            onChange={(e) =>
              setDocument((current) => ({ ...current, prefix: e.target.value }))
            }
          />
        </label>
        <ProviderPicker
          provider={resolveProvider(document.mode, providers, provider)}
          providers={providersFor(document.mode, providers)}
          selectable={selectableProviders(document.mode, providers)}
          onChange={setProvider}
          title={
            document.mode === "range"
              ? "Deploy target. Every target listed compiles the range natively."
              : "Deploy target"
          }
        />
        <span className="rg-spacer" />
        <span className={`rg-count ${errors.length ? "is-error" : "is-ok"}`}>
          {errors.length} errors
        </span>
        <span className="rg-count is-warning">{warnings.length} warnings</span>
        <span
          className={`rg-saved ${dirty ? "is-dirty" : ""}`}
          title={topology ? `${topology.name}, version ${topology.version}` : "Never saved"}
        >
          {dirty
            ? "Unsaved changes"
            : topology
            ? `Saved, version ${topology.version}`
            : "Not saved"}
        </span>
        <button onClick={save} disabled={saving || busy} title={blocked || "Ctrl+S"}>
          {saving ? "Saving" : saveMode(topology) === "fork" ? "Save a copy" : "Save"}
        </button>
        <button onClick={() => setTemplatePickerOpen(true)}>Load template</button>
        {document.mode === "range" ? (
          <button onClick={() => setExtensionsOpen(true)} title="Add GOAD extensions">
            Extensions
          </button>
        ) : null}
        <button onClick={tidy} title="Arrange by tier, peer networks side by side">
          Tidy
        </button>
        <button
          className="rg-primary"
          onClick={() => setPanel("export")}
          disabled={busy}
        >
          View working directory
        </button>
      </header>

      <div className="rg-body">
        {readOnly ? (
          <aside className="rg-panel rg-palette rg-readonly-note">
            <h2>Palette</h2>
            <section className="rg-palette-labs">
              <h3>Range templates</h3>
              <LabList
                mode="range"
                onLoad={(file) => loadDocFromUrl(`/${file}.json`)}
              />
            </section>
            <p className="rg-muted">
              Locked so the baseline stays intact while you explore it.
              Unlock to customise, or add an extension.
            </p>
            <button className="rg-primary rg-unlock" onClick={() => setTemplateView(false)}>
              Unlock to edit
            </button>
          </aside>
        ) : (
          <Palette
            groups={palette}
            onAdd={(entry) => addFromPalette(entry)}
            presets={presetsFor(document.mode)}
            onAddPreset={(preset) => addPreset(preset)}
            labsMode={document.mode}
            labsTitle={document.mode === "range" ? "Range templates" : "Starters"}
            onLoadLab={(file) => loadDocFromUrl(`/${file}.json`)}
          />
        )}

        <div
          className="rg-canvas"
          ref={wrapper}
          onDrop={readOnly ? undefined : onDrop}
          onDragOver={(event) => {
            event.preventDefault();
            event.dataTransfer.dropEffect = "move";
          }}
        >
          {problems.length ? (
            <div className="rg-diag-banner">
              <span className="rg-diag-text">
                Canvas problem: {problems[0]}
                {problems.length > 1 ? ` (and ${problems.length - 1} more)` : ""}
              </span>
              <button
                type="button"
                onClick={() => flow.fitView({ padding: 0.2, duration: 300 })}
              >
                Fit view
              </button>
              <button
                type="button"
                onClick={() => {
                  record("copy-diagnostics", { via: "banner" });
                  copyDiagnostics();
                }}
              >
                Copy diagnostics
              </button>
            </div>
          ) : null}
          <CanvasErrorBoundary getDocument={() => docRef.current}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            connectionMode={ConnectionMode.Loose}
            deleteKeyCode={readOnly ? null : "Backspace"}
            nodesDraggable={!readOnly}
            nodesConnectable={!readOnly}
            edgesUpdatable={!readOnly}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onReconnect={onReconnect}
            onNodeDragStart={onNodeDragStart}
            onNodeDrag={onNodeDrag}
            onNodeDragStop={onNodeDragStop}
            onNodeClick={(_e, node) => {
              setSelection({ type: "node", id: node.id });
              setPanel("inspector");
            }}
            onEdgeClick={(_e, edge) => {
              setSelection({ type: "edge", id: edge.id });
              setPanel("inspector");
            }}
            onEdgeDoubleClick={(_e, edge) => clearWaypoints(edge.id)}
            onPaneClick={() => setSelection(null)}
            fitView
            fitViewOptions={{ padding: 0.15 }}
            minZoom={0.2}
            maxZoom={1.75}
            proOptions={{ hideAttribution: true }}
          >
            <Background color={document.mode === "range" ? "#37424e" : "#4a373b"} gap={18} />
            <Panel position="top-left" className="rg-legend">
              {legendItems(document).map((item) => (
                <span key={item.key} className="rg-legend-item">
                  <span className="rg-legend-swatch" style={{ background: item.color }} />
                  {item.label}
                </span>
              ))}
            </Panel>
            {summary ? (
              <Panel position="top-right" className="rg-summary">
                <div className="rg-summary-head">
                  <h3>{summary.name}</h3>
                  <button
                    type="button"
                    className="rg-summary-close"
                    aria-label="Dismiss"
                    onClick={() => setSummary(null)}
                  >
                    x
                  </button>
                </div>
                <p className="rg-summary-shape">{summary.blurb}</p>
                {summary.teaches ? (
                  <p className="rg-summary-teaches">{summary.teaches}</p>
                ) : null}
              </Panel>
            ) : null}
            <Controls />
            <MiniMap
              pannable
              nodeColor={(n) => n.data?.display?.color || "#868e96"}
              maskColor="rgba(20,21,24,0.7)"
            />
            {guides ? (
              <HelperLines vertical={guides.vertical} horizontal={guides.horizontal} />
            ) : null}
            {dragging && !readOnly ? (
              <Panel position="bottom-center">
                <div ref={binRef} className={`rg-bin ${binHot ? "is-hot" : ""}`}>
                  <Icon icon="tabler/outline/trash" size={20} />
                  <span>{binHot ? "Release to delete" : "Drop here to delete"}</span>
                </div>
              </Panel>
            ) : null}
          </ReactFlow>
          </CanvasErrorBoundary>
          {!readOnly && document.nodes.length === 0 ? (
            <div className="rg-empty-hint">
              <p className="rg-empty-title">Start your {document.mode === "range" ? "range" : "topology"}</p>
              <p>
                Drag a <b>Network</b> from the palette onto the canvas, then drop
                subnets and hosts inside it.
              </p>
              <p className="rg-muted">
                Or pick a {document.mode === "range" ? "GOAD lab" : "starter"} from the top of the palette.
              </p>
            </div>
          ) : null}
        </div>

        <div className={`rg-right ${panel === "export" ? "is-wide" : ""}`}>
          <div className="rg-tabs">
            <button
              className={panel === "inspector" ? "is-active" : ""}
              onClick={() => setPanel("inspector")}
            >
              Inspector
            </button>
            <button
              className={panel === "export" ? "is-active" : ""}
              onClick={() => setPanel("export")}
            >
              Export
            </button>
          </div>

          {panel === "export" ? (
            <ExportPanel document={settled} provider={provider} />
          ) : (
        <Inspector
          schema={schema}
          selection={selection}
          document={document}
          readOnly={readOnly}
          kindLabels={kindLabels}
          provider={document.mode === "range" ? provider : undefined}
          findings={selection ? findingsFor(selection.id) : []}
          onOverlayChange={(id, overlay) =>
            setDocument((current) => updateOverlay(current, id, overlay))
          }
          onEdgeChange={(id, patch) =>
            setDocument((current) => updateEdge(current, id, patch))
          }
          onSelectEdge={selectEdge}
          onSelectNode={(id) => {
            setSelection({ type: "node", id });
            setPanel("inspector");
          }}
          canStraighten={
            selection?.type === "edge" &&
            (document.edges.find((e) => e.id === selection.id)?.waypoints?.length || 0) > 0
          }
          onStraighten={() => selection && clearWaypoints(selection.id)}
          onApplyCover={applyCover}
          onRandomizeUri={randomizeUri}
          onJoinDomain={onJoinDomain}
          onPlaceSubnet={onPlaceSubnet}
          rangeHostCount={
            document.nodes.filter((n) =>
              ["dc", "srv", "wks", "fw"].includes(n.kind)
            ).length
          }
          domains={domainsText}
          onDomainsChange={changeDomains}
          onAddEdge={onAddEdge}
          onRename={rename}
          onDelete={(target) => {
            setDocument((current) =>
              target.type === "edge"
                ? removeEdge(current, target.id)
                : removeNode(current, target.id)
            );
            setSelection(null);
          }}
        />
          )}
        </div>
      </div>

      <footer className="rg-footer">
        <div className="rg-findings">
          {findings.length === 0 ? (
            <span className="rg-hint">
              No findings. redStackPRO generates code and never deploys it.
            </span>
          ) : (
            findings.map((finding, index) => (
              <button
                key={index}
                className={`rg-finding is-${finding.severity}`}
                onClick={() =>
                  setSelection({
                    type: document.edges.some((e) => e.id === finding.target_ids[0])
                      ? "edge"
                      : "node",
                    id: finding.target_ids[0],
                  })
                }
              >
                <FindingBadge code={finding.code} /> {finding.message}
                {finding.remedy ? (
                  <span className="rg-remedy">{finding.remedy}</span>
                ) : null}
              </button>
            ))
          )}
        </div>
        {status ? <span className="rg-status">{status}</span> : null}
      </footer>

      {libraryOpen ? (
        <Library
          currentId={topology?.id || null}
          onOpen={openFromLibrary}
          onClone={cloneBlueprint}
          onDelete={removeTopology}
          onPublish={publishTopology}
          onUnpublish={unpublishTopology}
          onClose={() => setLibraryOpen(false)}
        />
      ) : null}

      {conflict ? (
        <ConflictDialog
          details={conflict}
          busy={saving}
          onDismiss={() => setConflict(null)}
          onReload={reloadOverMine}
          onFork={() => fork("conflict copy")}
        />
      ) : null}
      {templatePickerOpen ? (
        <TemplatePicker
          mode={document.mode}
          onPick={(file) => {
            setTemplatePickerOpen(false);
            loadDocFromUrl(`/${file}.json`);
          }}
          onDismiss={() => setTemplatePickerOpen(false)}
        />
      ) : null}
      {extensionsOpen ? (
        <Extensions
          document={document}
          readOnly={readOnly}
          onToggle={toggleExtension}
          onDismiss={() => setExtensionsOpen(false)}
        />
      ) : null}
    </div>
  );
}

export default function App() {
  return (
    <ReactFlowProvider>
      <Editor />
    </ReactFlowProvider>
  );
}
