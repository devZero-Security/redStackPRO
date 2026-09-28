import React, { useCallback, useEffect, useState } from "react";

import { api } from "./api.js";

// The library. Two things the header select cannot do: browse and clone the
// starter blueprints, and manage the topologies you own (delete one, offer one as a
// blueprint). The select stays for quick switching; this is the fuller view.
//
// Publishing moves a topology out of your list and into the blueprint library, and
// unpublishing moves it back, so every action here reloads both lists rather
// than patching one. See 0025.
//
// Paging is opt in and there is no total count, so the only honest thing to show
// is more when a full page came back and nothing when it did not. See 0026.

const PAGE = 25;

export function Library({
  currentId,
  onOpen,
  onClone,
  onDelete,
  onPublish,
  onUnpublish,
  onClose,
}) {
  const [topologies, setTopologies] = useState([]);
  const [blueprints, setBlueprints] = useState([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [firstPage, prints] = await Promise.all([
        api.listTopologies(PAGE, 0),
        api.listBlueprints(),
      ]);
      setTopologies(firstPage);
      setBlueprints(prints);
      setOffset(firstPage.length);
      setHasMore(firstPage.length === PAGE);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const loadMore = useCallback(async () => {
    setError("");
    try {
      const next = await api.listTopologies(PAGE, offset);
      setTopologies((rows) => [...rows, ...next]);
      setOffset((current) => current + next.length);
      setHasMore(next.length === PAGE);
    } catch (e) {
      setError(e.message);
    }
  }, [offset]);

  // A mutating action runs in the parent, which owns the confirm and the open
  // topology, then this reloads because the action may have moved a topology between
  // the two lists.
  const run = useCallback(
    async (id, action) => {
      setBusyId(id);
      setError("");
      try {
        await action(id);
        await load();
      } catch (e) {
        setError(e.message);
      } finally {
        setBusyId(null);
      }
    },
    [load]
  );

  // Open and clone navigate away, so they close the modal, but only once the
  // parent confirms it happened. Declining the discard prompt returns false and
  // leaves the library up.
  const navigate = useCallback(
    async (id, action) => {
      setBusyId(id);
      setError("");
      try {
        if (await action(id)) onClose();
      } catch (e) {
        setError(e.message);
      } finally {
        setBusyId(null);
      }
    },
    [onClose]
  );

  return (
    <div
      className="rg-modal-backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget && !busyId) onClose();
      }}
    >
      <div className="rg-modal is-library" role="dialog" aria-label="Library">
        <div className="rg-library-head">
          <h2>Library</h2>
          <button onClick={onClose} title="Close">
            Close
          </button>
        </div>

        {error ? <p className="rg-library-error">{error}</p> : null}

        <section className="rg-library-section">
          <h3>Your topologies</h3>
          <p className="rg-muted rg-library-sub">
            Your private saved topologies. Publish one to offer it as a blueprint
            others can clone; delete removes it and all its revisions.
          </p>
          {loading ? (
            <p className="rg-muted rg-loading">Loading.</p>
          ) : topologies.length === 0 ? (
            <p className="rg-muted">Nothing saved yet. Use Load blueprint in the toolbar to start from a shipped topology, or build one and Save it.</p>
          ) : (
            <ul className="rg-library-list">
              {topologies.map((topology) => (
                <li
                  key={topology.id}
                  className={`rg-library-row ${
                    topology.id === currentId ? "is-current" : ""
                  }`}
                >
                  <button
                    className="rg-library-name"
                    onClick={() => navigate(topology.id, onOpen)}
                    disabled={!!busyId}
                    title="Open this topology"
                  >
                    <span>{topology.name}</span>
                    <span className="rg-library-meta">
                      version {topology.version}
                      {topology.id === currentId ? " · open" : ""}
                      {topology.editable ? "" : " · read only"}
                    </span>
                  </button>
                  <div className="rg-library-actions">
                    {topology.editable ? (
                      <button
                        onClick={() => run(topology.id, onPublish)}
                        disabled={!!busyId}
                        title="Offer this topology as a blueprint others can clone"
                      >
                        Publish
                      </button>
                    ) : null}
                    {topology.editable ? (
                      <button
                        className="rg-danger-text"
                        onClick={() => run(topology.id, onDelete)}
                        disabled={!!busyId}
                        title="Delete this topology and all its revisions"
                      >
                        Delete
                      </button>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          )}
          {hasMore ? (
            <button
              className="rg-library-more"
              onClick={loadMore}
              disabled={!!busyId}
            >
              Load more
            </button>
          ) : null}
        </section>

        <section className="rg-library-section">
          <h3>Blueprints</h3>
          <p className="rg-muted rg-library-sub">
            Published starters to clone. A clone is a private copy you own; the
            blueprint itself stays read only.
          </p>
          {loading ? (
            <p className="rg-muted rg-loading">Loading.</p>
          ) : blueprints.length === 0 ? (
            <p className="rg-muted">No blueprints yet. Shipped starting points are under Load blueprint in the toolbar. Publish one of your own topologies to add it here.</p>
          ) : (
            <ul className="rg-library-list">
              {blueprints.map((blueprint) => (
                <li key={blueprint.id} className="rg-library-row">
                  <div className="rg-library-name is-static">
                    <span>{blueprint.name}</span>
                    <span className="rg-library-meta">
                      {blueprint.owner_id ? "yours" : "system starter"}
                    </span>
                  </div>
                  <div className="rg-library-actions">
                    <button
                      className="rg-primary"
                      onClick={() => navigate(blueprint.id, onClone)}
                      disabled={!!busyId}
                      title="Start a new private topology from this blueprint"
                    >
                      Use this
                    </button>
                    {blueprint.editable ? (
                      <button
                        onClick={() => run(blueprint.id, onUnpublish)}
                        disabled={!!busyId}
                        title="Stop offering this topology as a blueprint"
                      >
                        Unpublish
                      </button>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
