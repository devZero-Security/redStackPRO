// Save and load, rendered.
//
// The pure suites cover the URL, the dirty comparison, and the layout guard as
// data. None of them can see the thing that actually goes wrong: a topology is
// lost on refresh because a component did not mount, an effect had the wrong
// dependency, or a handler was never wired to a button. That is a rendering
// failure and it needs a DOM.
//
// These are the two scenarios that used to need a browser and two tabs.

import React from "react";
import { describe, expect, test, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import App from "./App.jsx";

const PALETTE = {
  topology: [
    { kind: "network", abbrev: "network", category: "container", label: "Network", color: "#868e96" },
    { kind: "segment", abbrev: "subnet", category: "container", label: "Segment", color: "#868e96" },
  ],
  operational: [
    { kind: "teamserver", abbrev: "ts", category: "host", label: "Teamserver", color: "#e03131" },
  ],
};

// A saved topology, positions and all. The point of most of these tests is that
// what comes back is what went in.
const SAVED_DOCUMENT = {
  schema_version: "0.2.0",
  mode: "artie",
  name: "Saved range",
  prefix: "art",
  nodes: [
    { id: "c2-net01", kind: "network", overlay: { cidr: "10.30.0.0/16" },
      position: { x: 0, y: 0 }, width: 700, height: 300 },
    { id: "c2-sub01", kind: "segment",
      overlay: { cidr: "10.30.2.0/24", egress: "allowed", exposure: "local" },
      position: { x: 16, y: 34 }, width: 240, height: 120 },
    { id: "myth-ts01", kind: "teamserver", overlay: { c2: "mythic" },
      position: { x: 111, y: 222 } },
  ],
  edges: [
    { id: "e-c2-sub01-c2-net01-attached", role: "attached",
      source: "c2-sub01", target: "c2-net01" },
    { id: "e-myth-ts01-c2-sub01-attached", role: "attached",
      source: "myth-ts01", target: "c2-sub01" },
  ],
};

const SUMMARY = {
  id: "g1", name: "Saved range", mode: "artie", visibility: "private",
  schema_version: "0.2.0", version: 3, owner_id: "u1",
  is_blueprint: false, editable: true,
};

function respond(status, body) {
  return {
    ok: status < 400,
    status,
    headers: { get: () => "application/json" },
    json: async () => body,
  };
}

/** A backend that records what the canvas asked it for. */
function fakeBackend({ putResult, documents } = {}) {
  const calls = [];
  const docs = documents || { g1: SAVED_DOCUMENT };

  global.fetch = vi.fn(async (url, options = {}) => {
    const method = options.method || "GET";
    const body = options.body ? JSON.parse(options.body) : null;
    calls.push({ url, method, body, headers: options.headers || {} });

    if (url.includes("/registry/palette")) return respond(200, { groups: PALETTE });
    if (url.includes("/registry/schema")) return respond(200, { $defs: {} });
    if (url.includes("/registry/providers")) {
      return respond(200, { providers: [{ name: "gcp" }, { name: "aws" }] });
    }
    if (url.endsWith("/validate")) {
      return respond(200, { valid: true, errors: 0, warnings: 0, findings: [] });
    }
    if (url.includes("/topologies?") && method === "GET") {
      return respond(200, [SUMMARY,
        { ...SUMMARY, id: "g2", name: "Someone else's", editable: false }]);
    }
    if (url.endsWith("/topologies") && method === "POST") {
      return respond(201, { ...SUMMARY, id: "g9", name: body.name, version: 1 });
    }
    const match = url.match(/\/topologies\/([^/?]+)$/);
    if (match && method === "GET") {
      return respond(200, {
        topology: { ...SUMMARY, id: match[1] },
        document: docs[match[1]],
      });
    }
    if (match && method === "PUT") {
      if (putResult === "conflict") {
        return respond(409, {
          code: "conflict",
          message: "This topology moved since you read it.",
          details: { topology_id: match[1], your_version: 3, current_version: 5 },
        });
      }
      return respond(200, { ...SUMMARY, id: match[1], version: 4 });
    }
    return respond(404, { code: "not_found", message: "no route: " + url });
  });

  return calls;
}

const openUrl = (search) =>
  window.history.replaceState({}, "", "/" + (search || ""));

const putBodies = (calls) => calls.filter((c) => c.method === "PUT").map((c) => c.body);
const postedTopologies = (calls) =>
  calls.filter((c) => c.method === "POST" && c.url.endsWith("/topologies"));

beforeEach(() => {
  openUrl("");
  window.confirm = () => true;
});


describe("loading", () => {
  test("a topology named in the URL is open after a reload", async () => {
    openUrl("?topology=g1");
    fakeBackend();
    render(<App />);

    // This is the reload. Nothing was carried over in memory; the id in the
    // URL is the only thing that survived.
    expect(await screen.findByText("art-myth-ts01")).toBeTruthy();
    expect(screen.getByLabelText("Topology name").value).toBe("Saved range");
  });

  test("a topology that opens clean has nothing to save", async () => {
    openUrl("?topology=g1");
    fakeBackend();
    render(<App />);
    await screen.findByText("art-myth-ts01");

    expect(screen.getByText(/Saved, version 3/)).toBeTruthy();
  });

  test("the picker lists the topologies and marks the ones owned elsewhere", async () => {
    fakeBackend();
    render(<App />);

    const picker = await screen.findByLabelText("Open topology");
    await waitFor(() =>
      expect(within(picker).getByText(/Someone else's \(read only\)/)).toBeTruthy());
  });
});


describe("saving", () => {
  test("an edit shows as unsaved and saving sends the version that was read",
    async () => {
      openUrl("?topology=g1");
      const calls = fakeBackend();
      const user = userEvent.setup();
      render(<App />);
      await screen.findByText("art-myth-ts01");

      await user.type(screen.getByLabelText("Topology name"), "!");
      expect(await screen.findByText("Unsaved changes")).toBeTruthy();

      await user.click(screen.getByRole("button", { name: "Save" }));

      await waitFor(() => expect(putBodies(calls).length).toBe(1));
      const sent = putBodies(calls)[0];
      // Compare and swap is explicit in the body. See 0017.
      expect(sent.version).toBe(3);
      expect(sent.name).toBe("Saved range!");
      await waitFor(() =>
        expect(screen.getByText(/Saved, version 4/)).toBeTruthy());
    });

  test("the layout that was loaded is the layout that gets saved", async () => {
    // The requirement is that a reload restores the arrangement. A saved topology
    // carries its positions, so the only way to lose them is to lay it out
    // again on the way in or drop them on the way out.
    openUrl("?topology=g1");
    const calls = fakeBackend();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("art-myth-ts01");

    await user.type(screen.getByLabelText("Topology name"), "!");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(putBodies(calls).length).toBe(1));
    const sent = putBodies(calls)[0].document;
    const byId = Object.fromEntries(sent.nodes.map((n) => [n.id, n]));
    expect(byId["myth-ts01"].position).toEqual({ x: 111, y: 222 });
    expect(byId["c2-sub01"].position).toEqual({ x: 16, y: 34 });
    expect(byId["c2-sub01"].width).toBe(240);
    expect(byId["c2-net01"].height).toBe(300);
  });

  test("a topology with no id is created, once, with an idempotency key",
    async () => {
      const calls = fakeBackend();
      const user = userEvent.setup();
      render(<App />);
      await screen.findByRole("button", { name: "Save" });

      await user.type(screen.getByLabelText("Topology name"), " one");
      await user.click(screen.getByRole("button", { name: "Save" }));

      await waitFor(() => expect(postedTopologies(calls).length).toBe(1));
      const created = postedTopologies(calls)[0];
      expect(created.headers["Idempotency-Key"]).toBeTruthy();
      // The id it came back with is now in the URL, so this reload restores it.
      await waitFor(() =>
        expect(window.location.search).toBe("?topology=g9"));
    });
});


describe("fresh canvas", () => {
  test("a fresh canvas opens ready to edit, with no start choice", async () => {
    fakeBackend();
    render(<App />);

    // There is one edition, so a fresh canvas is immediately editable rather
    // than gated behind an entry choice.
    await screen.findByRole("button", { name: "Save" });
    expect(screen.getByRole("button", { name: "Load template" })).toBeTruthy();
    expect(screen.queryByText("Start a topology")).toBeNull();
  });
});


describe("undo and redo", () => {
  test("undo and redo are disabled until there is something to undo", async () => {
    fakeBackend();
    render(<App />);
    await screen.findByRole("button", { name: "Save" });

    expect(screen.getByRole("button", { name: "Undo" }).disabled).toBe(true);
    expect(screen.getByRole("button", { name: "Redo" }).disabled).toBe(true);
  });

  test("deleting a node is undoable and redoable", async () => {
    openUrl("?topology=g1");
    fakeBackend();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("art-myth-ts01");

    // A plain click, not userEvent's full pointer sequence: a real mousedown
    // hands the node to React Flow's own drag setup, which this jsdom has no
    // layout engine for. All that is wanted here is the click that selects it.
    fireEvent.click(screen.getByText("art-myth-ts01"));
    await user.click(await screen.findByRole("button", { name: "Delete node" }));
    expect(screen.queryByText("art-myth-ts01")).toBeNull();
    expect(screen.getByRole("button", { name: "Undo" }).disabled).toBe(false);

    await user.click(screen.getByRole("button", { name: "Undo" }));
    expect(await screen.findByText("art-myth-ts01")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Redo" }).disabled).toBe(false);

    await user.click(screen.getByRole("button", { name: "Redo" }));
    await waitFor(() => expect(screen.queryByText("art-myth-ts01")).toBeNull());
  });

  test("typing a name coalesces into one undo step, via the toolbar button",
    async () => {
      openUrl("?topology=g1");
      fakeBackend();
      const user = userEvent.setup();
      render(<App />);
      await screen.findByText("art-myth-ts01");

      const nameInput = screen.getByLabelText("Topology name");
      await user.type(nameInput, "!!!");
      expect(nameInput.value).toBe("Saved range!!!");

      await user.click(screen.getByRole("button", { name: "Undo" }));
      // The whole typing burst coalesces into one step: one undo clears it all.
      await waitFor(() => expect(nameInput.value).toBe("Saved range"));
      expect(screen.getByRole("button", { name: "Undo" }).disabled).toBe(true);
    });

  test("Ctrl+Z is left to the browser while a field is focused, and works once it is not",
    async () => {
      openUrl("?topology=g1");
      fakeBackend();
      const user = userEvent.setup();
      render(<App />);
      await screen.findByText("art-myth-ts01");

      const nameInput = screen.getByLabelText("Topology name");
      await user.type(nameInput, "!");
      expect(nameInput.value).toBe("Saved range!");

      // Still focused in the field: the canvas leaves this to native text undo.
      await user.keyboard("{Control>}z{/Control}");
      expect(nameInput.value).toBe("Saved range!");

      // Focus moves off the field: the same shortcut now reaches the canvas.
      nameInput.blur();
      await user.keyboard("{Control>}z{/Control}");
      await waitFor(() => expect(nameInput.value).toBe("Saved range"));
    });

  test("opening a different topology resets the undo stack", async () => {
    openUrl("?topology=g1");
    fakeBackend();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("art-myth-ts01");

    await user.type(screen.getByLabelText("Topology name"), "!");
    expect(screen.getByRole("button", { name: "Undo" }).disabled).toBe(false);

    await user.click(screen.getByRole("button", { name: "New" }));
    await screen.findByText(/Not saved/);
    expect(screen.getByRole("button", { name: "Undo" }).disabled).toBe(true);
  });
});


describe("two tabs", () => {
  test("a conflict names both versions instead of throwing", async () => {
    openUrl("?topology=g1");
    fakeBackend({ putResult: "conflict" });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("art-myth-ts01");

    await user.type(screen.getByLabelText("Topology name"), "!");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("This topology moved")).toBeTruthy();
    const prose = screen.getByText(/You opened version/);
    expect(prose.textContent).toMatch(/version 3/);
    expect(prose.textContent).toMatch(/version 5/);
    expect(prose.textContent).toMatch(/Nothing has been discarded/);
  });

  test("keeping your version creates a new topology rather than duplicating theirs",
    async () => {
      // The duplicate endpoint copies what is stored, which on a conflict is
      // the revision that just won. Keeping the local document means a create.
      // See 0018.
      openUrl("?topology=g1");
      const calls = fakeBackend({ putResult: "conflict" });
      const user = userEvent.setup();
      render(<App />);
      await screen.findByText("art-myth-ts01");

      await user.type(screen.getByLabelText("Topology name"), "!");
      await user.click(screen.getByRole("button", { name: "Save" }));
      await screen.findByText("This topology moved");

      await user.click(
        screen.getByRole("button", { name: "Save mine as a new topology" }));

      await waitFor(() => expect(postedTopologies(calls).length).toBe(1));
      const created = postedTopologies(calls)[0];
      expect(created.body.name).toBe("Saved range! (conflict copy)");
      expect(created.body.document.nodes.find((n) => n.id === "myth-ts01").position)
        .toEqual({ x: 111, y: 222 });
      expect(calls.some((c) => c.url.includes("/duplicate"))).toBe(false);
    });

  test("reloading their version discards yours and says so", async () => {
    openUrl("?topology=g1");
    fakeBackend({ putResult: "conflict" });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("art-myth-ts01");

    await user.type(screen.getByLabelText("Topology name"), "!");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText("This topology moved");

    await user.click(
      screen.getByRole("button", { name: "Discard mine and reload" }));

    // Their version came back, so the local edit to the name is gone.
    await waitFor(() =>
      expect(screen.getByLabelText("Topology name").value).toBe("Saved range"));
    expect(screen.queryByText("This topology moved")).toBeNull();
  });
});
