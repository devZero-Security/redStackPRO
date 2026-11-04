// The app shell over the merged widgets and validator: how a new trust is
// typed, what the legend calls each line, how the footer reads findings of
// each severity, and what a topology remembers about where it came from and
// where it deploys.

import React from "react";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, test, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import App from "./App.jsx";
import { connectEdge, emptyDocument, legendItems } from "./topology.js";
import { edgeId } from "./idscheme.js";
import { countBySeverity, findingSelection, sortFindings } from "./findingSeverity.js";
import { TEMPLATES } from "./templates.js";
import { targetFor } from "./deployTarget.js";
import { supportsExtension } from "./extensions.js";

const HERE = dirname(fileURLToPath(import.meta.url));

const PALETTE = {
  topology: [
    { kind: "network", abbrev: "network", category: "container", label: "Network", color: "#868e96" },
    { kind: "segment", abbrev: "subnet", category: "container", label: "Segment", color: "#868e96" },
  ],
  domains: [
    { kind: "domain", abbrev: "dom", category: "container", label: "Domain", color: "#868e96" },
  ],
};

function respond(status, body) {
  return {
    ok: status < 400,
    status,
    headers: { get: () => "application/json" },
    json: async () => body,
  };
}

const GCP_ONLY = [{ name: "gcp", capabilities: ["windows_image"], maturity: "proven" }];

// Serves the registry, saved documents and the shipped blueprint files from
// public/, and records every call so a test can read what was saved.
function fakeBackend({ documents = {}, findings = [], providers = GCP_ONLY, editable = true } = {}) {
  const calls = [];
  global.fetch = vi.fn(async (url, options = {}) => {
    const method = options.method || "GET";
    calls.push({ url, method, body: options.body ? JSON.parse(options.body) : null });
    if (url.includes("/registry/palette")) return respond(200, { groups: PALETTE });
    if (url.includes("/registry/schema")) return respond(200, { $defs: {} });
    if (url.includes("/registry/providers")) return respond(200, { providers });
    if (url.includes("/health")) return respond(200, { status: "ok", app_version: "9.9.9" });
    if (url.endsWith("/validate")) return respond(200, { findings });
    if (url.endsWith("/compile")) {
      return respond(200, { compile_id: "c1", files: [{ path: "deploy.tfvars", contents: "" }] });
    }
    if (url.includes("/topologies?") && method === "GET") return respond(200, []);
    const summary = (id, mode) => ({
      id, name: "Range", mode, visibility: "private", schema_version: "0.7.0",
      version: 1, owner_id: "u1", is_blueprint: false, editable,
    });
    if (url.endsWith("/topologies") && method === "POST") {
      return respond(201, { ...summary("g9", "defense"), editable: true });
    }
    const match = url.match(/\/topologies\/([^/?]+)$/);
    if (match && method === "GET" && documents[match[1]]) {
      return respond(200, {
        topology: summary(match[1], documents[match[1]].mode),
        document: documents[match[1]],
      });
    }
    if (match && method === "PUT") return respond(200, { ...summary(match[1], "defense"), version: 2 });
    if (url.endsWith(".json") && !url.includes("/api/")) {
      const file = join(HERE, "../public", url.replace(/^\//, ""));
      return respond(200, JSON.parse(readFileSync(file, "utf8")));
    }
    return respond(404, { code: "not_found", message: "no route: " + url });
  });
  return calls;
}

const openUrl = (search) => window.history.replaceState({}, "", "/" + (search || ""));
beforeEach(() => openUrl(""));

// Two domains in one forest and one in another. Not joined to anything, so
// they draw as loose boxes.
const DOMAINS = {
  schema_version: "0.7.0", mode: "defense", name: "Range", prefix: "def",
  nodes: [
    { id: "sevenkingdoms", kind: "domain", position: { x: 0, y: 0 }, width: 300, height: 160,
      overlay: { fqdn: "sevenkingdoms.local", netbios: "SEVENKINGDOMS" } },
    { id: "north", kind: "domain", position: { x: 400, y: 0 }, width: 300, height: 160,
      overlay: { fqdn: "north.sevenkingdoms.local", netbios: "NORTH" } },
    { id: "essos", kind: "domain", position: { x: 800, y: 0 }, width: 300, height: 160,
      overlay: { fqdn: "essos.local", netbios: "ESSOS" } },
    { id: "corp", kind: "domain", position: { x: 1200, y: 0 }, width: 300, height: 160,
      overlay: {} },
  ],
  edges: [],
};


describe("a new trust", () => {
  test("drawn child to parent, it becomes a parent_child trust from the parent", () => {
    const doc = connectEdge(DOMAINS, "north", "sevenkingdoms", "trusts");
    expect(doc.edges).toEqual([{
      id: edgeId("sevenkingdoms", "north", "trusts"),
      role: "trusts", source: "sevenkingdoms", target: "north", trust_type: "parent_child",
    }]);
  });

  test("between two forests, it becomes a forest trust as drawn", () => {
    const doc = connectEdge(DOMAINS, "essos", "sevenkingdoms", "trusts");
    expect(doc.edges[0]).toMatchObject({
      source: "essos", target: "sevenkingdoms", trust_type: "forest",
    });
  });

  test("with a domain still unnamed, it stays untyped until both FQDNs are set", () => {
    const doc = connectEdge(DOMAINS, "corp", "essos", "trusts");
    expect(doc.edges[0].trust_type).toBeUndefined();
    expect(doc.edges[0]).toMatchObject({ source: "corp", target: "essos" });
  });

  test("a C2 route still gets its HTTPS defaults", () => {
    const doc = connectEdge(emptyDocument("offense"), "nginx-rd01", "myth-ts01", "fronts");
    expect(doc.edges[0]).toMatchObject({
      role: "fronts", protocol: "https", listen_port: 443, upstream_port: 443,
    });
  });

  test("added from Connections, it is typed, oriented and one undo step", async () => {
    openUrl("?topology=g1");
    fakeBackend({ documents: { g1: DOMAINS } });
    const user = userEvent.setup();
    render(<App />);
    fireEvent.click(await screen.findByText("north"));

    await user.selectOptions(
      await screen.findByRole("combobox", { name: "connect to" }), "sevenkingdoms");
    await user.click(screen.getByRole("button", { name: "Add" }));

    // The parent is the source, so from north the line reads as incoming.
    expect(await screen.findByText("Trusted by")).toBeTruthy();
    // Typed parent_child, so the legend calls it a same-forest trust.
    const legend = window.document.querySelector(".rg-legend");
    expect(within(legend).getByText("Trusts, same forest")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(within(legend).queryByText(/Trusts/)).toBeNull());
    expect(screen.getByRole("button", { name: "Undo" }).disabled).toBe(true);
  });
});


describe("legend", () => {
  test("reads each line the way the Inspector does", () => {
    const doc = {
      edges: [
        { role: "fronts" }, { role: "logs_to" }, { role: "peers" },
        { role: "trusts", trust_type: "parent_child" }, { role: "trusts", trust_type: "forest" },
      ],
    };
    const labels = legendItems(doc).map((i) => i.label);
    expect(labels).toEqual([
      "C2 route", "Ships logs to", "Peered with",
      "Trusts, same forest", "Trusts, across forests",
    ]);
    expect(labels.join(" ")).not.toMatch(/URIs|logs_to|peers/);
  });
});


describe("findings by severity", () => {
  const FINDINGS = [
    { code: "SVC002", severity: "info", target_ids: ["corp"], message: "A notice.", remedy: "" },
    { code: "RNG013", severity: "warning", target_ids: ["essos"], message: "A warning.", remedy: "" },
    { code: "SCH001", severity: "error", target_ids: ["topology"], field: "prefix",
      message: "prefix on topology: bad.", remedy: "" },
  ];

  test("sorted worst first, counted apart, and a notice never counts as a warning", () => {
    expect(sortFindings(FINDINGS).map((f) => f.severity)).toEqual(["error", "warning", "info"]);
    expect(countBySeverity(FINDINGS)).toEqual({ error: 1, warning: 1, info: 1 });
    expect(countBySeverity([FINDINGS[0]])).toEqual({ error: 0, warning: 0, info: 1 });
  });

  test("a document-level finding selects nothing, so Topology settings show", () => {
    expect(findingSelection(DOMAINS, FINDINGS[2])).toBeNull();
    expect(findingSelection(DOMAINS, FINDINGS[1])).toEqual({ type: "node", id: "essos" });
    expect(findingSelection(DOMAINS, { target_ids: ["gone"] })).toBeNull();
  });

  test("the header counts info apart and the footer lists it last, not as a failure",
    async () => {
      openUrl("?topology=g1");
      fakeBackend({ documents: { g1: DOMAINS }, findings: FINDINGS });
      render(<App />);

      expect(await screen.findByText("1 info")).toBeTruthy();
      expect(screen.getByText("1 warnings")).toBeTruthy();
      expect(screen.getByText("1 errors")).toBeTruthy();

      const footer = window.document.querySelector(".rg-findings");
      const buttons = [...footer.querySelectorAll("button.rg-finding")];
      expect(buttons.map((b) => b.className)).toEqual([
        "rg-finding is-error", "rg-finding is-warning", "rg-finding is-info",
      ]);
      const label = within(footer).getByText("Info, not blocking:");
      expect(label.nextElementSibling).toBe(buttons[2]);
    });

  test("only notices: nothing reads as an error", async () => {
    openUrl("?topology=g1");
    fakeBackend({ documents: { g1: DOMAINS }, findings: [FINDINGS[0]] });
    render(<App />);
    expect(await screen.findByText("1 info")).toBeTruthy();
    expect(screen.getByText("0 errors").className).toMatch(/is-ok/);
    expect(screen.getByText("0 warnings")).toBeTruthy();
  });

  test("clicking a topology finding clears the selection to Topology settings", async () => {
    openUrl("?topology=g1");
    fakeBackend({ documents: { g1: DOMAINS }, findings: FINDINGS });
    const user = userEvent.setup();
    render(<App />);
    fireEvent.click(await screen.findByText("north"));
    await screen.findByRole("combobox", { name: "connect to" });
    expect(screen.queryByText("Topology settings")).toBeNull();

    await user.click(await screen.findByText("prefix on topology: bad."));
    expect(await screen.findByText("Topology settings")).toBeTruthy();
  });
});


describe("blueprint picker text", () => {
  test("MINILAB says its workstation boots Server 2022 on GCP and AWS", () => {
    const minilab = TEMPLATES.defense.find((t) => t.name === "MINILAB");
    expect(minilab.blurb).toMatch(/Windows 10 workstation/);
    expect(minilab.blurb).toMatch(/Server 2022 on GCP and AWS/);
  });
});


describe("the deploy target saves with the topology", () => {
  const THREE = [
    { name: "gcp", capabilities: ["windows_image"], maturity: "proven" },
    { name: "aws", capabilities: ["windows_image"], maturity: "proven" },
    { name: "azure", capabilities: ["windows_image"], maturity: "proven" },
  ];
  const OFFENSE_ONLY = [...THREE, { name: "linuxonly", capabilities: [], maturity: "proven" }];
  const SAVED = {
    schema_version: "0.7.0", mode: "offense", name: "Range", prefix: "off", provider: "azure",
    nodes: [{ id: "c2-net01", kind: "network", overlay: { cidr: "10.30.0.0/16" }, position: { x: 0, y: 0 } }],
    edges: [],
  };

  test("targetFor prefers a provider the mode can build, else the session choice", () => {
    expect(targetFor("offense", THREE, "azure", "gcp")).toBe("azure");
    expect(targetFor("offense", THREE, undefined, "aws")).toBe("aws");
    // Before the registry answers, the saved one stands.
    expect(targetFor("offense", [], "azure", "gcp")).toBe("azure");
    // A defense range cannot deploy where there is no Windows image.
    expect(targetFor("defense", OFFENSE_ONLY, "linuxonly", "aws")).toBe("aws");
    expect(targetFor("offense", THREE, "nowhere", "gcp")).toBe("gcp");
  });

  test("a reload restores the saved target, a pick marks unsaved and saves, undo puts it back",
    async () => {
      openUrl("?topology=g1");
      const calls = fakeBackend({ documents: { g1: SAVED }, providers: THREE });
      const user = userEvent.setup();
      render(<App />);
      expect(await screen.findByRole("button", { name: "Deploy target: Azure" })).toBeTruthy();
      expect(screen.getByText(/Saved, version 1/)).toBeTruthy();

      await user.click(screen.getByRole("button", { name: "Deploy target: Azure" }));
      await user.click(screen.getByRole("option", { name: /AWS/ }));
      expect(await screen.findByText("Unsaved changes")).toBeTruthy();

      await user.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(() =>
        expect(calls.some((c) => c.method === "PUT")).toBe(true));
      const put = calls.find((c) => c.method === "PUT");
      expect(put.body.document.provider).toBe("aws");

      fireEvent.click(screen.getByRole("button", { name: "Deploy target: AWS" }));
      await user.click(screen.getByRole("option", { name: /GCP/ }));
      await screen.findByRole("button", { name: "Deploy target: GCP" });
      window.document.body.focus();
      await user.click(screen.getByRole("button", { name: "Undo" }));
      expect(await screen.findByRole("button", { name: "Deploy target: AWS" })).toBeTruthy();
    });

  test("the download button names the target", async () => {
    openUrl("?topology=g1");
    fakeBackend({ documents: { g1: SAVED }, providers: THREE });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("button", { name: "Deploy target: Azure" });
    await user.click(screen.getByRole("button", { name: "Export" }));
    expect(await screen.findByRole("button", { name: "Download (Azure)" })).toBeTruthy();
  });

  test("on a locked blueprint a pick is a session choice and the view stays clean",
    async () => {
      fakeBackend({ providers: THREE });
      const user = userEvent.setup();
      render(<App />);
      await user.click(await screen.findByRole("tab", { name: "Defense" }));
      await user.click(await screen.findByRole("button", { name: "Load blueprint" }));
      const dialog = await screen.findByRole("dialog", { name: "Load a blueprint" });
      await user.click(within(dialog).getByText("GOAD-Light").closest("button"));
      await screen.findByText("Unlock to edit");

      await user.click(screen.getByRole("button", { name: /Deploy target:/ }));
      await user.click(screen.getByRole("option", { name: /AWS/ }));
      expect(await screen.findByRole("button", { name: "Deploy target: AWS" })).toBeTruthy();
      expect(screen.getByText("Not saved")).toBeTruthy();
    });
});


describe("extensions follow the source blueprint", () => {
  const lab = (extra) => ({ mode: "defense", nodes: [], edges: [], ...extra });

  test("matched on blueprint first, on the name only for older documents", () => {
    expect(supportsExtension(lab({ name: "My lab (copy)", blueprint: "goad-light" }), "ws01")).toBe(true);
    expect(supportsExtension(lab({ name: "GOAD", blueprint: "nha" }), "ws01")).toBe(false);
    expect(supportsExtension(lab({ name: "GOAD-Light" }), "ws01")).toBe(true);
    expect(supportsExtension(lab({ name: "renamed" }), "ws01")).toBe(false);
    expect(supportsExtension(lab({ name: "anything", blueprint: "nha" }), "wazuh")).toBe(true);
  });

  async function loadGoadLight(user) {
    await user.click(await screen.findByRole("tab", { name: "Defense" }));
    await user.click(await screen.findByRole("button", { name: "Load blueprint" }));
    const dialog = await screen.findByRole("dialog", { name: "Load a blueprint" });
    await user.click(within(dialog).getByText("GOAD-Light").closest("button"));
    await screen.findByText("Unlock to edit");
  }

  test("a loaded blueprint is tagged without an edit, and a renamed copy keeps its extensions",
    async () => {
      fakeBackend();
      const user = userEvent.setup();
      render(<App />);
      await loadGoadLight(user);
      expect(screen.getByText("Not saved")).toBeTruthy();

      const name = screen.getByLabelText("Topology name");
      await user.clear(name);
      await user.type(name, "Team range");
      await user.click(screen.getByRole("button", { name: "Extensions" }));
      const dialog = await screen.findByRole("dialog", { name: "GOAD extensions" });
      expect(within(dialog).getByText("Workstation (ws01)")).toBeTruthy();
    });

  test("Save a copy keeps the source blueprint", async () => {
    const doc = {
      schema_version: "0.7.0", mode: "defense", name: "GOAD-Light renamed", prefix: "def",
      blueprint: "goad-light",
      nodes: [{ id: "net01", kind: "network", overlay: { cidr: "192.168.0.0/16" }, position: { x: 0, y: 0 } }],
      edges: [],
    };
    openUrl("?topology=g3");
    const calls = fakeBackend({ documents: { g3: doc }, editable: false });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("net01");
    await user.type(screen.getByLabelText("Topology name"), "!");
    await user.click(screen.getByRole("button", { name: "Save a copy" }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/topologies"))).toBe(true));
    const post = calls.find((c) => c.method === "POST" && c.url.endsWith("/topologies"));
    expect(post.body.document.blueprint).toBe("goad-light");
  });
});
