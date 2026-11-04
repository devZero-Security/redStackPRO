// The app shell over the merged widgets and validator: how a new trust is
// typed, what the legend calls each line, and how the footer reads findings of
// each severity, including the info notices and document-level findings.

import React from "react";
import { describe, expect, test, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import App from "./App.jsx";
import { connectEdge, emptyDocument, legendItems } from "./topology.js";
import { edgeId } from "./idscheme.js";
import { countBySeverity, findingSelection, sortFindings } from "./findingSeverity.js";
import { TEMPLATES } from "./templates.js";

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

function fakeBackend({ documents = {}, findings = [] } = {}) {
  global.fetch = vi.fn(async (url, options = {}) => {
    const method = options.method || "GET";
    if (url.includes("/registry/palette")) return respond(200, { groups: PALETTE });
    if (url.includes("/registry/schema")) return respond(200, { $defs: {} });
    if (url.includes("/registry/providers")) {
      return respond(200, { providers: [
        { name: "gcp", capabilities: ["windows_image"], maturity: "proven" },
      ] });
    }
    if (url.includes("/health")) return respond(200, { status: "ok", app_version: "9.9.9" });
    if (url.endsWith("/validate")) return respond(200, { findings });
    if (url.includes("/topologies?") && method === "GET") return respond(200, []);
    const match = url.match(/\/topologies\/([^/?]+)$/);
    if (match && method === "GET" && documents[match[1]]) {
      return respond(200, {
        topology: {
          id: match[1], name: "Range", mode: documents[match[1]].mode, visibility: "private",
          schema_version: "0.7.0", version: 1, owner_id: "u1", is_blueprint: false, editable: true,
        },
        document: documents[match[1]],
      });
    }
    return respond(404, { code: "not_found", message: "no route: " + url });
  });
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
