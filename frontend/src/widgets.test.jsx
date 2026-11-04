// The structured Inspector editors, rendered through the real Inspector against
// the real schema: trusts, fronts ports, edge roles, connections, ACLs, users,
// gMSAs, group nesting and the topology settings. Each harness keeps the
// document in state and applies edits the way App does.

import React, { useState } from "react";
import { describe, expect, test } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import SCHEMA from "../../src/redstackpro/schema/topology/0.7.0.json";
import { Inspector } from "./Inspector.jsx";
import { addEdge, updateEdge, updateOverlay } from "./topology.js";
import { rolesFor } from "./edgeRoles.js";

function Harness({ initial, selection, seen = [], ...rest }) {
  const [doc, setDoc] = useState(initial);
  const apply = (fn) =>
    setDoc((d) => {
      const next = fn(d);
      seen.push(next);
      return next;
    });
  return (
    <Inspector
      schema={SCHEMA}
      selection={selection}
      document={doc}
      findings={[]}
      onOverlayChange={(id, overlay) => apply((d) => updateOverlay(d, id, overlay))}
      onEdgeChange={(id, patch) => apply((d) => updateEdge(d, id, patch))}
      onAddEdge={(s, t, r) => apply((d) => addEdge(d, s, t, r))}
      onRename={() => {}}
      onDelete={() => {}}
      kindLabels={{}}
      {...rest}
    />
  );
}

const last = (seen) => seen[seen.length - 1];

// -- edge roles

describe("edge roles follow the endpoint kinds", () => {
  test("rolesFor mirrors the drawn roles in roles.yaml", () => {
    expect(rolesFor("redirector", "teamserver")).toEqual(["fronts"]);
    expect(rolesFor("teamserver", "collector")).toEqual(["logs_to"]);
    expect(rolesFor("network", "network")).toEqual(["peers"]);
    expect(rolesFor("domain", "domain")).toEqual(["trusts"]);
    expect(rolesFor("jumpbox", "network")).toEqual([]);
    expect(rolesFor("teamserver", "redirector")).toEqual([]);
  });

  function offenseDoc(edges) {
    return {
      schema_version: "0.7.0",
      mode: "offense",
      prefix: "off",
      nodes: [
        { id: "rdr01", kind: "redirector", overlay: {} },
        { id: "myth-ts01", kind: "teamserver", overlay: { c2: "mythic" } },
        { id: "log-col01", kind: "collector", overlay: {} },
        { id: "main-net01", kind: "network", overlay: {} },
      ],
      edges,
    };
  }

  test("a logs_to line shows its role as text, prefixed names, and never offers manages", () => {
    render(
      <Harness
        initial={offenseDoc([{ id: "e1", role: "logs_to", source: "myth-ts01", target: "log-col01" }])}
        selection={{ type: "edge", id: "e1" }}
      />
    );
    expect(screen.getByRole("heading", { name: "Ships logs to" })).toBeTruthy();
    expect(screen.getByText("off-myth-ts01")).toBeTruthy();
    expect(screen.getByText("off-log-col01")).toBeTruthy();
    expect(screen.queryByRole("combobox", { name: "role" })).toBeNull();
    expect(screen.queryByText(/manages/i)).toBeNull();
  });

  test("a line whose role no longer fits its ends offers the roles that do", async () => {
    const seen = [];
    render(
      <Harness
        initial={offenseDoc([
          { id: "e1", role: "fronts", source: "rdr01", target: "log-col01", protocol: "https", listen_port: 443, uri_prefix: "/cdn" },
        ])}
        selection={{ type: "edge", id: "e1" }}
        seen={seen}
      />
    );
    const select = screen.getByRole("combobox", { name: "role" });
    const labels = within(select).getAllByRole("option").map((o) => o.textContent);
    expect(labels).toEqual(["C2 route (not valid from a redirector to a collector)", "Ships logs to"]);
    await userEvent.setup().selectOptions(select, "logs_to");
    const edge = last(seen).edges[0];
    expect(edge.role).toBe("logs_to");
    expect(edge.uri_prefix).toBeUndefined();
    expect(edge.protocol).toBeUndefined();
  });

  test("Connections lists only nodes a line can reach and adds the line they take", async () => {
    const user = userEvent.setup();
    const seen = [];
    render(
      <Harness initial={offenseDoc([])} selection={{ type: "node", id: "rdr01" }} seen={seen} />
    );
    const select = screen.getByRole("combobox", { name: "connect to" });
    const names = within(select).getAllByRole("option").map((o) => o.textContent);
    expect(names).toEqual(["connect to...", "off-myth-ts01", "off-log-col01"]);
    await user.selectOptions(select, "myth-ts01");
    expect(screen.getByText("Adds: off-rdr01 routes C2 to off-myth-ts01.")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Add" }));
    const edge = last(seen).edges[0];
    expect(edge).toMatchObject({ role: "fronts", source: "rdr01", target: "myth-ts01" });
  });

  test("Connections adds a reverse line when only that direction is valid", async () => {
    const user = userEvent.setup();
    const seen = [];
    render(
      <Harness initial={offenseDoc([])} selection={{ type: "node", id: "log-col01" }} seen={seen} />
    );
    await user.selectOptions(screen.getByRole("combobox", { name: "connect to" }), "myth-ts01");
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(last(seen).edges[0]).toMatchObject({ role: "logs_to", source: "myth-ts01", target: "log-col01" });
  });

  test("connection rows read as phrases about the other end", () => {
    render(
      <Harness
        initial={offenseDoc([{ id: "e1", role: "logs_to", source: "myth-ts01", target: "log-col01" }])}
        selection={{ type: "node", id: "log-col01" }}
      />
    );
    const row = screen.getByRole("button", { name: /Receives logs from/ });
    expect(row.textContent).toContain("off-myth-ts01");
  });
});

// -- fronts ports

describe("fronts edge protocol and ports", () => {
  const doc = (extra) => ({
    schema_version: "0.7.0",
    mode: "offense",
    prefix: "off",
    nodes: [
      { id: "rdr01", kind: "redirector", overlay: {} },
      { id: "ts01", kind: "teamserver", overlay: {} },
    ],
    edges: [{ id: "e1", role: "fronts", source: "rdr01", target: "ts01", uri_prefix: "/cdn", ...extra }],
  });

  test("defaults read as HTTPS, 443 to 443 with nothing to edit", () => {
    render(
      <Harness
        initial={doc({ protocol: "https", listen_port: 443, upstream_port: 443 })}
        selection={{ type: "edge", id: "e1" }}
      />
    );
    expect(screen.getByText("HTTPS, 443 to 443")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Reset to HTTPS 443" })).toBeNull();
    expect(screen.queryByRole("spinbutton")).toBeNull();
  });

  test("other values are explained and reset", async () => {
    const seen = [];
    render(
      <Harness
        initial={doc({ protocol: "dns", listen_port: 8443, upstream_port: 80 })}
        selection={{ type: "edge", id: "e1" }}
        seen={seen}
      />
    );
    expect(screen.getByText("DNS, 8443 to 80")).toBeTruthy();
    expect(
      screen.getByText("Redirectors serve HTTPS on 443 only; other values open a port nothing answers on.")
    ).toBeTruthy();
    await userEvent.setup().click(screen.getByRole("button", { name: "Reset to HTTPS 443" }));
    expect(last(seen).edges[0]).toMatchObject({ protocol: "https", listen_port: 443, upstream_port: 443 });
    expect(screen.getByText("HTTPS, 443 to 443")).toBeTruthy();
  });
});
