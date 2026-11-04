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
import {
  connectOptions, defaultTrustPatch, parentChild, rolesFor,
} from "./edgeRoles.js";
import { domainDirectory, principalStatus, targetStatus } from "./domainDirectory.js";

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

// -- trusts

function rangeDoc(edges, extraDomains = []) {
  return {
    schema_version: "0.7.0",
    mode: "defense",
    prefix: "def",
    nodes: [
      { id: "sevenkingdoms", kind: "domain", overlay: { fqdn: "sevenkingdoms.local", netbios: "SEVENKINGDOMS" } },
      { id: "north", kind: "domain", overlay: { fqdn: "north.sevenkingdoms.local", netbios: "NORTH" } },
      { id: "essos", kind: "domain", overlay: { fqdn: "essos.local", netbios: "ESSOS" } },
      ...extraDomains,
    ],
    edges,
  };
}

describe("trust editor", () => {
  test("the default type follows the FQDNs, and a parent and child is oriented parent first", () => {
    const doc = rangeDoc([]);
    expect(parentChild(doc, "north", "sevenkingdoms")).toEqual({ parent: "sevenkingdoms", child: "north" });
    expect(defaultTrustPatch(doc, { source: "north", target: "sevenkingdoms" })).toEqual({
      trust_type: "parent_child", source: "sevenkingdoms", target: "north",
    });
    expect(defaultTrustPatch(doc, { source: "sevenkingdoms", target: "essos" })).toEqual({ trust_type: "forest" });
    const unnamed = rangeDoc([], [{ id: "corp", kind: "domain", overlay: {} }]);
    expect(defaultTrustPatch(unnamed, { source: "corp", target: "essos" })).toBeNull();
  });

  test("an untyped trust drawn child to parent is typed and flipped when first shown", () => {
    const seen = [];
    render(
      <Harness
        initial={rangeDoc([{ id: "t1", role: "trusts", source: "north", target: "sevenkingdoms" }])}
        selection={{ type: "edge", id: "t1" }}
        seen={seen}
      />
    );
    expect(last(seen).edges[0]).toMatchObject({
      trust_type: "parent_child", source: "sevenkingdoms", target: "north",
    });
    expect(screen.getByRole("combobox", { name: "trust type" }).value).toBe("parent_child");
    expect(screen.queryByRole("combobox", { name: "role" })).toBeNull();
    expect(screen.getByText(/north.sevenkingdoms.local is created as a child domain under sevenkingdoms.local/)).toBeTruthy();
  });

  test("an untyped trust between two forests becomes a forest trust with plain directions", () => {
    const seen = [];
    render(
      <Harness
        initial={rangeDoc([{ id: "t1", role: "trusts", source: "sevenkingdoms", target: "essos" }])}
        selection={{ type: "edge", id: "t1" }}
        seen={seen}
      />
    );
    expect(last(seen).edges[0].trust_type).toBe("forest");
    const dir = screen.getByRole("combobox", { name: "trust direction" });
    expect(within(dir).getAllByRole("option").map((o) => o.textContent)).toEqual([
      "Two-way: each domain trusts the other",
      "One-way: sevenkingdoms.local trusts essos.local",
      "One-way: essos.local trusts sevenkingdoms.local",
    ]);
    expect(screen.getByRole("checkbox", { name: "transitive" }).checked).toBe(true);
  });

  test("external and tree root say they are not built", async () => {
    const user = userEvent.setup();
    render(
      <Harness
        initial={rangeDoc([{ id: "t1", role: "trusts", source: "sevenkingdoms", target: "essos", trust_type: "forest" }])}
        selection={{ type: "edge", id: "t1" }}
      />
    );
    const type = screen.getByRole("combobox", { name: "trust type" });
    expect(within(type).getAllByRole("option").map((o) => o.textContent)).toEqual([
      "Parent and child", "Forest", "External", "Tree root",
    ]);
    expect(screen.queryByText(/Not built yet/)).toBeNull();
    await user.selectOptions(type, "external");
    expect(screen.getByText("Not built yet: this trust type is recorded but not created.")).toBeTruthy();
    await user.selectOptions(type, "tree_root");
    expect(screen.getByText("Not built yet: this trust type is recorded but not created.")).toBeTruthy();
  });

  test("a trust between unnamed domains stays unset and says how it will be decided", () => {
    const seen = [];
    render(
      <Harness
        initial={rangeDoc(
          [{ id: "t1", role: "trusts", source: "corp", target: "essos" }],
          [{ id: "corp", kind: "domain", overlay: {} }]
        )}
        selection={{ type: "edge", id: "t1" }}
        seen={seen}
      />
    );
    expect(seen).toHaveLength(0);
    expect(screen.getByRole("combobox", { name: "trust type" }).value).toBe("");
    expect(screen.getByText(/Set both domains' FQDN and it is picked for you/)).toBeTruthy();
  });

  test("connecting two domains from Connections adds a typed, oriented trust", async () => {
    const user = userEvent.setup();
    const seen = [];
    render(<Harness initial={rangeDoc([])} selection={{ type: "node", id: "north" }} seen={seen} />);
    expect(connectOptions(rangeDoc([]), { id: "north", kind: "domain" }, { id: "sevenkingdoms", kind: "domain" }))
      .toEqual([{ role: "trusts", source: "sevenkingdoms", target: "north" }]);
    await user.selectOptions(screen.getByRole("combobox", { name: "connect to" }), "sevenkingdoms");
    const connections = within(screen.getByRole("heading", { name: "Connections" }).closest(".rg-connections"));
    await user.click(connections.getByRole("button", { name: "Add" }));
    expect(last(seen).edges[0]).toMatchObject({
      role: "trusts", source: "sevenkingdoms", target: "north", trust_type: "parent_child",
    });
  });
});

// -- domain editors

function essosDoc(overlay = {}) {
  return {
    schema_version: "0.7.0",
    mode: "defense",
    prefix: "def",
    nodes: [
      {
        id: "essos",
        kind: "domain",
        overlay: {
          fqdn: "essos.local",
          netbios: "ESSOS",
          users: [
            { username: "khal.drogo", privilege: "domain_admin", groups: ["Dothraki"] },
            { username: "viserys.targaryen", groups: ["Targaryen"] },
          ],
          ous: ["Pentos"],
          ...overlay,
        },
      },
      { id: "meereen", kind: "dc", overlay: { os: "windows_server_2019" } },
      { id: "braavos", kind: "srv", overlay: { hostname: "braavos" } },
    ],
    edges: [
      { id: "j1", role: "joins", source: "meereen", target: "essos" },
      { id: "j2", role: "joins", source: "braavos", target: "essos" },
    ],
  };
}

const domainSelection = { type: "node", id: "essos" };

describe("ACL editor", () => {
  test("the directory knows users, groups, computers, gMSAs and OUs", () => {
    const doc = essosDoc({ gmsa: [{ name: "gmsaDragon", hosts: ["braavos"] }] });
    const dir = domainDirectory(doc, doc.nodes[0]);
    expect(dir.users).toEqual(["khal.drogo", "viserys.targaryen"]);
    expect(dir.groups).toEqual(["Dothraki", "Targaryen"]);
    expect(dir.computers).toEqual(["braavos$", "meereen$"]);
    expect(dir.gmsa).toEqual(["gmsaDragon$"]);
    expect(principalStatus(dir, "KHAL.DROGO")).toBe("known");
    expect(principalStatus(dir, "Domain Admins")).toBe("known");
    expect(principalStatus(dir, "NT AUTHORITY\\ANONYMOUS LOGON")).toBe("known");
    expect(principalStatus(dir, "khal.drgo")).toBe("created");
    expect(targetStatus(dir, "OU=Pentos,DC=essos,DC=local")).toBe("dn");
    expect(targetStatus(dir, "Pentos")).toBe("known");
    expect(targetStatus(dir, "castelblack$")).toBe("skipped");
    expect(targetStatus(dir, "viserys")).toBe("created");
  });

  test("principal and target offer this domain's names, and a typo is flagged before Add", async () => {
    const user = userEvent.setup();
    const seen = [];
    const { container } = render(
      <Harness initial={essosDoc()} selection={domainSelection} seen={seen} />
    );
    const principal = screen.getByRole("combobox", { name: "principal" });
    const target = screen.getByRole("combobox", { name: "target" });
    const values = (input) =>
      [...container.querySelector(`datalist[id="${input.getAttribute("list")}"]`).options].map((o) => o.value);
    expect(values(principal)).toEqual(expect.arrayContaining(["khal.drogo", "Domain Admins", "Dothraki", "braavos$"]));
    expect(values(target)).toEqual(expect.arrayContaining(["viserys.targaryen", "OU=Pentos,DC=essos,DC=local"]));

    await user.type(principal, "khal.drgo");
    expect(screen.getByText("khal.drgo is not found on this domain; it would be created as an empty group.")).toBeTruthy();
    await user.type(target, "castelblack$");
    expect(screen.getByText("castelblack$ is not found on this domain; this right would be skipped.")).toBeTruthy();
  });

  test("rights are the ones that compile, each with its meaning", async () => {
    const user = userEvent.setup();
    const seen = [];
    render(<Harness initial={essosDoc()} selection={domainSelection} seen={seen} />);
    const right = screen.getByRole("combobox", { name: "right" });
    const values = within(right).getAllByRole("option").map((o) => o.value);
    expect(values).toEqual(expect.arrayContaining([
      "GenericAll", "ForceChangePassword", "AddMember", "Ext-Write-SPN", "Ext-User-Force-Change-Password",
    ]));
    await user.selectOptions(right, "ForceChangePassword");
    expect(screen.getByText("Reset the target user's password without knowing the old one.")).toBeTruthy();
    await user.type(screen.getByRole("combobox", { name: "principal" }), "khal.drogo");
    await user.type(screen.getByRole("combobox", { name: "target" }), "viserys.targaryen");
    await user.click(within(screen.getByText(/^Access rights/).closest(".rg-acls")).getByRole("button", { name: "Add" }));
    expect(last(seen).nodes[0].overlay.acls).toEqual([
      { principal: "khal.drogo", target: "viserys.targaryen", right: "ForceChangePassword" },
    ]);
  });

  test("a saved right the script does not know is called out", () => {
    render(
      <Harness
        initial={essosDoc({ acls: [{ principal: "khal.drogo", target: "Domain Admins", right: "AllExtendedRights" }] })}
        selection={domainSelection}
      />
    );
    expect(screen.getByText("AllExtendedRights is not a right redStackPRO applies; this entry is skipped.")).toBeTruthy();
  });
});
