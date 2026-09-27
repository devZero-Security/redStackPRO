// The host VulnPicker's account-technique bridge, rendered.
//
// kerberoasting, asreproasting, password_in_description, and weak_password are
// account flaws, not host tasks (see vulns.js and rangeUsers.js
// plantAccountTechnique). Checking one of these four on a host's vuln picker
// must plant a matching flawed user on the host's joined domain rather than
// write into the host's own overlay.vulns, and unchecking it must remove
// exactly that user. These tests drive the real Inspector component (not a
// mock of it) against a small in-memory document, the same way App wires
// onOverlayChange, so the plant/remove/no-op behavior is exercised end to end.

import React, { useState } from "react";
import { describe, expect, test } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { Inspector } from "./Inspector.jsx";

// Just enough of the real schema for the host and domain overlay panels: the
// vulns array (so VulnPicker renders) and the domain's users array (so
// DomainUsers renders and a planted user shows up).
const SCHEMA = {
  $defs: {
    overlay_range_host: {
      properties: {
        vulns: { type: "array", "x-redstackpro-source": "user", items: {} },
      },
    },
    overlay_domain: {
      properties: {
        users: {
          type: "array",
          "x-redstackpro-source": "user",
          items: {
            properties: {
              flaws: {
                items: {
                  enum: ["kerberoastable", "asrep_roastable", "password_in_description", "weak_password", "spn_set"],
                },
              },
            },
          },
        },
      },
    },
  },
};

function baseDocument() {
  return {
    schema_version: "0.6.0",
    mode: "haven",
    prefix: "hv",
    nodes: [
      { id: "dc01", kind: "domain", overlay: { fqdn: "sk.local", users: [] } },
      { id: "srv01", kind: "srv", overlay: { vulns: [] } }, // joined to dc01
      { id: "srv02", kind: "srv", overlay: { vulns: [] } }, // not joined
    ],
    edges: [{ id: "e1", role: "joins", source: "srv01", target: "dc01" }],
  };
}

// Three Inspector panels sharing one document, the way three separate
// selections of the same canvas would: a joined host, an unjoined host, and
// the domain, so a plant on one panel is visible from another.
function Harness() {
  const [document, setDocument] = useState(baseDocument());
  const onOverlayChange = (nodeId, overlay) =>
    setDocument((d) => ({
      ...d,
      nodes: d.nodes.map((n) => (n.id === nodeId ? { ...n, overlay } : n)),
    }));
  const panel = (id) => (
    <Inspector
      schema={SCHEMA}
      selection={{ type: "node", id }}
      document={document}
      findings={[]}
      onOverlayChange={onOverlayChange}
      onRename={() => {}}
      onDelete={() => {}}
      kindLabels={{}}
    />
  );
  return (
    <div>
      <div data-testid="joined-host">{panel("srv01")}</div>
      <div data-testid="unjoined-host">{panel("srv02")}</div>
      <div data-testid="domain">{panel("dc01")}</div>
    </div>
  );
}

const panels = () => ({
  joinedHost: within(screen.getByTestId("joined-host")),
  unjoinedHost: within(screen.getByTestId("unjoined-host")),
  domain: within(screen.getByTestId("domain")),
});

describe("account techniques on the host vuln picker", () => {
  test("checking kerberoasting on a domain-joined host plants a marked user", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const { joinedHost, domain } = panels();

    const box = joinedHost.getByRole("checkbox", { name: "Kerberoasting" });
    expect(box.checked).toBe(false);
    expect(box.disabled).toBe(false);

    await user.click(box);

    expect(joinedHost.getByRole("checkbox", { name: "Kerberoasting" }).checked).toBe(true);
    // The user landed on the domain, not the host: it did not go into the
    // host's own overlay.vulns.
    const row = domain.getByRole("button", { name: "svc.kerberoast" });
    expect(row).toBeTruthy();
    expect(within(row.closest(".rg-user")).getByText("2 flaws")).toBeTruthy();
  });

  test("unchecking removes exactly that planted user", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const { joinedHost, domain } = panels();

    await user.click(joinedHost.getByRole("checkbox", { name: "Kerberoasting" }));
    expect(domain.getByRole("button", { name: "svc.kerberoast" })).toBeTruthy();

    await user.click(joinedHost.getByRole("checkbox", { name: "Kerberoasting" }));

    expect(joinedHost.getByRole("checkbox", { name: "Kerberoasting" }).checked).toBe(false);
    expect(domain.queryByRole("button", { name: "svc.kerberoast" })).toBeNull();
  });

  test("planting two different techniques adds two separate users, removable independently", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const { joinedHost, domain } = panels();

    await user.click(joinedHost.getByRole("checkbox", { name: "Kerberoasting" }));
    await user.click(joinedHost.getByRole("checkbox", { name: "AS-REP roasting" }));

    expect(domain.getByRole("button", { name: "svc.kerberoast" })).toBeTruthy();
    expect(domain.getByRole("button", { name: "roastme" })).toBeTruthy();

    await user.click(joinedHost.getByRole("checkbox", { name: "Kerberoasting" }));

    expect(domain.queryByRole("button", { name: "svc.kerberoast" })).toBeNull();
    expect(domain.getByRole("button", { name: "roastme" })).toBeTruthy();
  });

  test("a host with no joined domain cannot plant: the checkbox is disabled with a hint", async () => {
    render(<Harness />);
    const { unjoinedHost } = panels();

    const box = unjoinedHost.getByRole("checkbox", { name: "Kerberoasting" });
    expect(box.disabled).toBe(true);
    expect(
      unjoinedHost.getByText("Join this host to a domain to plant account techniques.")
    ).toBeTruthy();
  });

  test("a normal host vuln still toggles into the host's own overlay.vulns", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const { joinedHost, domain } = panels();

    // Coercion & relay starts collapsed (nothing in it is selected yet).
    await user.click(joinedHost.getByRole("button", { name: "Coercion & relay" }));
    const box = joinedHost.getByRole("checkbox", { name: "SMBv1 enabled" });
    expect(box.checked).toBe(false);

    await user.click(box);

    expect(joinedHost.getByRole("checkbox", { name: "SMBv1 enabled" }).checked).toBe(true);
    expect(joinedHost.getByText("vulnerabilities (1)")).toBeTruthy();
    // No domain user was created for a plain host vuln.
    expect(domain.getByText("Users")).toBeTruthy();
    expect(domain.queryByText(/^\d+ flaws?$/)).toBeNull();
  });
});
