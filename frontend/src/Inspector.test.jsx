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
import { fireEvent, render, screen, within } from "@testing-library/react";
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
        acls: { type: "array", "x-redstackpro-source": "user", items: {} },
      },
    },
  },
};

function baseDocument() {
  return {
    schema_version: "0.7.0",
    mode: "defense",
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
    // kerberoastable and spn_set are one flaw, counted once.
    expect(within(row.closest(".rg-user")).getByText("1 flaw")).toBeTruthy();
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

// A locked defense template (readOnly, before "Unlock to edit") must still show
// the planted domain users and ACL edges: that is the content a person wants
// to preview before deciding to unlock. Only vulns/hardening stayed visible
// before this change; users/acls used to be omitted outright when readOnly.
describe("users and acls on a locked (readOnly) domain", () => {
  function lockedDomainDocument() {
    return {
      schema_version: "0.7.0",
      mode: "defense",
      prefix: "hv",
      nodes: [
        {
          id: "dc01",
          kind: "domain",
          overlay: {
            fqdn: "sk.local",
            users: [{ username: "j.smith", privilege: "domain_admin", flaws: ["weak_password"] }],
            acls: [{ principal: "j.smith", target: "Domain Admins", right: "GenericAll" }],
          },
        },
      ],
      edges: [],
    };
  }

  test("users list renders read-only: visible, no add form, no delete, controls disabled", () => {
    const document = lockedDomainDocument();
    render(
      <Inspector
        schema={SCHEMA}
        selection={{ type: "node", id: "dc01" }}
        document={document}
        findings={[]}
        onOverlayChange={() => {}}
        onRename={() => {}}
        onDelete={() => {}}
        kindLabels={{}}
        readOnly
      />
    );

    // The planted account is visible, not hidden.
    expect(screen.getByText("Users (1)")).toBeTruthy();
    expect(screen.getByRole("button", { name: "j.smith" })).toBeTruthy();

    // Nothing that mutates the list is offered.
    expect(screen.queryByPlaceholderText("username, e.g. j.smith")).toBeNull();
    expect(screen.queryByRole("button", { name: "Populate random" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove user" })).toBeNull();

    // The privilege select is present but disabled.
    const priv = screen.getByDisplayValue("domain admin");
    expect(priv.disabled).toBe(true);
  });

  test("acls list renders read-only: visible, no add row, no delete", () => {
    const document = lockedDomainDocument();
    render(
      <Inspector
        schema={SCHEMA}
        selection={{ type: "node", id: "dc01" }}
        document={document}
        findings={[]}
        onOverlayChange={() => {}}
        onRename={() => {}}
        onDelete={() => {}}
        kindLabels={{}}
        readOnly
      />
    );

    expect(screen.getByText("Access rights (1)")).toBeTruthy();
    const acls = within(screen.getByText("Access rights (1)").closest(".rg-acls"));
    expect(acls.getByText("j.smith")).toBeTruthy();
    expect(acls.getByText("Domain Admins")).toBeTruthy();

    expect(acls.queryByPlaceholderText("principal")).toBeNull();
    expect(acls.queryByPlaceholderText("target")).toBeNull();
    expect(acls.queryByRole("button", { name: "Remove right" })).toBeNull();
  });
});

// vulns_vars is an object with free keys. It is edited as JSON text that only
// reaches the document once it parses to an object; it used to be a plain input
// that showed "[object Object]" and saved what was typed as a string.
const VV_SCHEMA = {
  $defs: {
    overlay_range_host: {
      properties: {
        vulns: { type: "array", "x-redstackpro-source": "user", items: {} },
        vulns_vars: {
          type: "object",
          description: "Per-vuln parameters for this host's declared vulns, e.g. a file share path or a delegation target.",
          additionalProperties: true,
        },
      },
    },
  },
};

function HostHarness({ overlay, onChange = () => {} }) {
  const [document, setDocument] = useState({
    schema_version: "0.7.0",
    mode: "defense",
    prefix: "hv",
    nodes: [{ id: "wks01", kind: "wks", overlay }],
    edges: [],
  });
  return (
    <Inspector
      schema={VV_SCHEMA}
      selection={{ type: "node", id: "wks01" }}
      document={document}
      findings={[]}
      onOverlayChange={(nodeId, next) => {
        onChange(next);
        setDocument((d) => ({
          ...d,
          nodes: d.nodes.map((n) => (n.id === nodeId ? { ...n, overlay: next } : n)),
        }));
      }}
      onRename={() => {}}
      onDelete={() => {}}
      kindLabels={{}}
    />
  );
}

const vulnsVarsBox = () => screen.getByRole("textbox", { name: "vulns_vars" });

describe("vulns_vars is edited as JSON", () => {
  test("an existing object shows as JSON, not [object Object]", () => {
    render(<HostHarness overlay={{ vulns: [], vulns_vars: { bot_user: "T\a" } }} />);
    expect(JSON.parse(vulnsVarsBox().value)).toEqual({ bot_user: "T\a" });
  });

  test("valid JSON is saved as an object; invalid JSON keeps the last value", () => {
    const seen = [];
    render(<HostHarness overlay={{ vulns: [] }} onChange={(o) => seen.push(o)} />);
    fireEvent.change(vulnsVarsBox(), { target: { value: '{"delegate_to": ["CIFS/dc01.t.lab"]}' } });
    expect(seen.at(-1).vulns_vars).toEqual({ delegate_to: ["CIFS/dc01.t.lab"] });

    fireEvent.change(vulnsVarsBox(), { target: { value: '{"delegate_to": [' } });
    expect(seen).toHaveLength(1);
    expect(screen.getByText("Not valid JSON yet. The last valid value is kept.")).toBeTruthy();

    fireEvent.change(vulnsVarsBox(), { target: { value: "" } });
    expect(seen.at(-1).vulns_vars).toBeUndefined();
  });
});

describe("vulns_vars help lists the keys of the ticked vulns", () => {
  const help = () => screen.getByRole("textbox", { name: "vulns_vars" }).closest(".rg-field");

  // The keys used to be a help list under the JSON; they are now the form above
  // it (vulnForm.test.jsx covers the inputs), and the JSON is its advanced view.
  test("a ticked parameterized vuln lists its keys, required or optional, in the form", () => {
    render(
      <HostHarness overlay={{ vulns: ["smbv1", "constrained_delegation_kerberos", "sysvol_secret", "ntlm_relay"] }} />
    );
    const box = within(document.querySelector(".rg-vuln-form"));
    expect(box.getByText("Constrained delegation (Kerberos only)")).toBeTruthy();
    expect(box.getByText("delegate_to")).toBeTruthy();
    expect(box.getByText("required")).toBeTruthy();
    expect(box.getByText("sysvol_secret.account")).toBeTruthy();
    expect(box.getByText("sysvol_secret.name")).toBeTruthy();
    expect(box.getAllByText("optional")).toHaveLength(2);
    // A User activity vuln keeps its box, pointing there, and shows no key twice.
    const relay = within(box.getByText("Relay bot (NTLM relay)").closest("fieldset"));
    expect(relay.getByText("Set under User activity above.")).toBeTruthy();
    expect(box.queryByText("ntlm_relay_user")).toBeNull();
    // smbv1 reads nothing, so it gets no entry.
    expect(box.queryByText("SMBv1 enabled")).toBeNull();
    const jsonField = screen.getByRole("textbox", { name: "Edit as JSON" }).closest(".rg-field");
    expect(within(jsonField).queryByText(/a file share path or a delegation target/)).toBeNull();
  });

  test("with no parameterized vuln ticked it stays the plain one-line help", () => {
    render(<HostHarness overlay={{ vulns: ["smbv1"] }} />);
    const box = within(help());
    expect(
      box.getByText("Per-vuln parameters for this host's declared vulns, e.g. a file share path or a delegation target.")
    ).toBeTruthy();
    expect(box.queryByText("delegate_to")).toBeNull();
    expect(help().querySelector(".rg-vuln-params")).toBeNull();
  });
});
