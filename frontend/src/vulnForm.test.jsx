// The vulnerability settings form, rendered in the real Inspector over the
// shipped blueprints: pickers for what names the topology, typed inputs for the
// rest, and the JSON view below it kept in step both ways.

import React, { useState } from "react";
import { describe, expect, test } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { computeAccessibleName } from "dom-accessibility-api";

import SCHEMA from "../../src/redstackpro/schema/topology/0.7.0.json";
import LIGHT from "../public/goad/goad-light.json";
import GOAD from "../public/goad/goad.json";
import { Inspector } from "./Inspector.jsx";

const clone = (v) => JSON.parse(JSON.stringify(v));

// One node of a blueprint in the Inspector, the way App wires it. `edit`
// changes the document before it renders; `seen` collects every overlay written.
function Panel({ blueprint, id, edit, findings = [], readOnly = false, seen }) {
  const [document, setDocument] = useState(() => {
    const doc = clone(blueprint);
    edit?.(doc);
    return doc;
  });
  return (
    <Inspector
      schema={SCHEMA}
      selection={{ type: "node", id }}
      document={document}
      findings={findings}
      readOnly={readOnly}
      onOverlayChange={(nodeId, overlay) => {
        if (nodeId === id) seen?.push(overlay);
        setDocument((d) => ({
          ...d,
          nodes: d.nodes.map((n) => (n.id === nodeId ? { ...n, overlay } : n)),
        }));
      }}
      onRename={() => {}}
      onDelete={() => {}}
      kindLabels={{}}
    />
  );
}

const overlayOf = (doc, id) => doc.nodes.find((n) => n.id === id).overlay;
const json = () => screen.getByRole("textbox", { name: "Edit as JSON" });
const jsonValue = () => JSON.parse(json().value);
const last = (seen) => seen.at(-1).vulns_vars;
const optionValues = (select) => [...select.querySelectorAll("option")].map((o) => o.value);

describe("domain user pickers", () => {
  test("a stored north\\user shows picked as NORTH\\user, and the document keeps it", () => {
    render(<Panel blueprint={LIGHT} id="winterfell" />);
    const bot = screen.getByRole("combobox", { name: "bot_user" });
    expect(bot.value).toBe("NORTH\\robb.stark");
    const groups = [...bot.querySelectorAll("optgroup")].map((g) => g.label);
    expect(groups).toEqual(["north.sevenkingdoms.local", "sevenkingdoms.local"]);
    expect(jsonValue().bot_user).toBe("north\\robb.stark");
  });

  test("picking a user writes DOMAIN\\user and the JSON follows", () => {
    const seen = [];
    render(<Panel blueprint={LIGHT} id="winterfell" seen={seen} />);
    fireEvent.change(screen.getByRole("combobox", { name: "ntlm_relay_user" }), {
      target: { value: "SEVENKINGDOMS\\tywin.lannister" },
    });
    expect(last(seen).ntlm_relay_user).toBe("SEVENKINGDOMS\\tywin.lannister");
    expect(last(seen).bot_user).toBe("north\\robb.stark");
    expect(jsonValue().ntlm_relay_user).toBe("SEVENKINGDOMS\\tywin.lannister");
  });

  test("an edit in the JSON shows in the form", () => {
    render(<Panel blueprint={LIGHT} id="winterfell" />);
    const next = { ...jsonValue(), bot_user: "NORTH\\arya.stark" };
    fireEvent.change(json(), { target: { value: JSON.stringify(next) } });
    expect(screen.getByRole("combobox", { name: "bot_user" }).value).toBe("NORTH\\arya.stark");
  });

  test("Other takes a typed name and says when the range has no such user", () => {
    const seen = [];
    render(<Panel blueprint={LIGHT} id="winterfell" seen={seen} />);
    fireEvent.change(screen.getByRole("combobox", { name: "bot_user" }), { target: { value: "__other__" } });
    const typed = screen.getByRole("textbox", { name: "bot_user, typed" });
    expect(typed.value).toBe("north\\robb.stark");
    fireEvent.change(typed, { target: { value: "NORTH\\ghost" } });
    expect(last(seen).bot_user).toBe("NORTH\\ghost");
    expect(screen.getByText("Not a user in this range.")).toBeTruthy();
    expect(screen.getByText("Type it as DOMAIN\\user.")).toBeTruthy();
  });

  test("a bare user picker offers this domain's users by name alone", () => {
    render(<Panel blueprint={LIGHT} id="winterfell" />);
    const principal = screen.getByRole("combobox", { name: "gpo_abuse.principal" });
    expect(principal.value).toBe("samwell.tarly");
    const users = optionValues(principal).filter((v) => v && v !== "__other__");
    expect(users.every((v) => !v.includes("\\"))).toBe(true);
    expect(users).not.toContain("tywin.lannister");
  });

  test("a key two vulns read shows once", () => {
    render(<Panel blueprint={LIGHT} id="winterfell" />);
    expect(screen.getAllByRole("combobox", { name: "bot_user" })).toHaveLength(1);
    expect(screen.getByText(/set under Responder-friendly posture above/)).toBeTruthy();
  });
});

describe("hosts and services", () => {
  test("a TERMSRV target is filled from a host pick and stays editable", () => {
    const seen = [];
    render(<Panel blueprint={LIGHT} id="winterfell" seen={seen} />);
    const host = screen.getByRole("combobox", { name: "stored_credential.target host" });
    expect(host.value).toBe("castelblack");
    fireEvent.change(host, { target: { value: "winterfell" } });
    expect(last(seen).stored_credential.target).toBe("TERMSRV/winterfell");
    const text = screen.getByRole("textbox", { name: "stored_credential.target" });
    fireEvent.change(text, { target: { value: "TERMSRV/winterfell.north.sevenkingdoms.local" } });
    expect(last(seen).stored_credential).toEqual({
      owner: "north\\robb.stark", username: "north\\robb.stark",
      target: "TERMSRV/winterfell.north.sevenkingdoms.local",
    });
  });

  test("the UNC targets are typed, since they must name a host that does not resolve", () => {
    render(<Panel blueprint={LIGHT} id="winterfell" />);
    expect(screen.getByRole("textbox", { name: "responder_target" }).value).toBe("\\\\Bravos\\private");
    expect(screen.queryByRole("combobox", { name: /responder_target/ })).toBeNull();
  });

  test("linked servers are checkboxes of the SQL hosts, cross domain", () => {
    const seen = [];
    render(<Panel blueprint={GOAD} id="castelblack" seen={seen} />);
    const braavos = screen.getByRole("checkbox", { name: "Link to braavos.essos.local" });
    expect(braavos.checked).toBe(true);
    const self = screen.getByRole("checkbox", { name: "Link to castelblack.north.sevenkingdoms.local" });
    expect(self.checked).toBe(false);
    fireEvent.click(braavos);
    expect(last(seen).mssql_linked_targets).toBeUndefined();
  });

  test("delegate_to is the SPN picker, one key among the others", () => {
    render(<Panel blueprint={LIGHT} id="castelblack" />);
    expect(screen.getByRole("checkbox", { name: "HTTP on winterfell" }).checked).toBe(true);
    expect(screen.getByRole("checkbox", { name: "CIFS on winterfell" }).checked).toBe(false);
    // The short-name SPN GOAD adds is not a service the picker offers.
    expect(screen.getByText("HTTP/winterfell")).toBeTruthy();
    expect(screen.queryByRole("checkbox", { name: /on castelblack/ })).toBeNull();
  });

  test("NTFS rights are a fixed list", () => {
    const seen = [];
    render(<Panel blueprint={LIGHT} id="castelblack" seen={seen} />);
    const rights = screen.getByRole("combobox", { name: "permissions.rights" });
    expect(rights.value).toBe("FullControl");
    expect(optionValues(rights)).not.toContain("__other__");
    fireEvent.change(rights, { target: { value: "Modify" } });
    expect(last(seen).permissions).toEqual({
      path: "C:\\inetpub\\wwwroot\\upload", user: "IIS_IUSRS", rights: "Modify",
    });
  });
});

describe("row editors", () => {
  test("EXECUTE AS rows list, add whole, and remove", () => {
    const seen = [];
    render(<Panel blueprint={GOAD} id="castelblack" seen={seen} />);
    expect(screen.getByText("NORTH\\samwell.tarly may impersonate sa")).toBeTruthy();
    const add = screen.getByRole("button", { name: "Add to mssql_execas_logins" });
    expect(add.disabled).toBe(true);
    expect(screen.getByRole("combobox", { name: "mssql_execas_logins new may impersonate" }).value).toBe("sa");
    fireEvent.change(screen.getByRole("combobox", { name: "mssql_execas_logins new login" }), {
      target: { value: "NORTH\\hodor" },
    });
    fireEvent.click(add);
    expect(last(seen).mssql_execas_logins.at(-1)).toEqual({ login: "NORTH\\hodor", target: "sa" });
    fireEvent.click(screen.getByRole("button", { name: "Remove mssql_execas_logins row 1" }));
    expect(last(seen).mssql_execas_logins.map((r) => r.login)).toEqual([
      "NORTH\\brandon.stark", "NORTH\\hodor",
    ]);
  });

  test("a linked login picks its target from the linked servers", () => {
    render(<Panel blueprint={GOAD} id="castelblack" />);
    const target = screen.getByRole("combobox", { name: "mssql_linked_logins new linked server" });
    expect(optionValues(target)).toContain("braavos.essos.local");
  });
});

describe("defaults on tick", () => {
  test("ticking MSSQL linked servers fills the other SQL hosts", () => {
    const seen = [];
    render(
      <Panel
        blueprint={GOAD}
        id="castelblack"
        seen={seen}
        edit={(doc) => {
          const ov = overlayOf(doc, "castelblack");
          ov.vulns = ov.vulns.filter((v) => v !== "mssql_linked");
          delete ov.vulns_vars.mssql_linked_targets;
          delete ov.vulns_vars.mssql_linked_logins;
        }}
      />
    );
    expect(screen.queryByRole("checkbox", { name: "Link to braavos.essos.local" })).toBeNull();
    fireEvent.click(screen.getByRole("checkbox", { name: "MSSQL linked servers" }));
    expect(last(seen).mssql_linked_targets).toEqual(["braavos.essos.local"]);
    expect(screen.getByRole("checkbox", { name: "Link to braavos.essos.local" }).checked).toBe(true);
  });

  test("ticking a stored credential fills only the target", () => {
    const seen = [];
    render(<Panel blueprint={LIGHT} id="castelblack" seen={seen} />);
    fireEvent.click(screen.getByRole("button", { name: "Credentials" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Stored credential (CredMan)" }));
    expect(last(seen).stored_credential).toEqual({ target: "TERMSRV/castelblack" });
    expect(screen.getByRole("combobox", { name: "stored_credential.owner" }).value).toBe("");
  });
});

describe("required keys and findings", () => {
  test("a required key says so and shows its RNG011 finding at its input", () => {
    const finding = {
      code: "RNG011", severity: "warning", target_ids: ["winterfell"],
      field: "vulns_vars.bot_user",
      message: "rdp_scheduler on winterfell has no vulns_vars.bot_user, so no logon bot is created.",
    };
    render(
      <Panel
        blueprint={LIGHT}
        id="winterfell"
        findings={[finding]}
        edit={(doc) => {
          delete overlayOf(doc, "winterfell").vulns_vars.bot_user;
        }}
      />
    );
    const field = screen.getByRole("combobox", { name: "bot_user" }).closest(".rg-vuln-key-field");
    expect(within(field).getByText("required")).toBeTruthy();
    expect(within(field).getByText(finding.message)).toBeTruthy();
    expect(within(json().closest(".rg-field")).queryByText(finding.message)).toBeNull();
  });

  test("an empty key with a fallback names what it falls back to", () => {
    render(
      <Panel
        blueprint={LIGHT}
        id="winterfell"
        edit={(doc) => {
          delete overlayOf(doc, "winterfell").vulns_vars.ntlm_relay_user;
        }}
      />
    );
    const relay = screen.getByRole("combobox", { name: "ntlm_relay_user" });
    expect(relay.value).toBe("");
    expect(within(relay).getByText("uses bot_user: north\\robb.stark")).toBeTruthy();
    expect(screen.getByText("required (or bot_user)")).toBeTruthy();
  });

  test("an ESC key set on another host in the domain says where", () => {
    render(
      <Panel
        blueprint={GOAD}
        id="braavos"
        edit={(doc) => {
          overlayOf(doc, "braavos").vulns.push("esc7");
        }}
      />
    );
    const manager = screen.getByRole("combobox", { name: "esc7_manager" });
    expect(manager.value).toBe("");
    expect(within(manager).getByText("set on meereen: ESSOS\\viserys.targaryen")).toBeTruthy();
  });
});

describe("read-only blueprints and accessibility", () => {
  test("a locked blueprint shows every value, disabled", () => {
    render(<Panel blueprint={GOAD} id="castelblack" readOnly />);
    const rights = screen.getByRole("combobox", { name: "permissions.rights" });
    expect(rights.disabled).toBe(true);
    expect(rights.value).toBe("FullControl");
    expect(screen.getByRole("checkbox", { name: "Link to braavos.essos.local" }).disabled).toBe(true);
    expect(screen.getByText("NORTH\\samwell.tarly may impersonate sa")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /^Add to / })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Remove / })).toBeNull();
    expect(json().disabled).toBe(true);
  });

  test("every control in the form has a name unique on the page", () => {
    for (const [blueprint, id] of [[LIGHT, "winterfell"], [GOAD, "castelblack"], [GOAD, "meereen"]]) {
      const { container, unmount } = render(<Panel blueprint={blueprint} id={id} />);
      const controls = [...container.querySelectorAll("input, select, textarea")];
      const names = controls.map((el) => computeAccessibleName(el));
      const form = [...container.querySelectorAll(".rg-vuln-form input, .rg-vuln-form select, .rg-vuln-form textarea")];
      expect(form.length).toBeGreaterThan(3);
      for (const el of form) {
        const name = computeAccessibleName(el);
        expect(name, el.outerHTML).toBeTruthy();
        expect(names.filter((n) => n === name), `${id}: ${name}`).toHaveLength(1);
      }
      unmount();
    }
  });
});
