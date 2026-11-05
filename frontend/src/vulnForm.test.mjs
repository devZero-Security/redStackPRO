import assert from "node:assert";
import { readFileSync } from "node:fs";
import { VULN_PARAMS } from "./vulns.js";
import { userSpnChoices } from "./spnChoices.js";
import {
  FS_RIGHTS, PICKS, ROW_KINDS, bareUserChoices, choicesFor, defaultLinkedTargets,
  domainUserChoices, formSections, getVar, groupChoices, keysOutsideForm, matchOption,
  netbiosOf, ouChoices, userOrGroupChoices, rowColumns, setElsewhere, setVar, sqlHostChoices,
  termsrvChoices, withVulnDefaults,
} from "./vulnForm.js";

const load = (path) => JSON.parse(readFileSync(path, "utf8"));
const BLUEPRINTS = {
  "goad-light": load("public/goad/goad-light.json"),
  goad: load("public/goad/goad.json"),
  nha: load("public/goad/nha.json"),
  harbor: load("public/harbor.json"),
};
const { "goad-light": light, goad, nha, harbor } = BLUEPRINTS;

let passed = 0;
const test = (name, fn) => { fn(); passed += 1; console.log("  ok", name); };

const values = (groups) => groups.flatMap((g) => g.options.map((o) => o.value));
const node = (doc, id) => doc.nodes.find((n) => n.id === id);

// The host with its shipped settings for one vuln taken out, as if newly placed.
function without(doc, id, vuln, keys) {
  const n = node(doc, id);
  let vars = n.overlay.vulns_vars;
  for (const k of keys) vars = setVar(vars, k, undefined);
  return { ...n, overlay: { ...n.overlay, vulns: n.overlay.vulns.filter((v) => v !== vuln), vulns_vars: vars } };
}
const tick = (doc, n, vuln) =>
  withVulnDefaults(doc, n, { ...n.overlay, vulns: [...(n.overlay.vulns || []), vuln] });

test("every pick and input on VULN_PARAMS is one the form knows", () => {
  const inputs = new Set(["number", "multiline", "lines", "files"]);
  for (const [id, params] of Object.entries(VULN_PARAMS)) {
    for (const p of params) {
      if (p.pick) assert.ok(PICKS[p.pick], `${id} ${p.key} pick ${p.pick}`);
      if (p.input) assert.ok(inputs.has(p.input), `${id} ${p.key} input ${p.input}`);
      assert.ok(!(p.pick && p.input), `${id} ${p.key} has both`);
    }
  }
});

test("domain users are DOMAIN\\user from every domain, the host's own first", () => {
  const groups = domainUserChoices(light, "winterfell");
  assert.deepStrictEqual(groups.map((g) => g.label), ["north.sevenkingdoms.local", "sevenkingdoms.local"]);
  for (const v of values(groups)) assert.match(v, /^(NORTH|SEVENKINGDOMS)\\[^\\]+$/);
  assert.ok(values(groups).includes("NORTH\\robb.stark"));
  assert.ok(values(groups).includes("SEVENKINGDOMS\\cersei.lannister"));
  // goad adds essos, still after the host's own domain.
  assert.deepStrictEqual(domainUserChoices(goad, "braavos").map((g) => g.label)[0], "essos.local");
});

test("the NetBIOS prefix follows the compiler's default when unset", () => {
  assert.strictEqual(netbiosOf({ overlay: { fqdn: "corp.example.local" } }), "CORP");
  assert.strictEqual(netbiosOf({ overlay: { fqdn: "averyveryverylongname.lab" } }), "AVERYVERYVERYLO");
  assert.strictEqual(netbiosOf({ overlay: { fqdn: "a.lab", netbios: "ACME" } }), "ACME");
  const doc = {
    nodes: [
      { id: "d", kind: "domain", overlay: { fqdn: "corp.example.local", users: [{ username: "j.doe" }] } },
      { id: "h", kind: "srv", overlay: {} },
    ],
    edges: [{ role: "joins", source: "h", target: "d" }],
  };
  assert.deepStrictEqual(values(domainUserChoices(doc, "h")), ["CORP\\j.doe"]);
});

test("bare users are the host's own domain, by name alone", () => {
  const v = values(bareUserChoices(light, "winterfell"));
  assert.ok(v.includes("samwell.tarly"));
  assert.ok(v.every((u) => !u.includes("\\")));
  assert.ok(!v.includes("cersei.lannister"), "another domain's user is not offered bare");
  const lone = { nodes: [{ id: "h", kind: "srv", overlay: {} }], edges: [] };
  assert.deepStrictEqual(bareUserChoices(lone, "h"), []);
});

test("groups are the domain's own, then the built-ins, by name", () => {
  const groups = groupChoices(goad, "meereen");
  assert.strictEqual(groups[0].label, "Groups on essos.local");
  assert.ok(values([groups[0]]).includes("DragonsFriends"));
  assert.strictEqual(groups.at(-1).label, "Built-in groups");
  assert.ok(values(groups).includes("Domain Users"));
  assert.ok(values(groups).every((g) => !g.includes("\\")));
});

test("an ESC5 principal is a user as DOMAIN\\user or a group by name", () => {
  const groups = userOrGroupChoices(goad, "meereen");
  assert.strictEqual(groups[0].label, "Users on essos.local");
  for (const v of values([groups[0]])) assert.match(v, /^ESSOS\\[^\\]+$/);
  assert.ok(matchOption(groups, "ESSOS\\khal.drogo"));
  assert.ok(matchOption(groups, "Domain Users"));
});

test("OUs are distinguished names under the domain root", () => {
  const v = values(ouChoices(goad, "kingslanding"));
  assert.ok(v.includes("OU=Crownlands,DC=sevenkingdoms,DC=local"));
  assert.deepStrictEqual(ouChoices(goad, "winterfell"), [], "north has no OUs");
});

test("SQL hosts are hostname.fqdn in any domain, the host itself last as a loopback", () => {
  const groups = sqlHostChoices(goad, "castelblack");
  assert.deepStrictEqual(groups.map((g) => g.label), ["north.sevenkingdoms.local", "essos.local"]);
  assert.deepStrictEqual(values(groups), ["castelblack.north.sevenkingdoms.local", "braavos.essos.local"]);
  assert.strictEqual(groups[0].options[0].label, "castelblack (this host)");
  // braavos runs SQL as a service on an adcs host; kingslanding runs none.
  assert.ok(!values(sqlHostChoices(goad, "braavos")).some((v) => v.startsWith("kingslanding")));
  // NHA links its SQL host to itself.
  assert.deepStrictEqual(values(sqlHostChoices(nha, "sql")), ["sql.academy.ninja.lan"]);
});

test("a TERMSRV target names the host's own domain by computer name, others by FQDN", () => {
  const groups = termsrvChoices(harbor, "fr-wks01");
  assert.strictEqual(groups[0].label, "freight.harbor.corp");
  assert.deepStrictEqual(values([groups[0]]).sort(), ["fr-app01", "fr-dc01", "fr-wks01"]);
  assert.ok(values(groups).includes("hq-dc01.harbor.corp"));
  assert.ok(groups[0].options.some((o) => o.label === "fr-wks01 (this host)"));
});

test("NTFS rights are the win_acl names, FullControl among them", () => {
  assert.ok(FS_RIGHTS.some((r) => r.value === "FullControl"));
  assert.ok(FS_RIGHTS.every((r) => /^[A-Z][A-Za-z]+$/.test(r.value)));
});

test("execas rows pick logins as DOMAIN\\user and start the target at sa", () => {
  const cols = rowColumns("execas_logins", goad, "castelblack", {});
  const [login, target] = cols;
  for (const v of values(login.choices)) assert.match(v, /\\/);
  assert.strictEqual(target.initial, "sa");
  assert.ok(matchOption(target.choices, "sa"));
  // A linked login's target is one of the host's linked servers.
  const linked = rowColumns("linked_logins", goad, "castelblack", node(goad, "castelblack").overlay.vulns_vars);
  assert.deepStrictEqual(values(linked[0].choices), ["braavos.essos.local"]);
  assert.deepStrictEqual(rowColumns("linked_logins", goad, "castelblack", {})[0].choices, []);
});

// Every value the shipped blueprints carry is one the form offers, so opening
// one shows it picked rather than typed. The two exceptions are deliberate.
test("the shipped blueprints' settings are among the choices offered", () => {
  const typedOnPurpose = new Set([
    "goad/meereen/esc13_group/greatmaster", // an empty group the ESC13 task creates
    "goad-light/castelblack/delegate_to/HTTP/winterfell", // a short-name SPN GOAD adds
    "goad/castelblack/delegate_to/HTTP/winterfell",
  ]);
  let checked = 0;
  for (const [name, doc] of Object.entries(BLUEPRINTS)) {
    for (const n of doc.nodes) {
      const vars = n.overlay?.vulns_vars;
      if (!vars) continue;
      for (const s of formSections(n.overlay.vulns)) {
        for (const p of s.params) {
          const value = getVar(vars, p.key);
          if (value == null || !p.pick) continue;
          const rows = ROW_KINDS.has(p.pick);
          const items = rows ? value : Array.isArray(value) ? value : [value];
          for (const item of items) {
            if (rows) {
              for (const col of rowColumns(p.pick, doc, n.id, vars)) {
                if (!col.choices?.length || item[col.field] == null) continue;
                assert.ok(matchOption(col.choices, item[col.field]), `${name} ${n.id} ${p.key} ${col.field} ${item[col.field]}`);
                checked += 1;
              }
              continue;
            }
            const probe = p.pick === "termsrv" ? item.replace(/^[^/]+\//, "") : item;
            const hit = matchOption(choicesFor(p.pick, doc, n.id), probe);
            if (typedOnPurpose.has(`${name}/${n.id}/${p.key}/${item}`)) {
              assert.ok(!hit, `${name} ${n.id} ${p.key} ${item} is now offered; drop the exception`);
            } else {
              assert.ok(hit, `${name} ${n.id} ${p.key} ${item}`);
            }
            checked += 1;
          }
        }
      }
    }
  }
  assert.ok(checked > 30, `checked ${checked}`);
});

test("ticking mssql_linked fills the other SQL hosts, once", () => {
  const bare = without(goad, "castelblack", "mssql_linked", ["mssql_linked_targets", "mssql_linked_logins"]);
  const ticked = tick(goad, bare, "mssql_linked");
  assert.deepStrictEqual(ticked.vulns_vars.mssql_linked_targets, ["braavos.essos.local"]);
  assert.deepStrictEqual(
    tick(goad, without(goad, "braavos", "mssql_linked", ["mssql_linked_targets"]), "mssql_linked")
      .vulns_vars.mssql_linked_targets,
    ["castelblack.north.sevenkingdoms.local"]
  );
  // A target already set is kept.
  const set = { ...bare, overlay: { ...bare.overlay, vulns_vars: setVar(bare.overlay.vulns_vars, "mssql_linked_targets", ["x.lab"]) } };
  assert.deepStrictEqual(tick(goad, set, "mssql_linked").vulns_vars.mssql_linked_targets, ["x.lab"]);
  // Ticked before: a cleared list is not refilled.
  const before = { ...bare, overlay: { ...bare.overlay, vulns: [...bare.overlay.vulns, "mssql_linked"] } };
  const cleared = withVulnDefaults(goad, before, { ...before.overlay, vulns_vars: undefined });
  assert.strictEqual(cleared.vulns_vars, undefined);
  // NHA's only SQL host has no other to link to, so nothing is filled.
  const sql = without(nha, "sql", "mssql_linked", ["mssql_linked_targets", "mssql_linked_logins"]);
  assert.strictEqual(getVar(tick(nha, sql, "mssql_linked").vulns_vars, "mssql_linked_targets"), undefined);
});

test("ticking stored_credential fills TERMSRV/<this host> and never a user", () => {
  const bare = without(harbor, "fr-wks01", "stored_credential", ["stored_credential"]);
  const ticked = tick(harbor, bare, "stored_credential");
  assert.deepStrictEqual(ticked.vulns_vars.stored_credential, { target: "TERMSRV/fr-wks01" });
  // The hostname wins over the node id, as the compiler names the computer.
  const named = { ...bare, overlay: { ...bare.overlay, hostname: "ws07" } };
  assert.strictEqual(getVar(tick(harbor, named, "stored_credential").vulns_vars, "stored_credential.target"), "TERMSRV/ws07");
});

test("the delegation default still applies, and malformed settings are left alone", () => {
  const bare = without(light, "castelblack", "constrained_delegation_kerberos", ["delegate_to"]);
  assert.deepStrictEqual(tick(light, bare, "constrained_delegation_kerberos").vulns_vars.delegate_to,
    ["CIFS/winterfell.north.sevenkingdoms.local"]);
  const broken = { ...bare, overlay: { ...bare.overlay, vulns_vars: "bot_user=x" } };
  assert.strictEqual(tick(light, broken, "mssql_linked").vulns_vars, "bot_user=x");
});

test("a nested key is set on its dots and an emptied parent is dropped", () => {
  let vars = setVar(undefined, "gpo_abuse.principal", "samwell.tarly");
  assert.deepStrictEqual(vars, { gpo_abuse: { principal: "samwell.tarly" } });
  vars = setVar(vars, "bot_user", "NORTH\\robb.stark");
  vars = setVar(vars, "gpo_abuse.principal", undefined);
  assert.deepStrictEqual(vars, { bot_user: "NORTH\\robb.stark" });
  assert.strictEqual(setVar(vars, "bot_user", ""), undefined);
  assert.strictEqual(setVar({ directory: ["C:\\x"] }, "directory", []), undefined);
  assert.strictEqual(getVar({ gpo_abuse: "oops" }, "gpo_abuse.principal"), undefined);
});

test("a key two ticked vulns read shows once, under the first in the catalog", () => {
  const sections = formSections(["rdp_scheduler", "responder", "smbv1"]);
  assert.deepStrictEqual(sections.map((s) => s.vuln), ["responder", "rdp_scheduler"]);
  assert.deepStrictEqual(sections[0].params.map((p) => p.key), ["bot_user", "responder_target"]);
  assert.deepStrictEqual(sections[1].params.map((p) => p.key), ["bot_interval_minutes"]);
  assert.deepStrictEqual(sections[1].shared, [{ key: "bot_user", under: "Share-browsing bot (Responder)" }]);
});

test("keys the form does not show are named, so the JSON view can say so", () => {
  const n = node(goad, "castelblack");
  assert.deepStrictEqual(keysOutsideForm(n.overlay.vulns, n.overlay.vulns_vars), ["mssql_sysadmins"]);
});

test("an ESC key set on another host in the domain is found", () => {
  assert.deepStrictEqual(setElsewhere(goad, "braavos", "esc7_manager"),
    { host: "meereen", value: "ESSOS\\viserys.targaryen" });
  assert.strictEqual(setElsewhere(goad, "meereen", "esc7_manager"), null);
  assert.strictEqual(setElsewhere(goad, "braavos", "bot_user"), null, "only the domain-wide keys");
});

test("user SPN suggestions are SQL and IIS service SPNs only", () => {
  const spns = userSpnChoices(light, "north").map((c) => c.spn);
  assert.deepStrictEqual(spns, [
    "MSSQLSvc/castelblack.north.sevenkingdoms.local:1433",
    "HTTP/castelblack.north.sevenkingdoms.local",
  ]);
  for (const doc of Object.values(BLUEPRINTS)) {
    for (const d of doc.nodes.filter((n) => n.kind === "domain")) {
      for (const { spn } of userSpnChoices(doc, d.id)) {
        assert.match(spn, /^(MSSQLSvc\/[^/]+:1433|HTTP\/[^/]+)$/);
      }
    }
  }
  assert.deepStrictEqual(userSpnChoices(light, "sevenkingdoms"), [], "no SQL or IIS there");
  assert.deepStrictEqual(userSpnChoices(nha, "academy").map((c) => c.spn), [
    "HTTP/web.academy.ninja.lan", "MSSQLSvc/sql.academy.ninja.lan:1433",
  ]);
});

console.log(`vulnForm: ${passed} passed`);
