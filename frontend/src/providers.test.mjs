import assert from "node:assert/strict";
import {
  hostsRange,
  isProven,
  labelFor,
  providersFor,
  resolveProvider,
  selectableProviders,
  sortProviders,
} from "./providers.js";

// The registry payload, shaped as /registry/providers returns it. esxi and
// proxmox declare no public_address; all five declare a Windows image, which is
// what makes them native range targets.
const REGISTRY = [
  { name: "aws", maturity: "proven", capabilities: ["compute", "public_address", "windows_image"] },
  { name: "azure", maturity: "preview", capabilities: ["compute", "public_address", "windows_image"] },
  { name: "esxi", maturity: "preview", capabilities: ["compute", "windows_image"] },
  { name: "gcp", maturity: "proven", capabilities: ["compute", "public_address", "windows_image"] },
  { name: "proxmox", maturity: "preview", capabilities: ["compute", "windows_image"] },
];

// Vendor spelling. The three abbreviations shout, the two product names do not.
assert.equal(labelFor("aws"), "AWS");
assert.equal(labelFor("gcp"), "GCP");
assert.equal(labelFor("azure"), "Azure");
assert.equal(labelFor("proxmox"), "Proxmox");
assert.equal(labelFor("esxi"), "ESXi");

// A provider the registry grows that nobody has labelled still names itself,
// rather than rendering as an empty row.
assert.equal(labelFor("openstack"), "openstack");

// THE BUG THIS MODULE EXISTS FOR: the toolbar hardcoded four range providers and
// left esxi out, though the compiler has accepted it since the native range
// landed. Derived from the capability, esxi is offered.
assert.ok(providersFor("haven", REGISTRY).includes("esxi"));
assert.equal(providersFor("haven", REGISTRY).length, 5);

// A provider with no Windows image cannot build a defense range, and is offered
// for offense only.
const noWindows = [...REGISTRY, { name: "toy", capabilities: ["compute"] }];
assert.equal(hostsRange({ name: "toy", capabilities: ["compute"] }), false);
assert.ok(!providersFor("haven", noWindows).includes("toy"));
assert.ok(providersFor("artie", noWindows).includes("toy"));

// Familiarity first, and an unranked provider sorts last rather than vanishing.
assert.deepEqual(sortProviders(["esxi", "aws", "gcp"]), ["gcp", "aws", "esxi"]);
assert.deepEqual(
  sortProviders(["openstack", "gcp"]),
  ["gcp", "openstack"]
);

// A chosen provider this mode can build is left alone.
assert.equal(resolveProvider("haven", REGISTRY, "proxmox"), "proxmox");

// One it cannot lands on something real. The toolbar used to correct only what it
// drew, leaving the state pointed at a target the API would refuse, so the canvas
// showed one provider and compiled for another.
assert.equal(resolveProvider("haven", noWindows, "toy"), "gcp");

// With no registry loaded yet, the chosen provider survives rather than being
// reset to nothing on the first render.
assert.equal(resolveProvider("artie", [], "gcp"), "gcp");

// Only GCP and AWS have had a range deployed on them, so only those two are
// choosable. The other three still LIST -- the compiler genuinely builds them,
// and hiding that would understate the product.
assert.deepEqual(selectableProviders("artie", REGISTRY), ["gcp", "aws"]);
assert.deepEqual(selectableProviders("haven", REGISTRY), ["gcp", "aws"]);
assert.equal(providersFor("artie", REGISTRY).length, 5);

// Declaring nothing means preview. Claiming proven by omission is the wrong way
// round: a backend added tomorrow should not present itself as deployment-proven
// because someone forgot a line.
assert.equal(isProven({ name: "openstack", capabilities: [] }), false);
assert.ok(!selectableProviders("artie", noWindows).includes("toy"));

// A mode switch lands on a proven target, never a greyed one.
assert.equal(resolveProvider("haven", noWindows, "toy"), "gcp");

// But a provider someone deliberately chose and saved is left alone. Greying is
// about where the canvas steers people, not about overriding their choice.
assert.equal(resolveProvider("artie", REGISTRY, "azure"), "azure");

console.log("providers ok");
