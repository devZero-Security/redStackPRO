// The deploy targets the toolbar offers.
//
// This used to be two lists that could disagree, and did: the offense list came
// from the registry over /registry/providers, while the range list was a literal
// ["aws", "gcp", "azure", "proxmox"] written in the toolbar. The compiler's own
// RANGE_PROVIDERS has named five since the native range landed, so esxi was a
// supported target the canvas would not let anyone pick. Same shape as the
// goad-wazuh template that shipped without a line in the picker: the code could
// do it, nothing offered it.
//
// So there is one source now, and it is the registry. A provider hosts a native
// range iff it declares windows_image, which is the criterion export.py states in
// prose -- "every native backend knows the Windows host kinds" -- rather than a
// second list to keep in step. Add a provider to the registry with a Windows
// image and both canvases offer it without anyone editing this file.

// Vendor spelling, not a uniform shout: AWS, GCP and Azure are abbreviations and
// take capitals, while Proxmox and ESXi are product names and take the spelling
// their vendors use. Anyone who knows the tools reads the difference as care.
const LABELS = {
  aws: "AWS",
  gcp: "GCP",
  azure: "Azure",
  proxmox: "Proxmox",
  esxi: "ESXi",
};

// Familiarity first, and GCP leads because it is the one the initial customer
// runs. A provider we have no label for falls back to its registry name, so the
// chooser lists it rather than hiding it.
const ORDER = ["gcp", "aws", "azure", "proxmox", "esxi"];

export function labelFor(name) {
  return LABELS[name] || name;
}

function rank(name) {
  const index = ORDER.indexOf(name);
  return index === -1 ? ORDER.length : index;
}

export function sortProviders(names) {
  return [...names].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

// A defense range is built from Windows host kinds, so a provider that declares
// no Windows image cannot compile one. See export.py's RANGE_PROVIDERS, which
// test_providers.py pins to this same capability so the two cannot drift again.
export function hostsRange(provider) {
  return (provider.capabilities || []).includes("windows_image");
}

// Deployment-proven, or a backend that compiles but has not been put through a
// real range end to end. Preview targets are greyed in the chooser rather than
// hidden, because the compiler genuinely does build them -- hiding would
// understate the product, and listing them as equals oversells them. A provider
// that declares nothing counts as preview: claiming proven by omission is the
// wrong way round.
export function isProven(provider) {
  return provider.maturity === "proven";
}

// The targets to offer for a document in this mode. `providers` is the registry
// payload: [{name, capabilities, unsupported, maturity}]. Preview targets are
// included -- greying is the picker's job, not this function's.
export function providersFor(mode, providers) {
  const usable = mode === "range" ? providers.filter(hostsRange) : providers;
  return sortProviders(usable.map((p) => p.name));
}

// The subset a person may actually choose.
export function selectableProviders(mode, providers) {
  const proven = new Set(providers.filter(isProven).map((p) => p.name));
  return providersFor(mode, providers).filter((n) => proven.has(n));
}

// Keep a chosen provider one this mode can build AND one that is proven, so
// switching a document to Defense while pointed at a provider with no Windows
// image lands on something real rather than compiling against a target the API
// will refuse. A provider already chosen is left alone even if it is preview:
// greying is about where the canvas STEERS people, not about overriding a
// deliberate choice someone already made and saved.
export function resolveProvider(mode, providers, chosen) {
  const offered = providersFor(mode, providers);
  if (offered.includes(chosen)) return chosen;
  return selectableProviders(mode, providers)[0] || offered[0] || chosen;
}
