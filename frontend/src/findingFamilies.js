// A finding's code is the stable machine-readable surface (0014), but it is not
// a good thing to read first. "CAR006" tells a person nothing; "Cardinality"
// tells them which kind of question the validator is asking, and the message
// right next to it tells them the answer. So the canvas shows the family in
// words and keeps the code one hover away, which 0014 explicitly allows: the
// wire contract fixes the code, not how it is rendered.
//
// One entry per family in docs/validation.md. The blurb is the family's own
// section, compressed to a sentence a stakeholder can read out loud.

export const FAMILIES = {
  NAM: {
    label: "Naming",
    blurb: "How a node id is formed, and whether the name it composes to fits.",
  },
  REF: {
    label: "References",
    blurb: "Whether every edge points at a node that exists, and ids are unique.",
  },
  END: {
    label: "Edge endpoints",
    blurb: "Whether an edge joins the kinds of node that edge is allowed to join.",
  },
  NET: {
    label: "Cross-provider",
    blurb: "An edge spanning two providers, which the compiler cannot transport.",
  },
  CAR: {
    label: "Cardinality",
    blurb: "How many of an edge kind a node may have.",
  },
  FRT: {
    label: "Fronting",
    blurb: "Whether redirectors agree on the URIs and prefixes they front.",
  },
  MGT: {
    label: "Management path",
    blurb: "Whether every host the compiler configures can be reached to configure it.",
  },
  RDR: {
    label: "Redirector",
    blurb: "Whether a redirector has a real hostname it can answer on.",
  },
  CAP: {
    label: "Provider support",
    blurb: "Whether the selected provider can do what a node is asking for.",
  },
  EXP: {
    label: "Exposure",
    blurb: "Which hosts hold a public address, and which must not.",
  },
  LOG: {
    label: "Collector",
    blurb: "Whether log shipping has a route and a protected channel.",
  },
  ORD: {
    label: "Ordering",
    blurb: "Whether provisioning order resolves, or the topology has a cycle.",
  },
  RNG: {
    label: "Range model",
    blurb: "Whether domains, controllers and members form a coherent AD range.",
  },
};

// Codes are three letters then three digits. Anything else is a code from a
// newer validator than this build of the canvas, and the honest thing to show
// is the code itself rather than a guess or a blank.
const CODE = /^([A-Z]{3})(\d{3})$/;

export function familyFor(code) {
  const match = CODE.exec(String(code || ""));
  const known = match ? FAMILIES[match[1]] : null;
  if (!known) {
    return { label: String(code || ""), blurb: "", known: false };
  }
  return { ...known, known: true };
}

// What the hover says: the code it stands for, the family, and what that family
// checks. Severity is already carried by the border colour and the message, so
// it is not repeated here.
export function familyTooltip(code) {
  const family = familyFor(code);
  if (!family.known) return String(code || "");
  return `${code} - ${family.label}. ${family.blurb}`;
}
