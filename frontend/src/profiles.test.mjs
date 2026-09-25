import assert from "node:assert/strict";
import { PROFILES, coverFor, profileFor, uriFor, token } from "./profiles.js";

// A deterministic rng so the picks are reproducible: cycles through a fixed list
// of fractions.
function seeded(values) {
  let i = 0;
  return () => values[i++ % values.length];
}

// Every profile's decoy is one of the schema enum values, and its pools respect
// the schema patterns, so applying a profile can never write an invalid overlay.
{
  const decoys = new Set([
    "cdn", "maintenance", "webserver", "healthcare", "finance", "education",
    "news", "ecommerce", "food", "it", "sports", "travel", "none",
  ]);
  const hostRe = /^[a-z0-9.-]+$/;
  const uriRe = /^\/[a-z0-9][a-z0-9/_-]*$/;
  const headerRe = /^[A-Za-z][A-Za-z0-9-]*$/;
  for (const p of PROFILES) {
    assert.ok(decoys.has(p.decoy), `${p.key} decoy ${p.decoy} not in enum`);
    for (const s of p.subdomains) assert.match(s, hostRe, `${p.key} subdomain ${s}`);
    // A theme carries no root domain at all. One that did would be a plausible
    // name nobody owns, which passes RDR001 and deploys a redirector answering
    // to somebody else's domain.
    assert.equal(p.domains, undefined, `${p.key} must not carry root domains`);
    for (const u of p.prefixes) assert.match(u, uriRe, `${p.key} prefix ${u}`);
    for (const h of p.headers) assert.match(h, headerRe, `${p.key} header ${h}`);
  }
}

// coverFor fills a header and the theme's decoy. The token is fresh and
// lowercase alphanumeric. With no domain of the operator's there is no honest
// hostname to offer, so it returns none and the caller leaves the field alone.
{
  const cover = coverFor("healthcare", seeded([0, 0, 0]));
  assert.equal(cover.decoy, "healthcare");
  assert.equal(cover.hostname, undefined, "invented no root domain");
  assert.match(cover.header_name, /^[A-Za-z][A-Za-z0-9-]*$/);
  assert.match(cover.header_value, /^[a-z0-9]{24}$/);
}

// Given the operator's own domains, the hostname is a themed subdomain on one of
// them, so the cover always sits on a name they control.
{
  const cover = coverFor("cdn", seeded([0, 0, 0]), ["mydomain.com", "second.net"]);
  const [sub, ...rest] = cover.hostname.split(".");
  const domain = rest.join(".");
  assert.ok(["mydomain.com", "second.net"].includes(domain), `used ${domain}`);
  assert.ok(profileFor("cdn").subdomains.includes(sub), `themed subdomain ${sub}`);
}

// Every theme's subdomain suggestion lands on the operator's domain, whichever
// theme they pick. This is the whole contract now that the root is theirs.
for (const p of PROFILES) {
  const cover = coverFor(p.key, seeded([0, 0, 0]), ["owned.example"]);
  assert.ok(cover.hostname.endsWith(".owned.example"), `${p.key} left the domain`);
}

// uriFor never repeats a taken prefix, so two upstreams on one redirector cannot
// collide.
{
  const taken = [];
  for (let i = 0; i < 5; i += 1) {
    const uri = uriFor("cdn", taken);
    assert.ok(!taken.includes(uri), `repeated ${uri}`);
    assert.match(uri, /^\/[a-z0-9][a-z0-9/_-]*$/);
    taken.push(uri);
  }
  // Exhaust the pool and one more still comes back unique, with a suffix.
  const extra = uriFor("cdn", taken);
  assert.ok(!taken.includes(extra));
  assert.match(extra, /^\/[a-z0-9][a-z0-9/_-]*$/);
}

// An unknown key falls back to the first profile rather than throwing.
assert.equal(profileFor("nope"), PROFILES[0]);

// token respects its length.
assert.equal(token(8, seeded([0])).length, 8);

console.log("profiles.test.mjs: all passed");
