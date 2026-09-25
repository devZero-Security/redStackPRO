// Cover profiles: believable-but-fictional personas a redirector can wear. Each
// theme is a pool of subdomains, URI prefixes, and gating header names that read
// like the vertical it names, plus the decoy page the compiler serves for it.
// Applying a profile fills a redirector's hostname, gating header, and decoy and
// re-rolls its fronts URIs from these pools, so two redirectors in one range do
// not share a fingerprint. The list lives here, the way the palette comes from
// the registry: adding a theme is data. Everything is invented; no pool names a
// real organisation, brand, or domain. See 0041.
//
// A theme supplies the SUBDOMAIN only. The root is always a domain the operator
// registered and typed in, never one of ours and never a plausible invention:
// these pools used to carry fictional root domains too, and a cover built on one
// passed validation and deployed a redirector answering to a name nobody owned,
// which is the failure RDR001 exists to prevent arriving by a different door. The
// subdomain it picks is a suggestion and stays editable; the hostname field is an
// ordinary text field and changing it afterwards is expected.
//
// The pools respect the schema patterns: hostnames and URI prefixes are
// lowercase, a URI prefix begins with a slash then a word character, and a header
// name starts with a letter. The `decoy` of each theme is one of the schema enum
// values, so a profile maps straight onto gating.decoy.

export const PROFILES = [
  {
    key: "cdn",
    label: "CDN",
    decoy: "cdn",
    subdomains: ["cdn", "static", "assets", "edge", "media", "cache"],
    prefixes: ["/cdn/assets", "/static/js", "/media/img", "/v2/edge", "/cache/content", "/dist/app"],
    headers: ["X-Edge-Token", "X-CDN-Auth", "X-Cache-Key", "X-Asset-Sig"],
  },
  {
    key: "maintenance",
    label: "Maintenance page",
    decoy: "maintenance",
    subdomains: ["status", "app", "portal", "my", "service"],
    prefixes: ["/status", "/health", "/maintenance", "/api/ping", "/system/check"],
    headers: ["X-Status-Token", "X-Health-Key", "X-Service-Auth"],
  },
  {
    key: "webserver",
    label: "Web server",
    decoy: "webserver",
    subdomains: ["www", "web", "site", "host", "srv"],
    prefixes: ["/index", "/home", "/about", "/assets/css", "/app/main"],
    headers: ["X-Request-Id", "X-Web-Token", "X-Session-Ref"],
  },
  {
    key: "healthcare",
    label: "Healthcare portal",
    decoy: "healthcare",
    subdomains: ["portal", "patient", "mychart", "care", "health"],
    prefixes: ["/patient/portal", "/records/view", "/appointments", "/api/hl7", "/care/messages"],
    headers: ["X-Patient-Token", "X-Portal-Auth", "X-Care-Session"],
  },
  {
    key: "finance",
    label: "Finance / banking",
    decoy: "finance",
    subdomains: ["secure", "online", "banking", "my", "portal"],
    prefixes: ["/api/v2/accounts", "/online/banking", "/secure/login", "/transfers", "/statements"],
    headers: ["X-Auth-Token", "X-Session-Id", "X-Txn-Sig"],
  },
  {
    key: "education",
    label: "Education",
    decoy: "education",
    subdomains: ["portal", "my", "learn", "students", "campus"],
    prefixes: ["/portal/login", "/courses", "/lms/api", "/students/records", "/campus/services"],
    headers: ["X-Student-Token", "X-Portal-Auth", "X-Campus-Session"],
  },
  {
    key: "news",
    label: "News",
    decoy: "news",
    subdomains: ["www", "news", "read", "live", "stories"],
    prefixes: ["/latest", "/api/articles", "/live/feed", "/section/world", "/read/story"],
    headers: ["X-Read-Token", "X-Feed-Key", "X-Article-Ref"],
  },
  {
    key: "ecommerce",
    label: "E-commerce",
    decoy: "ecommerce",
    subdomains: ["shop", "store", "www", "cart", "checkout"],
    prefixes: ["/shop/catalog", "/cart/api", "/checkout", "/account/orders", "/products/list"],
    headers: ["X-Cart-Token", "X-Shop-Session", "X-Order-Key"],
  },
  {
    key: "food",
    label: "Food & recipes",
    decoy: "food",
    subdomains: ["www", "recipes", "kitchen", "cook", "eat"],
    prefixes: ["/recipes", "/api/dishes", "/kitchen/tips", "/collections", "/cook/steps"],
    headers: ["X-Recipe-Token", "X-Kitchen-Key", "X-Menu-Ref"],
  },
  {
    key: "it",
    label: "IT / cloud",
    decoy: "it",
    subdomains: ["app", "api", "dashboard", "cloud", "console"],
    prefixes: ["/api/v3", "/dashboard", "/console/logs", "/deploy/status", "/metrics"],
    headers: ["X-Api-Key", "X-Deploy-Token", "X-Console-Session"],
  },
  {
    key: "sports",
    label: "Sports",
    decoy: "sports",
    subdomains: ["www", "scores", "live", "stats", "fans"],
    prefixes: ["/scores/live", "/api/stats", "/standings", "/highlights", "/teams"],
    headers: ["X-Score-Token", "X-Stats-Key", "X-Match-Ref"],
  },
  {
    key: "travel",
    label: "Travel",
    decoy: "travel",
    subdomains: ["www", "book", "trips", "go", "explore"],
    prefixes: ["/destinations", "/api/bookings", "/trips/plan", "/deals", "/explore/guides"],
    headers: ["X-Trip-Token", "X-Booking-Key", "X-Travel-Session"],
  },
];

export function profileFor(key) {
  return PROFILES.find((p) => p.key === key) || PROFILES[0];
}

// Deterministic when handed a seeded rng, which is what the tests do; the app
// leaves it defaulting to Math.random.
export function pick(list, rng = Math.random) {
  return list[Math.floor(rng() * list.length)];
}

// A lowercase alphanumeric token, so it satisfies both the header value (free
// text) and, as a suffix, the URI prefix pattern.
export function token(length = 16, rng = Math.random) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < length; i += 1) out += alphabet[Math.floor(rng() * alphabet.length)];
  return out;
}

// The redirector-level values a profile fills: a hostname, a gating header, and
// the decoy page. The header value is a fresh random token, never a real one.
//
// The hostname is a themed subdomain on one of the operator's own registered
// domains. With no domain to build on there is no honest hostname to offer, so
// none is returned and the caller leaves whatever is there alone: an empty
// hostname is caught by RDR001 before anything is built, which is the right place
// to stop. The rest of the cover still applies, since a header and a decoy are
// useful whether or not the domain is settled yet.
export function coverFor(key, rng = Math.random, domains) {
  const profile = profileFor(key);
  const cover = {
    header_name: pick(profile.headers, rng),
    header_value: token(24, rng),
    decoy: profile.decoy,
  };
  if (domains && domains.length) {
    cover.hostname = `${pick(profile.subdomains, rng)}.${pick(domains, rng)}`;
  }
  return cover;
}

// A URI prefix for a fronts edge in this theme, avoiding any already taken from
// the same redirector so two upstreams never collide (which the compiler rejects
// as FRT002). When the pool is exhausted it falls back to a themed prefix with a
// short random suffix.
export function uriFor(key, taken = [], rng = Math.random) {
  const profile = profileFor(key);
  const free = profile.prefixes.filter((p) => !taken.includes(p));
  if (free.length) return pick(free, rng);
  return `${pick(profile.prefixes, rng)}/${token(4, rng)}`;
}
