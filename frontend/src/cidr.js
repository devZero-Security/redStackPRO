// Default address allocation. A new network takes the next free /16 (10.10, then
// 10.20, ...), a new subnet the next free /24 inside its network (x.y.0, x.y.1,
// ...). Both skip anything already in use, so two networks never collide and a
// peering never has to fight overlapping ranges. The person can still type an
// exact range in the inspector; this only fills the seed. See 0016.

function parse(text) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(text || "");
  if (!m) return null;
  const octets = [+m[1], +m[2], +m[3], +m[4]];
  const prefix = +m[5];
  if (octets.some((o) => o > 255) || prefix > 32) return null;
  return { octets, prefix };
}

function toInt(octets) {
  return (octets[0] * 2 ** 24 + octets[1] * 2 ** 16 + octets[2] * 2 ** 8 + octets[3]);
}

function range(c) {
  const size = 2 ** (32 - c.prefix);
  const base = toInt(c.octets);
  const start = base - (base % size);
  return [start, start + size - 1];
}

function overlaps(a, b) {
  const [as, ae] = range(a);
  const [bs, be] = range(b);
  return as <= be && bs <= ae;
}

function existing(document) {
  return document.nodes
    .map((n) => parse(n.overlay?.cidr))
    .filter(Boolean);
}

function intToOctets(n) {
  return [
    Math.floor(n / 2 ** 24) % 256,
    Math.floor(n / 2 ** 16) % 256,
    Math.floor(n / 2 ** 8) % 256,
    n % 256,
  ];
}

// The next free /16 carved from the topology's base_cidr (default 10.0.0.0/8). The
// first pass steps by 10 for readable spacing (10.10, 10.20, ...); a dense
// second pass fills in if those run out. An operator setting base_cidr moves the
// whole deployment into their own block. See 0046.
export function allocNetworkCidr(document) {
  const base = parse(document?.base_cidr) || { octets: [10, 0, 0, 0], prefix: 8 };
  const [start] = range(base);
  const blocks = base.prefix <= 16 ? 2 ** (16 - base.prefix) : 1;
  const taken = existing(document);
  const cand = (i) => {
    const [a, b] = intToOctets(start + i * 2 ** 16);
    return { octets: [a, b, 0, 0], prefix: 16 };
  };
  const fmt = (i) => {
    const [a, b] = cand(i).octets;
    return `${a}.${b}.0.0/16`;
  };
  const free = (i) => i < blocks && !taken.some((c) => overlaps(c, cand(i)));
  for (let i = 10; i < blocks; i += 10) if (free(i)) return fmt(i);
  for (let i = 0; i < blocks; i += 1) if (free(i)) return fmt(i);
  return fmt(0);
}

export function allocSegmentCidr(document, parentNetworkId) {
  const parent = document.nodes.find((n) => n.id === parentNetworkId);
  const pc = parse(parent?.overlay?.cidr);
  const [a, b] = pc ? [pc.octets[0], pc.octets[1]] : [10, 10];
  // Only other subnets constrain a subnet. The containing network's own range
  // covers every /24 inside it, so scanning it would leave nothing free.
  const taken = document.nodes
    .filter((n) => n.kind === "segment")
    .map((n) => parse(n.overlay?.cidr))
    .filter(Boolean);
  const free = (t) => !taken.some((c) => overlaps(c, { octets: [a, b, t, 0], prefix: 24 }));
  for (let t = 0; t <= 255; t += 1) if (free(t)) return `${a}.${b}.${t}.0/24`;
  return `${a}.${b}.0.0/24`;
}

// Whether a child range sits entirely inside a parent range. A subnet dropped
// into a network keeps a hand chosen range that already fits, and is reallocated
// only when its old range belongs to a different network.
export function cidrWithin(childCidr, parentCidr) {
  const c = parse(childCidr);
  const p = parse(parentCidr);
  if (!c || !p) return false;
  const [cs, ce] = range(c);
  const [ps, pe] = range(p);
  return ps <= cs && ce <= pe;
}
