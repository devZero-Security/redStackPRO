# Topology schema

Status: written. Version 0.4.0 covers `ops` mode. 0.1.0, 0.2.0, and 0.3.0 and
their examples stay in the repo as migration fixtures.

The schema is the artifact, not this file.

- `src/redstackpro/schema/topology/0.4.0.json` is the document schema
- `src/redstackpro/schema/topology/examples/0.4.0/` holds four worked examples that
  double as test fixtures
- `docs/validation.md` holds the rules JSON Schema cannot express
- Decision 0007 is why the model is shaped the way it is, 0021 is why exposure is
  a per-host ceiling rather than a segment property, and 0029 is the `peers` role

## Shape in one paragraph

One node collection and one edge collection. The ops node kinds are `network`,
`segment`, `redirector`, `teamserver`, `collector`, `jumpbox`, and `operator`;
range mode (`mode: range`) adds `domain`, `dc`, `srv`, `wks`, `fw`, `siem`, and
`appliance` (see the range model below). Segments and networks are nodes, so
every edge endpoint is a bare node id. Edges carry a `role` of `attached`,
`fronts`, `logs_to`, `manages`, `peers`, and, in range mode, `joins` (host to
domain) and `trusts` (domain to domain), with role-specific fields via a
`oneOf`. Overlays are per-node parameters; user-supplied fields carry an
`x-redstackpro-source` annotation and derived fields do not appear in the document
at all.

## Two artifacts, not one

Documents hold user-supplied values. Derived overlay fields and per-kind
requirements are not in the document, because the compiler computes the first and
declares the second per kind rather than per instance. Both live in the registry
at `src/redstackpro/schema/registry/`. See 0013.

- `kinds/<kind>.yaml`, one per node kind. Category, ansible group, derived
  fields, and requirements. Requirements may carry a `when` clause, which is
  equality on a single overlay field and deliberately not an expression language
- `providers/<provider>.yaml`, capabilities offered, and an `unsupported` list
  carrying the prose a capability failure reports
- `roles.yaml`, the closed set of seven edge roles, each declaring legal endpoint
  kinds, whether it requires reachability, and what it injects into which endpoint

`python -m redstackpro.tools.registry` loads it and runs the capability check. It exits if the
registry and this schema version disagree on kinds or roles, which is the drift
guard between two files that would otherwise diverge.

## Worked examples

- `minimal.json`, one redirector fronting one teamserver through a jumpbox
- `redstack.json`, the shape of the current redStack topology: one redirector in
  its own network peered to the main range, fronting three teamservers on separate
  prefixes, with a collector in its own tier. Kept to a single redirector because
  that is the familiar redStack shape; the rollover pool of a second redirector is
  exercised by the `rollover` test fixture rather than shipped here. Verify against
  real redStack before this ships as the default blueprint
- `parallel-chains.json`, two independent chains in separate routing domains with
  one management network reaching both. Substituted for the GOAD example, which
  moves to the range pass
- `peered.json`, two networks joined by a `peers` edge so a jumpbox in one manages
  hosts in the other across the peered boundary

## Range model

Range mode (`mode: range`, ADR 0047) is the Cyber Ranges canvas. A `domain` is a
container node the way a segment is; a host joins it with a `joins` edge and
nests inside its box. Domains link to each other with a `trusts` edge carrying
`direction`, `trust_type` (`parent_child`, `tree_root`, `external`, `forest`),
and `transitive`; a two-way trust is one bidirectional edge, not two.

The range host kinds `dc`, `srv`, `wks`, and `fw` share one overlay,
`overlay_range_host`. Its user fields:

- `os` and `hostname`, the image and canonical name (`windows_server_2019`,
  `kingslanding`)
- `role`, a server's primary function (`sql`, `web`, `fileshare`, `adcs`,
  `generic`), which drives its badge and, later, its provisioning
- `services`, free-form roles the host runs (`mssql`, `iis`, `adcs`)
- `edr`, the endpoint detection running on it (`defender`, `elastic`, `wazuh`,
  and the commercial labels), for evasion practice
- `vulns`, planted attack-path misconfigurations and CVEs from the GOAD-derived
  catalog in `frontend/src/vulns.js`, kept as free strings so the catalog grows
  without a schema change
- `hardening`, defensive controls (`asr`, `runasppl`, `constrained_powershell`,
  and peers) for practising against a locked-down endpoint rather than a weak
  one, as on the GOAD ws01 extension
- `notes`, free-form provenance, e.g. an imported role an importer could not map

A `siem` box carries `overlay_siem` (`product` of `wazuh`, `elk`, or `splunk`,
plus `os`/`hostname`/`notes`); an `appliance` reuses `overlay_range_host`. Both
sit on a subnet rather than joining a domain. Range semantics are checked by the
`RNG` rules in `validation.md`.

## Still open

**Instantiation parameters.** Per-operator templates mean the same topology spun up N
times without CIDR, hostname, or domain collisions. A topology-level variables block.
Not in 0.4.0. See 0012.

## Roadmap

Anticipated, not decided. None of these is an ADR yet.

- `peers` landed in 0.4.0: a network to network role for same-cloud links that do
  not warrant an endpoint host, which relaxes the cross-network management,
  logging, and fronting rules across the peered boundary (0029, 0030). Both cloud
  backends render it as VPC peering with CIDR based cross-network firewall rules:
  gcp in 0030, aws in 0031. Proxmox cannot peer and refuses through `CAP004`. Both
  the `peered` example and the seeded redStack blueprint now run two networks, with
  redStack isolating its redirector in a network of its own peered to the main
  range
- `tunnel` as a standalone role if range mode produces a pivot host case where
  the transport is the entire relationship
- Mixed-provider compilation, reading the optional `provider` field on networks.
  The field exists in the schema but nothing reads it yet, so it is a seam for a
  future hybrid export rather than a capability that ships today

## Fixed constraints

- No provider vocabulary at this layer. `exposure` and `egress` describe intent so
  they mean the same thing on Proxmox as on a cloud
- `schema_version` on every document, pinned per schema file, with migrations from
  the first release
- Validation errors carry a machine-readable code and prose written for a reader
