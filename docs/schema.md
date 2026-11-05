# Topology schema

Status: written. Version 0.7.0 covers `offense` and `defense` modes. 0.1.0 through 0.6.0
and their examples stay in the repo as migration fixtures.

The schema is the artifact, not this file.

Four-digit codes (00NN) are internal design-decision references and are not
published with this repo.

- `src/redstackpro/schema/topology/0.7.0.json` is the document schema
- `src/redstackpro/schema/topology/examples/0.7.0/` holds four worked examples that
  double as test fixtures
- `docs/validation.md` holds the rules JSON Schema cannot express
- Decision 0007 is why the model is shaped the way it is, 0021 is why exposure is
  a per-host ceiling rather than a segment property, and 0029 is the `peers` role

## Shape in one paragraph

One node collection and one edge collection. The offense node kinds are `network`,
`segment`, `redirector`, `teamserver`, `collector`, `jumpbox`, and `operator`;
defense mode (`mode: defense`) adds `domain`, `dc`, `srv`, `wks`, `fw`, `siem`, and
`appliance` (see the range model below). Segments and networks are nodes, so
every edge endpoint is a bare node id. Edges carry a `role` of `attached`,
`fronts`, `logs_to`, `manages`, `peers`, and, in defense mode, `joins` (host to
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
  exercised by the `rollover` test fixture rather than shipped here.
- `parallel-chains.json`, two independent chains in separate routing domains, each
  with its own jumpbox and collector, so burning one does not burn the other.
- `peered.json`, two networks joined by a `peers` edge so a jumpbox in one manages
  hosts in the other across the peered boundary

## Range model

Defense mode (`mode: defense`) is the range canvas. A `domain` is a
container node the way a segment is; a host joins it with a `joins` edge and
nests inside its box. Domains link to each other with a `trusts` edge carrying
`direction`, `trust_type` (`parent_child`, `tree_root`, `external`, `forest`),
and `transitive`; a two-way trust is one bidirectional edge, not two.

The range host kinds `dc`, `srv`, `wks`, and `fw` share one overlay,
`overlay_range_host`. Its user fields:

- `os`, the image: `windows_server_2019`, `windows_server_2022`, `windows_10`,
  `windows_11`, `linux`, or a named distribution (`debian_13`, `debian_12`,
  `ubuntu_2204`, `ubuntu_2004`). Empty builds Windows Server 2022 for a `dc` or
  `srv` and Windows 11 for a `wks` (`fw` and `appliance` are drawn but not built
  in this release). GCP and AWS have no Windows client image, so `windows_10` and
  `windows_11` boot Server 2022 there (`CAP005`). Windows 10 is past end of
  support (Microsoft ended it on 2025-10-14); it stays a choice for labs that need
  it (`CAP006`).
- `hostname`, the Windows computer name, 15 characters max (`kingslanding`).
  Keep it equal to the id.
- `role`, a host's primary function. `sql`, `adcs` and `mecm` install something;
  `web`, `fileshare` and `generic` are badges only
- `services`, software for a Windows member server: `mssql`, `iis`, `exchange`.
  Any other value installs nothing (`SVC001`)
- `edr`, a label shown in the briefing. Defender runs only with
  `defender_enabled`; SIEM agents follow the SIEM boxes the range has
- `vulns`, planted attack-path misconfigurations and CVEs from the GOAD-derived
  catalog in `frontend/src/vulns.js`, kept as free strings so the catalog grows
  without a schema change
- `hardening`, defensive controls (`asr`, `runasppl`, `constrained_powershell`,
  and peers). Recorded but not applied in this release (`HRD001`)
- `notes`, free text for the author; nothing reads it during the deploy

A `domain` carries `fqdn`, `netbios`, `users`, `acls`, `gmsa`, `laps_readers`,
`group_members`, `ous`, and `groups`, the groups to create even though no user is
in them (a group only an access right names).

A `siem` box carries `overlay_siem` (`product` of `wazuh` or `elk`, a Linux `os`
from the named distributions, `hostname`, `notes`); an `appliance` reuses
`overlay_range_host`. Both sit on a subnet rather than joining a domain. Range
semantics are checked by the `RNG` rules in `validation.md`.

Every property carries a short `title` the canvas shows as its label, falling
back to the key. The `$defs` (`identifier`, `cidr`, `ipv4`, `port`,
`public_address`) carry a title and description too, for a form that resolves
`$ref`.

## Still open

**Instantiation parameters.** Per-operator templates mean the same topology spun up N
times without CIDR, hostname, or domain collisions. A topology-level variables block.
Not in 0.7.0. See 0012.

## Landed

- `peers` landed in 0.4.0: a network to network role for same-cloud links that do
  not warrant an endpoint host, which relaxes the cross-network management,
  logging, and fronting rules across the peered boundary (0029, 0030). The cloud
  backends render it as network peering with CIDR based cross-network firewall
  rules: gcp in 0030, aws in 0031, azure (VNet peering) in 0.10.0. Proxmox and
  ESXi cannot peer and refuse through `CAP004`. Both
  the `peered` example and the shipped redStack blueprint now run two networks, with
  redStack isolating its redirector in a network of its own peered to the main
  range
- `desktop` landed in 0.5.0: an optional boolean on `overlay_operator` that
  installs a desktop plus xrdp so a Kali operator can be driven over a Guacamole
  RDP tile, which satisfies CAR008's GUI requirement for a web-UI C2 without a
  Windows operator. Additive and default false, so the migration from 0.4.0 is a
  version bump and nothing else

## Roadmap

Anticipated, not decided. None of these is an ADR yet.

- `tunnel` as a standalone role if defense mode produces a pivot host case where
  the transport is the entire relationship
- Mixed-provider compilation, reading the optional `provider` field on networks.
  The field exists in the schema and only the validator reads it (`NET001` refuses
  a fronts or logs_to edge across two providers); the compiler ignores it, so it is
  a seam for a future hybrid export rather than a capability that ships today

## Fixed constraints

- No provider vocabulary in the node and edge model (the document records only the
  deploy target and region). `exposure` and `egress` describe intent so they mean
  the same thing on Proxmox as on a cloud
- `schema_version` on every document, pinned per schema file, with migrations from
  the first release
- Validation errors carry a machine-readable code and prose written for a reader
