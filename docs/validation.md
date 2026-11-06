# Validator rules, schema 0.7.0

`SCH001` applies the JSON schema to the document. Everything after it is topology
semantics and belongs in the topology layer validator, not in the compiler. Every
rule carries a machine-readable code and prose written for a reader, because the
eventual agent harness iterates on the prose.

Severity is `error`, `warning` or `info`. The compiler refuses to run on any error.
An `info` finding is a notice: the export is fine, it just may not be what you
expect. A finding about one field carries that field's dotted path under its node
or edge in `field` (for example `tls.cert_source`), so the canvas can mark the
field itself.

Implemented in `src/redstackpro/validate.py`, one function per rule, with a negative
test per rule in `tests/test_validate.py` and `tests/test_ux_rules.py`. Rules
marked not implemented below are described but not yet written.

## Schema

- `SCH001` error. A value the topology schema rejects: a wrong type, a value
  outside an enum, a missing required field, a field the node or edge does not
  have, or a value that misses its pattern (a prefix with an underscore, a cidr
  with no mask, a domain with a scheme). The message is
  `{field} on {node}: {reason}. Example: {example}.` A node is checked against
  the one definition its `kind` selects and an edge against the one its `role`
  selects, so a bad field is one finding rather than one per branch of the
  schema's `oneOf`. A cidr with host bits set (`10.30.10.5/24`) is reported here
  too, since the clouds take a network address only. A document is checked
  against the schema of its own `schema_version`; the API migrates to the latest
  first. A document-level finding points at the target `topology`. Problems
  another rule words better are left to it: an operator handle or role
  (`VPN005`, `VPN006`), a `vulns_vars` that is not an object (`RNG012`), and an
  empty redirector domain (`RDR001`). A document whose nodes or edges lack an
  id, kind or role gets only `SCH001`, since the other rules cannot index it.

## Naming

Names are composed from the topology `prefix` and the node `id`, never stored.

- `NAM001` error. A node id must carry the kind tag its kind declares in the
  registry as the trailing token: `myth-ts01` for a teamserver, `c2-sub01` for a
  subnet.
- `NAM002` error. Every node id must end in a two digit ordinal. The slug carries
  the meaning; the ordinal keeps siblings apart.
- `NAM003` error. The composed name must be 15 characters or fewer. Windows
  truncates NetBIOS names there, so a longer host answers to a name the
  inventory does not use. On a Linux host the message says only that host names
  here are capped at 15.

## Referential integrity

- `REF001` error. Every edge `source` and `target` resolves to a node id.
- `REF002` error. Node ids are unique. Edge ids are unique.

## Endpoint kinds per role

- `END001` error. `attached` runs host to segment, or segment to network. No
  other combination.
- `END002` error. `fronts` runs redirector to teamserver.
- `END003` error. `logs_to` runs host to collector.
- `END004` error. `manages` runs jumpbox to network or segment.
- `END005` error. `peers` runs network to network. No other combination.
- `NET001` error. A `fronts` or `logs_to` edge whose endpoints resolve to
  networks with different `provider` values. Cross-provider transport is not
  implemented.

## Cardinality

- `CAR001` error. Every host has at least one `attached` edge.
- `CAR002` error. Every segment has exactly one `attached` edge to a network.
- `CAR003` error. A multihomed host has exactly one attachment marked `primary`.
- `CAR004` error. A host has at most one `logs_to` edge.
- `CAR005` error. A routing domain has at most one `manages` edge naming it or
  any of its segments as target. Two managers means ProxyJump cannot pick one.
- `CAR006` warning. A redirector fronting more than two teamservers. Normal, and
  redStack's own shape. Worth noting only because it concentrates blast radius:
  losing that host cuts every chain behind it.
- `CAR007` warning. A teamserver with no `fronts` edge. It has no inbound path.
- `CAR008` warning. A teamserver running a web-UI C2 (Mythic, Adaptix) with no
  operator that can open the UI. A plain Kali operator is SSH only, so the
  topology needs a Windows operator or a Kali operator with `desktop: true`
  (xrdp over a Guacamole RDP tile), or it should run a headless C2 such as
  Sliver instead.

## Fronting

- `FRT001` error. Redirectors fronting the same teamserver disagree on the URI
  prefix or the gating header. A beacon would work through one and get the decoy
  through another.
- `FRT002` error. One redirector routes the same prefix to two teamservers. The
  first rewrite rule matches and the second never fires.
- `FRT003` warning. A `fronts` edge with a `protocol` other than `https`, or a
  `listen_port` or `upstream_port` other than 443. Apache and nginx serve HTTPS on
  443 and proxy to 443, so another listen port opens a port nothing answers on and
  the beacon is told to call it, `dns` opens UDP with no listener, and another
  upstream port proxies to nothing.

## Reachability and management

- `MGT001` error. Every host the compiler configures has a management path,
  meaning a `manages` edge names its segment or its network. A host with
  `exposure: internet` on its segment may instead be reached directly. A jumpbox
  is exempt, since it is the entry point and would otherwise flag itself.
- `NET002` error. A `manages` edge whose jumpbox does not resolve to the same
  routing domain as its target, and no `peers` edge joins the two. `MGT001` asks
  whether a management path is claimed; this asks whether it is possible. A peers
  edge is the transport, so cross-network management is legal exactly when the two
  networks are directly peered. Peering is not transitive, so an edge from A to B
  and one from B to C does not let a jumpbox in A manage C.
- `NET003` error. A `fronts` edge whose redirector and teamserver are in different
  routing domains with no `peers` edge joining them. The redirector opens the
  upstream connection, so like `manages` and `logs_to` it is legal across a
  boundary exactly when a peering carries it; without one the cross-network rule
  names a CIDR that has no route.
- `NET004` error. A range host's `internal_ip` (only `dc`, `srv`, `wks`, `fw`
  carry the field) falls outside the `cidr` of the segment it sits in. A pinned
  address terraform cannot even route to from its own subnet is not a config a
  deploy could ever satisfy.
- `NET005` error. Two hosts in the same segment pinned to the same
  `internal_ip`. The second host's resource either fails to claim the address
  or silently steals it from the first at apply time.
- `NET006` error, provider-specific. A host's `internal_ip` falls inside the
  addresses the target provider reserves at either end of a subnet. AWS and Azure
  hold back the first four and the last; GCP holds back the first two and the last
  two. The counts are data, in each provider's `reserved_addresses` block under
  `src/redstackpro/schema/registry/providers/`. Because the bands differ, one topology can be legal
  on GCP and refused by AWS: the stock GOAD labs shipped a jumpbox pinned to
  `192.168.56.2` that deployed on GCP for months, then failed every AWS apply with
  "Address 192.168.56.2 is in subnet's reserved address range" two minutes in,
  after a NAT gateway and five instances already existed.
- `NET007` error. A subnet whose `cidr` is not inside its network's `cidr`. GCP
  takes it; AWS and Azure refuse it at apply. The remedy suggests a range inside
  the network.
- `RDR001` error. A redirector has no `hostname`, or its hostname still contains a
  placeholder (`example`, `change-me`, `changeme`, `your-domain`, in any case), so
  any `example.com` style name is refused. A domain cannot be generated
  the way the gating header value is: someone has to register one and point it at the
  redirector's address. Shipping a plausible placeholder hid that until deploy, where
  it surfaced as the redirector blocking on "create an A record for
  cdn.example-lure.com", an instruction nobody could follow, because satisfying it
  needed a topology edit rather than a DNS edit. Failing in the canvas costs seconds and
  says what to do.

  The hostname is required whatever `tls.cert_source` says. Self signed narrows the
  question to a certificate the beacon will not trust, but it does not remove the
  need for a name: the implant profile, the gated URL an operator hands out, and every
  solution step are written in terms of the domain. `letsencrypt` is the default,
  so the name you choose gets a real certificate unless you deliberately pick
  `self_signed`.

  This is why a shipped example carrying a redirector does not validate as it stands:
  it is exactly one field short, and that field is yours. Set the domain and it
  compiles. `tests/shipped.py` fills it for the test suite, and
  `test_every_shipped_redirector_example_demands_a_hostname_first` pins both halves:
  that `RDR001` is the only error in a shipped example, and that supplying the domain
  clears it.

  The gating header value goes the other way: leave it blank and the compiler rolls a
  fresh random token per redirector pool, so the examples ship it empty rather than as
  a literal anyone reading the repo would already know. The canvas shows "leave blank
  for a random value" as hint text, from `x-redstackpro-placeholder` in the topology
  schema.
- `RDR002` warning. A redirector sets `gating.decoy_video` but no
  `gating.decoy_asset_pack`, which is a combination that cannot do anything. Every
  other asset on the cover page has a keyless fallback, so turning a knob on always
  produces something; a hero clip has none. Free-license libraries carry documentary
  footage rather than short quiet brand-free b-roll, and the libraries that do carry
  b-roll want their terms discharged with a visible credit on the page, which is
  the one thing a cover page cannot show without announcing what it is. So an
  operator's own pack is the only source.

  That made it the worst kind of setting: one that looks applied. It compiled, it
  deployed, the page rendered, and the only trace was a line on the redirector's
  stderr. A warning and not an error, because the page is genuinely fine without it:
  the hero falls back to the photograph planned alongside the clip, and then to drawn
  artwork. Nothing is broken; the operator is simply not getting what they asked for,
  and is entitled to hear it while the topology is still in front of them.
- `MGT002` error. A jumpbox is excluded from its own ProxyJump path. This is a
  compiler invariant, listed here because it is what the rule protects.

## VPN access

The multi-user VPN access layer, an offense concept: how operators reach the range
and who they are. The fields live on the jumpbox overlay: `access_mode`
(`public`, `wireguard`, `openvpn`), `vpn_port`, `vpn_protocol` (`udp`, `tcp`),
and `operators` (a roster of `{handle, role?}`). Credentials are generated at
apply, never in the export.

- `VPN001` error. A jumpbox with `access_mode: wireguard` and
  `vpn_protocol: tcp`. WireGuard runs over udp only, so this names a listener
  that cannot exist and the export would render an unreachable tunnel. Use
  `access_mode: openvpn` for tcp.
- `VPN002` warning. A defense jumpbox that declares a VPN `access_mode` or a
  non-empty `operators` roster. The VPN access layer and the operator roster are
  offense features; a defense range keeps the public portal, so the fields are
  ignored there. A warning rather than an error, since they do no harm.
- `VPN003` warning, offense only. A jumpbox on a VPN `access_mode` with no
  `operators` declared. The tunnel stands up, but only the shared break-glass
  admin holds a credential, so no per-user access is provisioned. A valid
  single-admin range, just probably not what a team meant to build.
- `VPN004` error. Two `operators` on one jumpbox sharing a `handle`. The handle
  keys the portal account and the VPN credential, so a duplicate collides at
  apply and the second account cannot be created. The same shape as `RNG007` for
  domain usernames.
- `VPN005` error. An operator `handle` that is not safe to deploy. The handle is
  interpolated into shell, filenames, and SQL on the jumpbox at apply, so it is held
  to a strict charset: lowercase letters, digits, dot, underscore or hyphen, starting
  with a letter or digit, at most 32 characters. Rename each handle to that form.
- `VPN006` error. An operator `role` that is not safe to deploy. The role goes into
  the briefing table and, as a comment, into the Guacamole seed SQL, so a newline or a
  pipe corrupts the table or breaks out of the SQL comment. A role is a single line,
  no pipe character, at most 64 characters. Shorten it and remove any newline or pipe.

## Jumpbox

- `JMP001` warning. A jumpbox without `guacamole` in its `services`. There is no
  portal, so hosts are reachable over ssh only, while deploy.sh and the guide send
  the operator to the portal.
- `JMP002` error. A jumpbox with `certificate_authority: false` while something
  signs with that CA: a collector with TLS on (the default), a Windows operator
  (its WinRM certificate), or `access_mode: openvpn`. Each fails mid provision
  without it, and only the OpenVPN task says why.

## Auto-stop

- `STP001` error. `auto_stop` sets both `at` and `after_hours` with a timezone other
  than UTC. `after_hours` is resolved at apply as a UTC clock, so a range with
  `after_hours` is scheduled in UTC, and an `at` in another zone cannot be compared
  with it. Keep one of the two, or set the timezone to UTC.

## Peering

A `peers` edge joins two networks so hosts in one can reach hosts in the other on
private addresses. It is what makes cross-network `manages` and `logs_to` legal.
The cloud backends render it as VPC peering on GCP and AWS and VNet peering on
Azure; Proxmox and ESXi, which cannot peer, refuse through `CAP004`.

- `PEER001` error. A `peers` edge whose source and target are the same network. A
  network peered with itself is not a connection.
- `PEER002` error. Two `peers` edges between the same pair of networks. One
  connection joins two networks; a second is redundant and, on a real cloud, an
  error at apply.
- `PEER003` error. Two peered networks whose CIDRs overlap. Peering with
  overlapping ranges fails at apply, because a host cannot tell which side an
  address in the shared range is on.

## Exposure and egress

Since 0.3.0 the segment's `exposure` is a ceiling and each host carries
`public_address`. These rules read the effective value, which is the host's own
field bounded by its segment.

- `EXP001` error. A jumpbox or redirector that holds no public address, so
  nothing outside can reach the thing that exists to be reached. Two ways to get
  there and the message says which: the segment permits no address, or the
  segment permits one and the host declined it.
- `EXP002` error. A teamserver, collector, or operator box holding a public
  address. Public addresses belong only on redirectors and jumpboxes. Before
  0.3.0 the remedy was to split a segment; it is now to change one field, which
  is the point of the change.
- `EXP003` error. A host in a segment with `egress: none` requires package
  installation. Nothing in the model can install offline.
- `EXP005` error. A host asks for a public address in a segment whose `exposure`
  permits none. Ignoring it would produce a topology that reads as exposed and
  deploys as unreachable, which is the failure the ceiling exists to prevent
  rather than to introduce.
- `EXP004` warning, not implemented. Two segments in the same network with
  different `exposure` values, where an edge crosses from the more exposed to the
  less exposed one and the tiers are not adjacent. Advisory only, since tiers are
  advisory. Deferred because tier adjacency has no defined ordering yet.

## Provider capability

Requirements come from the node kind registry, not from the document.

- `CAP001` error. A node declares a requirement the selected provider does not
  offer. An operator box with `os: windows` against a provider with no Windows
  image is the first case.
- `CAP002` error. A segment declares `exposure: internet` against a provider that
  cannot provide it. Proxmox is the case, and the preflight check has to fail
  loudly rather than silently produce an unreachable host.
- `CAP003` is **retired**, deliberately. It described a segment holding both
  addressed and unaddressed hosts against a provider that cannot route one subnet
  both ways, which was AWS: a subnet has one route table and one default route, so
  it is public or private and not both. The AWS backend no longer builds that
  shape. An addressed host is placed in the network's own public subnet, leaving
  the segment's subnet free to route at the NAT for everyone else, so AWS now
  declares the `mixed_exposure_segment` capability alongside GCP. The rule had also
  never fired in practice, being gated on `exposure: internet` while every shipped
  blueprint uses `local`, and its description had drifted to the opposite of the
  real failure.
- `CAP005` info, provider-specific. A range host with `os: windows_10` or
  `windows_11` on GCP or AWS. Neither publishes a Windows client image, so the
  host boots Windows Server 2022. Azure has the client images.
- `CAP006` info, provider-specific. A range host with `os: windows_10` on a
  provider that boots a real client build (Azure, Proxmox, ESXi). Microsoft
  ended Windows 10 support on 2025-10-14. The choice stays for labs that need
  it; a new workstation defaults to `windows_11`.
- `CAP001` and `CAP002` name the overlay field whose value raised the
  requirement (for example `exposure` on a segment), in the remedy and in
  `field`.
- `CAP004` error. A `peers` edge against a provider that does not render network
  peering. GCP, AWS, and Azure do; Proxmox and ESXi cannot peer at all, since
  joining two networks is a property of the host network's routing that
  redStackPRO does not control. The
  reason travels from the provider registry.

## Collector

- `LOG001` error. A `logs_to` edge whose endpoints share no routing domain and
  are not joined by a `peers` edge. Log shipping is push over TCP, so the sender
  has to be able to open a connection to the collector, and a peering carries that
  across a network boundary.
- `LOG002` warning. A collector with `tls: false`.
- `LOG003` **removed**, deliberately. It warned that a collector sharing a segment
  with the jumpbox belongs in its own tier. redStack runs the collector in the one
  internal segment alongside the jumpbox and the operator boxes, so warning about
  the shipped shape every time was noise.

## Ordering

Not a rule set. Ordering is derived from address dependencies rather than
declared. A `logs_to` edge means the collector play runs before the sender play.
A `fronts` edge means the teamserver play runs before the redirector play. If a
cycle appears, that is `ORD001` error, and it means the topology is wrong rather
than the ordering logic.

## Range model

These fire only in defense mode (`mode: defense`); the offense rules above are gated
off there, since a lab jumpbox on a local subnet is correct and defense blueprints
keep GOAD's host names instead of the kind tag and ordinal id scheme (`NAM001`,
`NAM002`). The shipped defense blueprints are clean of all of them.

- `RNG001` warning. A domain member (`dc`, `srv`, or `wks`) with no `joins`
  edge. In an AD range a host that joins no domain is drawn but part of nothing.
  A firewall is exempt, since it is not domain joined.
- `RNG002` warning. A `domain` that no domain controller joins. A domain needs a
  DC to exist; one with only member servers is not yet a working domain.
- `RNG003` error. A `trusts` edge from a domain to itself. A trust runs between
  two different domains; a self-trust is meaningless and would not provision.
- `RNG004` warning. A `siem` box with no `product` set. The product decides what
  the box collects, so an unset one is an incomplete appliance.
- `RNG005` warning. A `domain` that has user accounts but none with a
  domain-admin or enterprise-admin privilege. A lab domain needs a privileged
  account as the escalation target; a population with no admin has no top of the
  ladder to reach. An empty user list does not warn.
- `RNG006` error. Two domains that share an fqdn. A compile blocker rather than a
  warning: both cannot stand up, so the run would fail on the second.
- `RNG007` error. Two users in one domain with the same username. A
  sAMAccountName is unique within a domain, so the duplicate cannot be created.
- `RNG008` warning. Two `siem` boxes with the same `product`. A host reports to
  every SIEM box, one agent per product, so a Wazuh box and an ELK box coexist,
  but an agent can target only one box of a product and the second receives nothing.
- `RNG009` warning. A host declares a vuln that is really an account property
  (`kerberoasting`, `asreproasting`, `weak_password`, `password_in_description`).
  A host has no task for these, so declaring them in the host's `vulns` plants
  nothing; set them on a domain user's `flaws` instead. Caught because the run
  still succeeds, just without the attack the author intended.
- `RNG010` warning. A host declares a vuln that no role plants on that kind of
  host: `constrained_delegation` on any host (protocol transition is planted on a
  domain user's `flaws` only), `gpo_abuse` or `sysvol_secret` on anything but a
  `dc`, and `mssql_impersonation` or `mssql_linked` on anything but a Windows
  `srv` with role `sql` or the `mssql` service.
- `RNG011` warning, error for `keepass_vault`. A host declares a vuln whose task
  needs a `vulns_vars` key the host does not set, so the task is skipped. A
  `keepass_vault` with no `master_password` fails its task and stops the run for
  that host, so that one is an error.
  The required keys: `delegate_to` (`constrained_delegation_kerberos`),
  `bot_user` (`rdp_scheduler`, `responder`), `ntlm_relay_user` or `bot_user`
  (`ntlm_relay`), `stored_credential.owner` and `.username`, `files`,
  `keepass_vault.master_password`, `gpo_abuse.principal`, `mssql_linked_targets`,
  and `esc7_manager` / `esc14_target`, which may sit on any host in the domain.
  Every other key has a role default. The list lives in
  `validate.VULNS_VARS_REQUIRED`, and the canvas help in `frontend/src/vulns.js`
  `VULN_PARAMS` is kept in step by `tests/test_vuln_params_sync.py`.
- `RNG012` warning. A host's `vulns_vars` is not a JSON object (a string saved by
  an older canvas field, say), so none of its parameters reach the roles.

- `DOM001` error. A domain `fqdn` that is not at least two labels of letters,
  digits and hyphens (`corp`, `Seven Kingdoms.local`, an empty one), or a
  `netbios` that is not 1 to 15 letters or digits. Both compile, then promotion
  fails. An unset `netbios` is fine: the compiler uses the first label of the
  fqdn.
- `TRU001` warning. A `trusts` edge with `trust_type` `external` or `tree_root`.
  The dc role builds parent and child domains and forest trusts only, so the
  range gets no trust between the two. A trust with no `trust_type` is fine: the
  compiler picks `parent_child` when one fqdn ends with the other, else `forest`.
- `ACL001` warning. An entry in a domain's `acls` whose principal or target is
  not on that domain, or whose right is not one this release applies.
  `apply_acls.ps1` never fails on these: a missing principal is created as an
  empty group, a missing plain target is created as an empty group and the right
  lands on it, a missing `name$` target is skipped, and an unknown right is
  skipped. A name is known when it is a user, a group (built in, named in a
  user's `groups`, in `group_members`, or listed in the domain's `groups`), a
  gMSA, a joined computer with or without `$`, or, for a target, an OU or a
  distinguished name. `DOMAIN\name` is checked on that domain, and
  `NT AUTHORITY\` or `BUILTIN\` names always pass. The rights are the ones the
  script knows plus `ForceChangePassword` and `AddMember`, which the compiler
  maps onto them. List a group only an ACL names in the domain's `groups`.
- `HRD001` warning. A range host lists `hardening` controls. No role reads them
  in this release, so the host deploys without them.
- `SVC001` warning. A range host lists a `services` value no role installs.
  `mssql`, `iis` and `exchange` install on a Windows member server (`srv`);
  `adcs` and `mecm` come from `role`, so they count only alongside the matching
  role. Anything else (`smb`, a typo, `iis` on a workstation) installs nothing.
- `SVC002` info. A `fw` or `appliance` host. No role installs anything on it yet,
  so it boots as a plain host on its subnet.

`RNG006` and `RNG007` are the first of the compile pre-flight checks: things
that must hold before a range is provisioned, reported on the canvas now rather
than surfacing as a failure mid-run.

## Not implemented

- `MGT002`, a compiler invariant rather than a topology rule. It belongs in the
  compiler's own tests once inventory generation exists
- `EXP004`, deferred as above

## Open questions this file cannot yet answer

- Resolved by removal. `tunnel` endpoint kinds no longer matter because the role
  is gone.
- Whether `manages` may target an individual host, for the per-host exception
  case. Currently a validator relaxation with no schema change.
- Instantiation parameters for per-operator templates. Not in 0.7.0.
