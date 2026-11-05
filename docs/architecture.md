# Architecture

## Shape

```
canvas  ->  topology  ->  compiler  ->  working directory  ->  user runs it
```

The topology is the product. The canvas is a view onto it. The compiler is a
backend. Provider vocabulary stays out of the node and edge model: the document
records only the deploy target and region the canvas last chose (`provider`,
`region`), and a compile can override both.

## Layers

**Topology layer.** Provider-agnostic. Node kinds, edges, overlays. Knows nothing
about AWS resource types or Proxmox bridges. Owns validation.

**Compiler.** Renders the topology into HCL and Ansible. One backend per provider.
Emits a single root module with inter-module references so dependencies resolve
at apply time on the user's machine.

**Configuration layer.** Ansible, provider-agnostic. Same roles regardless of
where the host was provisioned.

## Three distinct concepts

**Node kinds** are what a thing is: network, segment, teamserver, redirector,
collector, jumpbox, operator box, and in defense mode domain, dc, srv, wks and
siem (fw and appliance are declared but not built, so the palette hides them).
Containers are node kinds too, which is what
lets every edge endpoint be a bare node id. No provider vocabulary.

**Blueprints** are starting points users clone and modify. redStack is the
recommended offense blueprint, and the GOAD-derived labs and Harbor are the defense
blueprints, built on the same model. A saved topology can also be published as a
blueprint for the team.

**Overlays** are per-node parameters: which C2 on this teamserver, which gating
rules on this redirector, which services on this jumpbox.

Every overlay field is marked user-supplied or derived. User-supplied fields
become form inputs on the canvas and values in the generated Terraform and
Ansible. Derived fields become HCL references the user never sees. The compiler
needs this distinction to know whether to emit a value or a reference.

## Two modes, one schema

A `mode` field on the topology document with values `offense` and `defense`. Mode gates the
canvas palette, icons, and chrome. The compiler ignores it. One topology model, one
validator, one compiler, one export shape, one set of backends.

Defense mode ships the GOAD-derived labs and Harbor as blueprints that open
locked; Unlock to edit makes one an editable range, and a new defense topology is
drawn from the same palette. Instantiation parameters are not built yet.

## Provider support is declarative

Node kinds declare requirements (compute, a Linux or Windows image, a public
address, outbound routing). Providers declare capabilities. The canvas raises an
error at design time (`CAP001`, `CAP002`, `CAP004`) when a topology asks for
something a target cannot do. This is what keeps multiple providers from becoming
multiple forks.

## Validation lives in the topology layer

Not in the compiler. A teamserver no redirector fronts, a host in a no-egress
subnet that still needs packages, a host with no management path. These light up
live in the UI, and the compiler refuses to run on an invalid topology.

Validation errors carry both a machine-readable code and prose written for a
reader. The prose matters because the eventual agent harness iterates on it.

## Versioning

Every saved topology carries `schema_version` with a migration path from day one.
Documents are stored as JSON (SQLite by default, Postgres optional) with
immutable revisions, which is also what
supplies the corpus migrations get tested against.
Users will save blueprints the week this ships and the model will change the
following month.

## API

API-first. Every UI action goes through the API with no exceptions, or the
eventual agent harness hits a wall.

- Compile results with IDs (compile is synchronous; the archive endpoint downloads a result by ID)
- Idempotency keys on anything that creates
- A compile endpoint that returns the working directory without side effects
- Structured errors, not status codes alone

The agent interface is topology document submission, not REST CRUD. An agent posts a
whole topology, gets back validation failures with reasons, and iterates. That
loop is what a language model is good at.

## Export

Compile returns a map of paths to contents. The archive endpoint is a formatter
over that map for the browser download.

The deliverable is a complete working directory: the Terraform root module and
`modules/`, the Ansible tree, `deploy.tfvars` to fill in, `deploy.sh` and
`deploy.ps1`, `manage.sh` and `manage.ps1`, `verify.py`, a `DEPLOYMENT-GUIDE.md`
with the run order, and the mode briefing. The user extracts it, fills in
`deploy.tfvars`, and runs `deploy.sh` without assembling anything.

## Scope

The canvas covers `offense` mode and `defense` mode, generating for GCP, AWS, and
Azure, all three supported and tested end to end for target ranges and attack
infrastructure. Proxmox and ESXi are on the roadmap, not yet supported; neither
can allocate a public address on its own, so redirector reachability would
depend on a network redStackPRO does not control.

Defense mode ships the GOAD-derived labs and Harbor as blueprints, and a range
can also be drawn from scratch on the same canvas. Instantiation parameters (one
topology stood up N times without collisions) are not built yet.

Ansible generation ships from the first release. Inventory, variables, and
play ordering are derived from the topology; the role bodies are redStackPRO's own
roles under `src/redstackpro/assets/ansible/roles/`, several adapted from redStack.

## Known gaps accepted by the export-only model

Every export ships `manage.sh` (`manage.ps1` on Windows) for `status`, `start`,
`stop`, and `teardown`, so the deployment's state and lifecycle are managed from the
export itself. What the model still does not do:

- No drift detection

An optional import path where users paste back outputs or state would close
it if it turns out to matter. Nothing in redStackPRO does this today.
