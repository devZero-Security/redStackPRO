# Architecture

## Shape

```
canvas  ->  topology  ->  compiler  ->  working directory  ->  user runs it
```

The topology is the product. The canvas is a view onto it. The compiler is a
backend. Provider vocabulary never appears in the topology layer.

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
collector, jumpbox, operator box. Containers are node kinds too, which is what
lets every edge endpoint be a bare node id. No provider vocabulary. See 0007.

**Blueprints** are saved topologies users clone and modify. Current redStack ships as
the default blueprint. GOAD variants become blueprints in phase three.

**Overlays** are per-node parameters: which C2 on this teamserver, which gating
rules on this redirector, which services on this jumpbox.

Every overlay field is marked user-supplied or derived. User-supplied fields
become form inputs on the canvas and tfvars entries in the export. Derived fields
become HCL references the user never sees. The compiler needs this distinction to
know whether to emit a variable or a reference.

## Two modes, one schema

A `mode` field on the topology document with values `ops` and `range`. Mode gates the
canvas palette, icons, and chrome. The compiler ignores it. One topology model, one
validator, one compiler, one export shape, one set of backends. See 0012.

Range mode ships without an editor: a shipped GOAD topology rendered read-only with a
parameter form. Custom range authoring unlocks the same canvas later.

## Provider support is declarative

Node kinds declare requirements (public IP, Windows image, nested virt, private
DNS). Providers declare capabilities. The UI warns at design time when a topology
asks for something a target cannot do. This is what keeps multiple providers from
becoming multiple forks.

## Validation lives in the topology layer

Not in the compiler. A redirector with no upstream teamserver, a segment
with unintended egress, a host with no reachable management path. These light up
live in the UI, and the compiler refuses to run on an invalid topology.

Validation errors carry both a machine-readable code and prose written for a
reader. The prose matters because the eventual agent harness iterates on it.

## Versioning

Every saved topology carries `schema_version` with a migration path from day one.
Documents are stored as JSONB with immutable revisions, which is also what
supplies the corpus migrations get tested against. See 0008.
Users will save blueprints the week this ships and the model will change the
following month.

## API

API-first. Every UI action goes through the API with no exceptions, or the
eventual agent harness hits a wall.

- Async jobs with IDs and a status endpoint
- Idempotency keys on anything that creates
- A compile endpoint that returns the working directory without side effects
- Structured errors, not status codes alone

The agent interface is topology document submission, not REST CRUD. An agent posts a
whole topology, gets back validation failures with reasons, and iterates. That
loop is what a language model is good at.

## Export

Compile returns a map of paths to contents. The archive endpoint is a formatter
over that map for the browser download. See 0010.

The deliverable is a complete working directory: root module, `modules/`,
populated tfvars, ansible tree, and a README with run order. The user unzips and
runs `terraform init` without assembling anything.

## Scope

Revised by 0012. The original ordering put ranges at phase three and Azure ahead
of AWS.

1. Canvas, schema, validation, compile preview that deploys nothing
2. `ops` mode generation across GCP, AWS, and Proxmox
3. `range` mode as a rendered GOAD template with instantiation parameters, same
   three providers, no custom authoring
4. Packaging and self-hosting
5. Azure, custom range authoring, and multi-provider export

Proxmox and QEMU are the on-prem target. ESXi is deferred and costs nothing to
add later, since it is a packaging problem rather than a provider port. See 0003.

Ansible generation is in scope from the first release. Inventory, variables, and
play ordering are derived from the topology; role bodies come from redStack. See
0011.

## Known gaps accepted by the export-only model

- No deployment status tracking
- No destroy button
- No drift detection

An optional import path where users paste back outputs or state would close these
if it turns out to matter. Not in scope for the demo.
