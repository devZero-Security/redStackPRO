<!-- markdownlint-disable MD033 MD041 -->

![redStackPRO: red team infrastructure and cyber ranges](docs/images/banner.png)

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-3B9EFF" alt="MIT license">
  <img src="https://img.shields.io/badge/version-0.9.0-CF2127" alt="version 0.9.0">
  <img src="https://img.shields.io/badge/providers-GCP%20%7C%20AWS-3B9EFF" alt="providers GCP and AWS">
  <img src="https://img.shields.io/badge/status-pre--release-A97BFF" alt="status pre-release">
  <img src="https://img.shields.io/badge/exports-Terraform%20%2B%20Ansible-844FBA?logo=terraform&logoColor=white" alt="Terraform and Ansible">
</p>

# redStackPRO

> A web canvas where you build infrastructure as a topology, then export a
> complete, runnable working directory of Terraform and Ansible. You run it from
> your own machine. **redStackPRO never holds your cloud credentials.**

redStackPRO puts attack infrastructure and target ranges on the same canvas.

Split horizon C2, attack infrastructure: two front doors that do not share a fate,
Apache fronting Sliver and Nginx fronting Mythic, each redirector on its own peered
network, with the teamservers, collector and operators behind a jumpbox.

![Split horizon C2 on the canvas: two redirector networks, Apache fronting Sliver and Nginx fronting Mythic, over a shared C2 subnet with the teamservers, an OpenSearch collector, operators and a jumpbox.](docs/images/split-horizon.png)

Harbor, a target range: a small corporate forest, a root domain and a child over a
parent-child trust, with the ordinary path from a phished workstation to the forest.

![The Harbor range on the canvas: the harbor and freight domains over an intra-forest trust, four Windows hosts and a jumpbox.](docs/images/harbor.png)

GOAD, the full lab: three domains across two forests, five machines and their trusts,
the reference range the written solution follows.

![The GOAD lab on the canvas: sevenkingdoms, north and essos across two forests, their intra and cross-forest trusts, five machines and a jumpbox.](docs/images/goad.png)

> [!IMPORTANT]
> **The export is the boundary.** The canvas generates files; you run them under
> your own credentials. redStackPRO never deploys anything and never holds a secret.

> [!CAUTION]
> **Authorized use only.** redStackPRO builds offensive infrastructure and
> deliberately vulnerable ranges. Use it only in lab environments you own or are
> explicitly authorized to test, never against systems you do not have written
> permission for.

---

## 🧭 Status

Pre-release, and the topology schema is still moving. The pipeline itself works end
to end: a topology compiles to Terraform and Ansible, and the export deploys.

| Provider | State |
| -------- | ----- |
| GCP, AWS | Supported and tested end to end, for both target ranges and attack infrastructure. |
| Azure | On the roadmap. Needs a peering module for the attack side. |
| Proxmox, ESXi | On the roadmap. Neither can allocate a public address on its own, so redirector reachability depends on a network redStackPRO does not control. |

---

## 🐳 Run with Docker

The whole canvas in one container, the API and the web app on one port:

    docker compose up                    # builds from this repo, http://127.0.0.1:8000

Or pull the published image instead of building it:

    docker run -p 8000:8000 -v redstackpro-data:/data \
      ghcr.io/devzero-security/redstackpro:0.9.0

The canvas listens on 8000 inside the container. To serve it on a different host
port, change the left half of the mapping (`-p 8787:8000`), or set
`REDSTACKPRO_PORT` for compose (`REDSTACKPRO_PORT=8787 docker compose up`).

Compose also carries an optional Postgres backend for a shared deployment:

    REDSTACKPRO_DATABASE_URL=postgresql+psycopg://redstackpro:redstackpro@db:5432/redstackpro \
      docker compose --profile postgres up

The image is the composition layer only. It does not carry Terraform or Ansible
and never holds your cloud credentials: you run the export it produces from your
own machine, exactly as in the from-source flow below.

---

## ⚙️ Run from source

Python 3.11 or newer, and Node 24 for the canvas.

    git clone <this repo> && cd redstackpro
    python -m venv .venv && . .venv/bin/activate
    pip install -e ".[dev]"

**The canvas** is two processes, the API and the web app:

    redstackpro serve                            # http://127.0.0.1:8000
    cd frontend && npm install && npm run dev

`redstackpro serve --port 8787` moves the API. Point the canvas dev server at it
with `REDSTACKPRO_API=http://127.0.0.1:8787`.

Open it, load a template from the library, choose your cloud in the toolbar
provider selector (GCP or AWS), press Compile, then Download. You get a zip of the
working directory described below.

**Or skip the canvas entirely** and compile a shipped template from the command
line, same compiler, same output:

    redstackpro compile frontend/public/goad/goad-light.json -o export

The command line defaults to GCP. Pass `--provider aws` for AWS.

That writes about **200 files**: Terraform for the cloud, Ansible for everything
that happens on the boxes, a `deploy.sh`, and a `RANGE-BRIEFING.md` telling you the
credentials and what is planted where. `goad-light` is a two-domain Active
Directory range: `sevenkingdoms` and `north` across a forest trust, two domain
controllers and a member server, plus a jumpbox.

To deploy it, fill in `export/terraform/terraform.tfvars` and run:

    cd export && bash deploy.sh

`deploy.sh` applies the Terraform and then provisions from the range's own
jumpbox, because the managed hosts sit on a private subnet nothing else can
reach. Your cloud credentials stay on your machine throughout.

---

## 🤖 API and agents

Everything the canvas does is available headless, so an agent can operate
redStackPRO without a person clicking through it. A topology is plain JSON against
a published schema (`src/redstackpro/schema/topology/`, also served at `/api/v1/registry/schema`),
the registry endpoints report the vocabulary of node kinds, providers and roles,
and the validate and compile steps the canvas calls are the same REST endpoints.
The API is documented at `/docs` and `/openapi.json`, which a model can read as
tools.

    redstackpro serve                                  # http://127.0.0.1:8000
    curl 127.0.0.1:8000/api/v1/registry/schema         # the topology schema
    curl -X POST 127.0.0.1:8000/api/v1/validate \
      -H 'content-type: application/json' \
      -d '{"document": {...topology...}, "provider": "gcp"}'
    curl -X POST 127.0.0.1:8000/api/v1/compile \
      -H 'content-type: application/json' \
      -d '{"document": {...topology...}, "provider": "gcp"}'

Validation returns structured findings, each with a stable `code`, the target,
prose and a remedy, and the compiler refuses a document with errors and hands back
those same findings. The loop is read the schema, compose a topology, validate,
fix what the findings name, compile. A model iterates on the outcome rather than
scraping prose, and the validate call stores nothing along the way. The command
line is the same pipeline for a shell agent, `redstackpro validate` and
`redstackpro compile`.

The running instance trusts the local caller, which suits a single-user or
self-hosted deployment. Authenticated, multi-tenant agentic access over the API
is part of the enterprise edition. redStackPRO holds no cloud credentials on any
path: the export is the handoff, and you run it yourself.

---

## 💡 Why

redStack proved the pattern but the topology is fixed in code. redStackPRO makes
it composable, adds multi-provider support, and puts attack infrastructure and
target ranges on the same canvas.

---

## 📚 Docs

- `docs/architecture.md`
- `docs/schema.md`
- `docs/validation.md`
- `docs/solutions/`
- `src/redstackpro/schema/topology/`

---

## 🗂️ Repo layout

    src/                     the Python package and everything it ships
      redstackpro/           the composition layer: validator, compiler, API
        schema/              the document schema, registry data, worked examples
        tools/               command line tools (compile, validate, dev tooling)
        assets/              Ansible roles and static files baked into the export
    frontend/                the web canvas (Vite + React)
    tests/                   the suite: compiler, validator, API, export
    docs/                    architecture, schema, validation, solutions, decisions
    pyproject.toml           package metadata, deps, and the console entry points
    alembic.ini              migration config for the Postgres backend
    Dockerfile               the one-container build (API plus built canvas)
    docker-compose.yml       local run, with an optional Postgres profile
    .dockerignore            build context trim
    README.md                this file
    LICENSE                  MIT, with the GOAD templates under GPLv3
    .github/                 CI workflows

---

## ✅ Checks

CI runs these on every push and pull request.

<details>
<summary>CI checks</summary>

All of them run locally except the Ansible ones, which need a Linux control node.

    pytest -q                                     the compiler, validator, and API
    redstackpro validate --hostname <name>        the worked examples
    python -m redstackpro.tools.check_conventions the house rules in the project conventions
    cd frontend && npm test && npm run build      the canvas

The rest run against a compiled export rather than against the generator,
because a working directory a person unzips and runs is the thing being claimed:

    redstackpro compile src/redstackpro/schema/topology/examples/0.4.0/redstack.json --hostname <name> -o export
    terraform -chdir=export/terraform fmt -check -recursive
    terraform -chdir=export/terraform validate
    ansible-playbook -i export/ansible/inventory.yml export/ansible/site.yml --syntax-check
    python -m redstackpro.tools.check_roles export/ansible

`--hostname` is not a flag to work around a broken example. Every shipped example
carrying a redirector arrives one field short on purpose: a redirector is the one
host that answers to the internet by name, a domain has to be registered and
pointed at the box by a human, and nothing can invent one. The validator says so
(RDR001) and the compiler refuses. Pass any domain you control and the tools
fill it the way you would in the canvas inspector before pressing Compile.

`check_roles.py` exists because a syntax check never opens a file reached by
`include_tasks` with a templated name, which is every branch the roles have.

</details>

---

## License

MIT. See LICENSE.

The GOAD range templates under `frontend/public/goad/` are the exception: they are
derived from [GOAD](https://github.com/Orange-Cyberdefense/GOAD) (GPLv3) and are
distributed under GPLv3, with the license and attribution in that directory. They
are data, not code: the canvas loads them as native ranges that compile through
redStackPRO's own terraform and ansible. The rest of the project is MIT.

A devZero Security LLC project.
