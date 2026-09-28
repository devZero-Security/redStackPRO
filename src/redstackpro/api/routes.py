"""Routes.

Every UI action goes through the API with no exceptions, or the eventual agent
harness hits a wall. The agent interface is topology document submission rather than
REST CRUD: post a whole topology, get validation failures with reasons, iterate.
See architecture.md.
"""

import io
import json
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, Header, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import or_, select

from ..export import compile_topology as assemble_export
from ..migrate import LATEST, MigrationError, migrate
from ..registry import Registry
from ..terraform import GenerationError
from ..validate import validate
from . import db, retention
from .principal import (CurrentPrincipal, Principal, conflict, forbidden,
                        invalid, not_found)

registry = Registry()

TAGS = [
    {"name": "topologies",
     "description": "Saved topologies. One owner, org visible or private, "
                    "immutable revisions on every save."},
    {"name": "blueprints",
     "description": "Starter topologies to clone from. Seeded system ones have no "
                    "owner; a team publishes its own. A clone is a private copy."},
    {"name": "validation",
     "description": "Topology semantics the schema cannot express. Findings carry "
                    "a code, target ids, prose, and a remedy."},
    {"name": "compile",
     "description": "Renders a topology into a working directory of Terraform and "
                    "Ansible. The archive is a formatter over the file map."},
    {"name": "import",
     "description": "Converts an external range definition (a GOAD config) into "
                    "a redStackPRO range document. Import only, nothing stored."},
    {"name": "registry",
     "description": "Node kinds, edge roles, and provider capabilities. The "
                    "canvas builds its palette from here rather than "
                    "hardcoding kinds."},
    {"name": "system", "description": "Liveness."},
]

SCHEMA_PATH = (Path(__file__).resolve().parents[1]
               / "schema/topology" / f"{LATEST}.json")

router = APIRouter()


# ---------------------------------------------------------------- schemas

class TopologyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    document: dict
    visibility: str = "private"


class TopologyUpdate(BaseModel):
    document: dict
    version: int = Field(description="The version you read. Mismatch is a 409.")
    name: str | None = None
    visibility: str | None = None


class TopologySummary(BaseModel):
    id: str
    name: str
    mode: str
    visibility: str
    schema_version: str
    version: int
    owner_id: str | None
    is_blueprint: bool
    editable: bool


class DocumentSubmission(BaseModel):
    """The agent path: submit a whole topology, no stored topology involved."""
    document: dict
    provider: str = "gcp"
    region: str | None = None


# ---------------------------------------------------------------- helpers

def session(request_session=Depends(lambda: None)):
    raise RuntimeError("replaced in create_app")


def _summary(topology, principal):
    return TopologySummary(
        id=topology.id,
        name=topology.name,
        mode=topology.mode,
        visibility=topology.visibility,
        schema_version=topology.schema_version,
        version=topology.version,
        owner_id=topology.owner_id,
        is_blueprint=topology.is_blueprint,
        editable=_may_write(topology, principal),
    )


def _may_read(topology, principal):
    # A blueprint is a starter to clone from. A system one has no owner and is a
    # global starter; a team's own published blueprint is scoped to that org, so
    # publishing shares within the org rather than with everyone. This is the
    # privacy 0025 left open. See 0028.
    if topology.is_blueprint:
        if topology.owner_id is None:
            return True
        return topology.org_id == principal.org_id
    if principal.is_admin and topology.org_id == principal.org_id:
        return True
    if topology.owner_id == principal.id:
        return True
    return topology.org_id == principal.org_id and topology.visibility == "org"


def _may_write(topology, principal):
    """Org visible topologies are read only to non owners. Reuse is by copy, because
    editable shared topologies need a real answer to concurrent writes and compare
    and swap returning a conflict is not one for a team. See 0009."""
    return topology.owner_id == principal.id


def _load(sess, topology_id, principal, write=False):
    topology = sess.get(db.Topology, topology_id)
    if topology is None or not _may_read(topology, principal):
        # A topology the principal cannot read is indistinguishable from one that
        # does not exist, so org membership is not enumerable.
        raise not_found("topology", topology_id)
    if write and not _may_write(topology, principal):
        raise forbidden(
            "This topology is visible to your org but owned by someone else. "
            "Duplicate it to make changes.",
            topology_id=topology_id, owner_id=topology.owner_id)
    return topology


def _document(sess, topology):
    revision = sess.get(db.TopologyRevision, topology.current_revision_id)
    return revision.document if revision else None


def _findings(document, provider=None):
    return [f.to_dict() for f in validate(document, provider=provider,
                                          registry=registry)]


def _compile(document, provider, region=None):
    """The complete working directory, generated code plus static modules and
    roles. Anything less is not runnable, and the download button is the
    product. See 0010."""
    return assemble_export(document, registry, provider=provider, region=region)


# ---------------------------------------------------------------- registry

@router.get("/registry/palette", tags=["registry"])
def get_palette(mode: str = Query("offense")):
    """What the canvas offers. Read from the registry rather than hardcoded, so
    pro adds a node kind by dropping a file in. See 0013."""
    return {"mode": mode, "groups": registry.palette(mode)}


@router.get("/registry/providers", tags=["registry"])
def get_providers():
    return {
        "providers": [
            {
                "name": name,
                "capabilities": sorted(registry.capabilities(name)),
                "unsupported": spec.get("unsupported", []),
                # Deployment-proven or not. The canvas greys a preview backend in
                # the chooser rather than hiding it: the compiler really does
                # build these, so hiding understates the product. Anything that
                # forgets to declare it is treated as preview, because claiming
                # proven by omission is the wrong way round.
                "maturity": spec.get("maturity", "preview"),
            }
            for name, spec in sorted(registry.providers.items())
        ]
    }


@router.get("/registry/roles", tags=["registry"])
def get_roles():
    return {"roles": registry.roles}


@router.get("/registry/schema", tags=["registry"],
            summary="The topology document schema")
def get_schema():
    """The canvas renders overlay forms from this rather than hardcoding fields,
    for the same reason it reads the palette rather than hardcoding kinds. Field
    descriptions and the x-redstackpro-source annotation come along, so a form can
    show help text and skip anything the compiler derives."""
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- topologies

@router.get("/topologies", response_model=list[TopologySummary], tags=["topologies"])
def list_topologies(sess=Depends(session), principal: Principal = CurrentPrincipal,
                limit: int = Query(100, ge=1, le=500),
                offset: int = Query(0, ge=0)):
    # Newest first and paged, so a large account is bounded. The shape stays a
    # bare list: a caller reading the array keeps working, and paging is opt in.
    # See 0026.
    #
    # Blueprints are their own listing, not part of a person's topologies. See 0025.
    stmt = (select(db.Topology)
            .where(db.Topology.org_id == principal.org_id)
            .where(db.Topology.is_blueprint.is_(False)))
    if not principal.is_admin:
        stmt = stmt.where(or_(db.Topology.owner_id == principal.id,
                              db.Topology.visibility == "org"))
    stmt = stmt.order_by(db.Topology.updated_at.desc()).limit(limit).offset(offset)
    return [_summary(g, principal) for g in sess.scalars(stmt)]


@router.post("/topologies", response_model=TopologySummary, status_code=201, tags=["topologies"])
def create_topology(body: TopologyCreate,
                 sess=Depends(session),
                 principal: Principal = CurrentPrincipal,
                 idempotency_key: str | None = Header(default=None)):
    if idempotency_key:
        # Sweep before the duplicate check, so a key past its window reads as a
        # new request rather than a stale hit. See 0024.
        retention.prune_idempotency_keys(sess)
        existing = sess.get(db.IdempotencyKey, idempotency_key)
        if existing:
            topology = sess.get(db.Topology, existing.resource_id)
            if topology:
                return _summary(topology, principal)

    document = _validated_document(body.document)

    topology = db.Topology(
        org_id=principal.org_id,
        owner_id=principal.id,
        name=body.name,
        mode=document.get("mode", "offense"),
        visibility=body.visibility,
        schema_version=document["schema_version"],
        version=1,
    )
    sess.add(topology)
    sess.flush()

    revision = db.TopologyRevision(topology_id=topology.id, version=1,
                                author_id=principal.id, document=document)
    sess.add(revision)
    sess.flush()
    topology.current_revision_id = revision.id

    if idempotency_key:
        sess.add(db.IdempotencyKey(key=idempotency_key,
                                   principal_id=principal.id,
                                   resource_id=topology.id))
    sess.commit()
    return _summary(topology, principal)


def _validated_document(document):
    if not isinstance(document, dict) or "schema_version" not in document:
        raise invalid("The document carries no schema_version.")
    if document["schema_version"] != LATEST:
        try:
            document = migrate(document)
        except MigrationError as exc:
            raise invalid(
                "This document is schema %s and cannot be migrated to %s: %s"
                % (document["schema_version"], LATEST, exc),
                schema_version=document.get("schema_version"), latest=LATEST)
    return document


@router.get("/topologies/{topology_id}", tags=["topologies"])
def get_topology(topology_id: str, sess=Depends(session),
              principal: Principal = CurrentPrincipal):
    topology = _load(sess, topology_id, principal)
    return {
        "topology": _summary(topology, principal).model_dump(),
        "document": _document(sess, topology),
    }


@router.put("/topologies/{topology_id}", response_model=TopologySummary, tags=["topologies"],
            summary="Save a new revision",
            responses={409: {"description":
                             "The topology moved since you read it. The body "
                             "carries your version and the current one."}})
def update_topology(topology_id: str, body: TopologyUpdate, sess=Depends(session),
                 principal: Principal = CurrentPrincipal):
    topology = _load(sess, topology_id, principal, write=True)

    if body.version != topology.version:
        raise conflict(
            "This topology moved since you read it. Reload and reapply your "
            "change.",
            topology_id=topology_id, your_version=body.version,
            current_version=topology.version)

    document = _validated_document(body.document)
    topology.version += 1
    topology.schema_version = document["schema_version"]
    topology.mode = document.get("mode", topology.mode)
    if body.name is not None:
        topology.name = body.name
    if body.visibility is not None:
        topology.visibility = body.visibility

    revision = db.TopologyRevision(topology_id=topology.id, version=topology.version,
                                author_id=principal.id, document=document)
    sess.add(revision)
    sess.flush()
    topology.current_revision_id = revision.id
    sess.commit()
    return _summary(topology, principal)


def _blueprint_document(sess, topology):
    """The revision a blueprint serves: the one pinned at publish time, not
    whatever the owner has edited since. Falls back to the current revision for a
    blueprint from before pinning existed, so an old row still clones. See 0028."""
    revision_id = topology.published_revision_id or topology.current_revision_id
    revision = sess.get(db.TopologyRevision, revision_id) if revision_id else None
    return revision.document if revision else None


def _copy_topology(sess, source, principal, name, document=None):
    """A deep copy with a fresh id, the copier as owner, visibility reset to
    private, is_blueprint reset to false, and no link back. Duplicating a topology
    and cloning a blueprint are the same operation, which is what 0025 lets the
    duplicate path already anticipated become.

    The document defaults to the source's current revision, which is what a
    duplicate copies. A clone passes the pinned blueprint revision instead, so
    the schema version comes from the document that is actually copied. See 0028."""
    if document is None:
        document = _document(sess, source)
    copy = db.Topology(
        org_id=principal.org_id,
        owner_id=principal.id,
        name=name,
        mode=source.mode,
        visibility="private",
        schema_version=document["schema_version"],
        version=1,
    )
    sess.add(copy)
    sess.flush()
    revision = db.TopologyRevision(topology_id=copy.id, version=1,
                                author_id=principal.id,
                                document=document)
    sess.add(revision)
    sess.flush()
    copy.current_revision_id = revision.id
    sess.commit()
    return copy


@router.post("/topologies/{topology_id}/duplicate", response_model=TopologySummary,
             status_code=201, tags=["topologies"])
def duplicate_topology(topology_id: str, sess=Depends(session),
                    principal: Principal = CurrentPrincipal):
    """A private copy of a topology the caller can read."""
    source = _load(sess, topology_id, principal)
    return _summary(_copy_topology(sess, source, principal,
                                "%s (copy)" % source.name), principal)


@router.delete("/topologies/{topology_id}", status_code=204, tags=["topologies"],
               summary="Delete a topology and its revisions")
def delete_topology(topology_id: str, sess=Depends(session),
                 principal: Principal = CurrentPrincipal):
    """Owner only, the same as any write. Revisions go with it through the
    cascade; stored compile results are left to age out, since they carry no
    foreign key and the archive is reached by compile id. See 0026."""
    topology = _load(sess, topology_id, principal, write=True)
    sess.delete(topology)
    sess.commit()


@router.post("/topologies/{topology_id}/publish", response_model=TopologySummary,
             tags=["blueprints"],
             summary="Mark a topology as a blueprint others can clone")
def publish_blueprint(topology_id: str, sess=Depends(session),
                      principal: Principal = CurrentPrincipal):
    """Publishing flags the topology and pins the revision a clone gets to the one
    current at publish time, so the owner can keep editing the live topology without
    moving what the next clone reads. Publishing again re-pins to the current
    revision, which is how a new template version is released. See 0028."""
    topology = _load(sess, topology_id, principal, write=True)
    topology.is_blueprint = True
    topology.published_revision_id = topology.current_revision_id
    sess.commit()
    return _summary(topology, principal)


@router.post("/topologies/{topology_id}/unpublish", response_model=TopologySummary,
             tags=["blueprints"], summary="Stop offering a topology as a blueprint")
def unpublish_blueprint(topology_id: str, sess=Depends(session),
                        principal: Principal = CurrentPrincipal):
    topology = _load(sess, topology_id, principal, write=True)
    topology.is_blueprint = False
    # No longer a blueprint, so it serves nothing. Clearing the pin keeps the row
    # honest; a later publish sets it again from the current revision. See 0028.
    topology.published_revision_id = None
    sess.commit()
    return _summary(topology, principal)


@router.get("/blueprints", response_model=list[TopologySummary],
            tags=["blueprints"])
def list_blueprints(sess=Depends(session),
                    principal: Principal = CurrentPrincipal):
    """The starter library. Seeded system blueprints have no owner; a team can
    add its own by publishing a topology. See 0025."""
    stmt = select(db.Topology).where(db.Topology.is_blueprint.is_(True))
    return [_summary(g, principal) for g in sess.scalars(stmt)
            if _may_read(g, principal)]


@router.post("/blueprints/{blueprint_id}/clone", response_model=TopologySummary,
             status_code=201, tags=["blueprints"],
             summary="Start a new private topology from a blueprint")
def clone_blueprint(blueprint_id: str, sess=Depends(session),
                    principal: Principal = CurrentPrincipal):
    source = sess.get(db.Topology, blueprint_id)
    if source is None or not source.is_blueprint or not _may_read(source,
                                                                  principal):
        raise not_found("blueprint", blueprint_id)
    # The pinned revision, not the owner's latest edit. See 0028.
    document = _blueprint_document(sess, source)
    return _summary(_copy_topology(sess, source, principal, source.name,
                                document=document), principal)


@router.get("/topologies/{topology_id}/revisions", tags=["topologies"])
def list_revisions(topology_id: str, sess=Depends(session),
                   principal: Principal = CurrentPrincipal,
                   limit: int = Query(100, ge=1, le=500),
                   offset: int = Query(0, ge=0)):
    # A save is a revision, so history grows without bound. Newest first and
    # paged. See 0026.
    topology = _load(sess, topology_id, principal)
    stmt = (select(db.TopologyRevision)
            .where(db.TopologyRevision.topology_id == topology.id)
            .order_by(db.TopologyRevision.version.desc())
            .limit(limit).offset(offset))
    return {"revisions": [
        {"id": r.id, "version": r.version, "author_id": r.author_id,
         "created_at": r.created_at.isoformat(),
         "current": r.id == topology.current_revision_id}
        for r in sess.scalars(stmt)
    ]}


# ---------------------------------------------------------------- validate

@router.post("/topologies/{topology_id}/validate", tags=["validation"])
def validate_topology(topology_id: str, provider: str | None = Query(default=None),
                   sess=Depends(session),
                   principal: Principal = CurrentPrincipal):
    topology = _load(sess, topology_id, principal)
    return _validation_response(_document(sess, topology), provider)


@router.post("/validate", tags=["validation"],
             summary="Validate a document without storing it",
             responses={200: {"content": {"application/json": {"example": {
                 "valid": False, "errors": 1, "warnings": 0,
                 "findings": [{
                     "code": "MGT001", "severity": "error",
                     "target_ids": ["ts-01"],
                     "template": "{name} has no management path.",
                     "values": {"name": "rt-ts-01"},
                     "message": "rt-ts-01 has no management path.",
                     "remedy": "Draw a manages edge from a jumpbox to its network.",
                 }]}}}}})
def validate_document(body: DocumentSubmission,
                      principal: Principal = CurrentPrincipal):
    """Submit a whole topology, get failures with reasons, iterate. That loop is
    the agent interface, and nothing is stored along the way."""
    return _validation_response(_validated_document(body.document),
                                body.provider)


def _validation_response(document, provider):
    findings = _findings(document, provider)
    errors = [f for f in findings if f["severity"] == "error"]
    return {
        "valid": not errors,
        "errors": len(errors),
        "warnings": len(findings) - len(errors),
        "findings": findings,
    }


# ---------------------------------------------------------------- compile

@router.post("/topologies/{topology_id}/compile", tags=["compile"])
def compile_topology(topology_id: str, provider: str = Query("gcp"),
                  region: str = Query(None),
                  sess=Depends(session),
                  principal: Principal = CurrentPrincipal):
    topology = _load(sess, topology_id, principal)
    return _compile_response(sess, _document(sess, topology), provider,
                             principal, topology_id=topology.id, region=region)


@router.post("/compile", tags=["compile"],
             summary="Compile a document without storing it",
             responses={
                 200: {"description": "The working directory as a file map."},
                 422: {"description":
                       "The topology has validation errors, listed in "
                       "details.findings. The compiler refuses to run."}})
def compile_document(body: DocumentSubmission,
                     sess=Depends(session),
                     principal: Principal = CurrentPrincipal):
    return _compile_response(sess, _validated_document(body.document),
                             body.provider, principal, region=body.region)


def _compile_response(sess, document, provider, principal, topology_id=None,
                      region=None):
    """Returns the file map. The archive endpoint is a formatter over it, so a
    zip and a file map cannot disagree. Synchronous today: a topology this size
    compiles in milliseconds. Going async returns 202 with the same compile_id
    and the response shape does not change. See 0010."""
    if provider not in registry.providers:
        raise invalid("No such provider: %s" % provider,
                      provider=provider, known=sorted(registry.providers))

    findings = _findings(document, provider)
    errors = [f for f in findings if f["severity"] == "error"]
    if errors:
        raise ApiValidationFailed(errors, findings)

    try:
        files = _compile(document, provider, region)
    except GenerationError as exc:
        raise invalid(str(exc), stage="compile")

    result = db.CompileResult(topology_id=topology_id, principal_id=principal.id,
                              provider=provider, files=files)
    sess.add(result)
    # A compile is the moment results grow, so it is also where they are swept.
    # The new result is younger than any cutoff, so this never touches it. See
    # 0024.
    retention.prune_compile_results(sess)
    sess.commit()

    return {
        "compile_id": result.id,
        "provider": provider,
        "files": [{"path": p, "contents": c} for p, c in sorted(files.items())],
        "warnings": [f for f in findings if f["severity"] == "warning"],
        "errors": [],
    }


def ApiValidationFailed(errors, findings):
    return invalid(
        "The topology has %d validation error%s. The compiler refuses to run."
        % (len(errors), "" if len(errors) == 1 else "s"),
        findings=findings)


@router.get("/compile/{compile_id}/archive", tags=["compile"],
            summary="Download the working directory as a zip",
            response_class=Response,
            responses={200: {"content": {"application/zip": {}},
                             "description":
                             "The same files the compile call returned."}})
def compile_archive(compile_id: str, sess=Depends(session),
                    principal: Principal = CurrentPrincipal):
    result = sess.get(db.CompileResult, compile_id)
    if result is None or result.principal_id != principal.id:
        raise not_found("compile result", compile_id)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, contents in sorted(result.files.items()):
            archive.writestr(path, contents)

    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition":
                 'attachment; filename="redstackpro-%s.zip"' % compile_id[:8]},
    )
