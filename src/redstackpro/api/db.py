"""Storage.

The topology is one JSONB column. Saves are immutable revisions, with a pointer
to the current one. Everything adjacent stays relational. See 0008.

Postgres in deployment, SQLite in tests. SQLAlchemy's JSON type maps to JSONB on
Postgres, so the model is the same either way.
"""

import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, Column, DateTime, ForeignKey, Integer,
                        String, Text, UniqueConstraint, create_engine)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker

DEFAULT_URL = "sqlite+pysqlite:///./redstackpro.db"


def new_id():
    return uuid.uuid4().hex


def now():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Org(Base):
    """The account boundary, not a sharing boundary. See 0009."""
    __tablename__ = "orgs"

    id = Column(String(32), primary_key=True, default=new_id)
    name = Column(String(200), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(String(32), primary_key=True, default=new_id)
    org_id = Column(String(32), ForeignKey("orgs.id"), nullable=False)
    email = Column(String(320), nullable=False, unique=True)
    # Unused in the POC, present because adding it later means touching every
    # query. No password column, ever: identity comes from upstream. See 0009.
    role = Column(String(16), nullable=False, default="member")
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class Topology(Base):
    """Identity, ownership, and a pointer to the current revision.

    owner_id is nullable so a system owned blueprint can exist without a
    migration when blueprints land.
    """
    __tablename__ = "topologies"

    id = Column(String(32), primary_key=True, default=new_id)
    org_id = Column(String(32), ForeignKey("orgs.id"), nullable=False)
    owner_id = Column(String(32), ForeignKey("users.id"), nullable=True)
    name = Column(String(200), nullable=False)
    mode = Column(String(16), nullable=False, default="artie")
    visibility = Column(String(16), nullable=False, default="private")
    schema_version = Column(String(16), nullable=False)
    # Compare and swap. Single user does not mean single writer: two tabs, or
    # the canvas and the agent harness, produce the same lost update.
    version = Column(Integer, nullable=False, default=1)
    current_revision_id = Column(String(32), nullable=True)
    is_blueprint = Column(Boolean, nullable=False, default=False)
    # The revision a blueprint serves to cloners, pinned at publish time so the
    # owner can keep editing the live topology without moving what the next clone
    # gets. Null on a topology that was never published. See 0028.
    published_revision_id = Column(String(32), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=now, onupdate=now,
                        nullable=False)

    revisions = relationship("TopologyRevision", back_populates="topology",
                             cascade="all, delete-orphan")


class TopologyRevision(Base):
    """Append only. The corpus migrations get tested against. See 0008."""
    __tablename__ = "topology_revisions"
    __table_args__ = (UniqueConstraint("topology_id", "version"),)

    id = Column(String(32), primary_key=True, default=new_id)
    topology_id = Column(String(32), ForeignKey("topologies.id"), nullable=False)
    version = Column(Integer, nullable=False)
    author_id = Column(String(32), nullable=True)
    document = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)

    topology = relationship("Topology", back_populates="revisions")


class IdempotencyKey(Base):
    """Anything that creates takes one. See architecture.md."""
    __tablename__ = "idempotency_keys"

    key = Column(String(200), primary_key=True)
    principal_id = Column(String(32), nullable=False)
    resource_id = Column(String(32), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class CompileResult(Base):
    """A compile is synchronous today. The archive endpoint reads this rather
    than recompiling, so the zip and the file map cannot disagree. See 0010."""
    __tablename__ = "compile_results"

    id = Column(String(32), primary_key=True, default=new_id)
    topology_id = Column(String(32), nullable=True)
    principal_id = Column(String(32), nullable=False)
    provider = Column(String(32), nullable=False)
    files = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


def make_engine(url=None):
    url = url or os.environ.get("REDSTACKPRO_DATABASE_URL", DEFAULT_URL)
    kwargs = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


def make_session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False,
                        future=True)
