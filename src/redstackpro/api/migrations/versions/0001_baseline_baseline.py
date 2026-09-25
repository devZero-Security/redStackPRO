"""baseline

The schema as of 0008, 0009, and 0010: orgs and users for the account boundary,
graphs and append only graph_revisions for storage, idempotency_keys, and stored
compile_results. Columns that are unused in the POC but present so retrofitting
does not touch every query (owner_id, user.role) are here from the start, because
that was the point of adding them. See 0023.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-08-14
"""
from alembic import op
import sqlalchemy as sa


revision = '0001_baseline'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('compile_results',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('graph_id', sa.String(length=32), nullable=True),
    sa.Column('principal_id', sa.String(length=32), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('files', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('idempotency_keys',
    sa.Column('key', sa.String(length=200), nullable=False),
    sa.Column('principal_id', sa.String(length=32), nullable=False),
    sa.Column('resource_id', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('key')
    )
    op.create_table('orgs',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('org_id', sa.String(length=32), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['orgs.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('graphs',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('org_id', sa.String(length=32), nullable=False),
    sa.Column('owner_id', sa.String(length=32), nullable=True),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('mode', sa.String(length=16), nullable=False),
    sa.Column('visibility', sa.String(length=16), nullable=False),
    sa.Column('schema_version', sa.String(length=16), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('current_revision_id', sa.String(length=32), nullable=True),
    sa.Column('is_blueprint', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['orgs.id'], ),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('graph_revisions',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('graph_id', sa.String(length=32), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('author_id', sa.String(length=32), nullable=True),
    sa.Column('document', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['graph_id'], ['graphs.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('graph_id', 'version')
    )


def downgrade():
    op.drop_table('graph_revisions')
    op.drop_table('graphs')
    op.drop_table('users')
    op.drop_table('orgs')
    op.drop_table('idempotency_keys')
    op.drop_table('compile_results')
