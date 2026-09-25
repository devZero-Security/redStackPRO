"""blueprint publish pin

Adds graphs.published_revision_id: the revision a blueprint serves to cloners,
set at publish time. A blueprint used to be a moving target, cloning whatever the
owner's latest edit was; pinning lets the owner keep editing without changing what
the next clone gets. Nullable, because a graph that was never published has no
published revision, and every existing row predates the column. See 0028.

Revision ID: 0002_blueprint_pin
Revises: 0001_baseline
Create Date: 2026-08-15
"""
from alembic import op
import sqlalchemy as sa


revision = '0002_blueprint_pin'
down_revision = '0001_baseline'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('graphs',
                  sa.Column('published_revision_id', sa.String(length=32),
                            nullable=True))


def downgrade():
    op.drop_column('graphs', 'published_revision_id')
