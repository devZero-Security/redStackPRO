"""topology rename

Renames the graph tables and columns to topology: graphs -> topologies,
graph_revisions -> topology_revisions, and graph_id -> topology_id on
topology_revisions and compile_results. The object the canvas builds is a
topology, so the storage vocabulary follows the code. batch_alter_table is used
so the column renames work on SQLite too, where the table is recreated. See 0023.

Revision ID: 0003_topology_rename
Revises: 0002_blueprint_pin
Create Date: 2026-09-25
"""
from alembic import op


revision = '0003_topology_rename'
down_revision = '0002_blueprint_pin'
branch_labels = None
depends_on = None


def upgrade():
    op.rename_table('graphs', 'topologies')
    op.rename_table('graph_revisions', 'topology_revisions')
    with op.batch_alter_table('topology_revisions') as batch_op:
        batch_op.alter_column('graph_id', new_column_name='topology_id')
    with op.batch_alter_table('compile_results') as batch_op:
        batch_op.alter_column('graph_id', new_column_name='topology_id')


def downgrade():
    with op.batch_alter_table('compile_results') as batch_op:
        batch_op.alter_column('topology_id', new_column_name='graph_id')
    with op.batch_alter_table('topology_revisions') as batch_op:
        batch_op.alter_column('topology_id', new_column_name='graph_id')
    op.rename_table('topology_revisions', 'graph_revisions')
    op.rename_table('topologies', 'graphs')
