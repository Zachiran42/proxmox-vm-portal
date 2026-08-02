"""Heartbeat des workers pour la supervision.

Revision ID: 0007_operations_supervision
Revises: 0006_vm_lifecycle
Create Date: 2026-08-02
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_operations_supervision"
down_revision = "0006_vm_lifecycle"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "worker_heartbeats",
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("worker_id"),
    )


def downgrade():
    op.drop_table("worker_heartbeats")
