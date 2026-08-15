"""Échéances et supervision du cycle de vie des VM.

Revision ID: 0014_vm_lifecycle_mco
Revises: 0013_netbox_admin_ipam
Create Date: 2026-08-15
"""

import sqlalchemy as sa
from alembic import op

revision = "0014_vm_lifecycle_mco"
down_revision = "0013_netbox_admin_ipam"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.add_column(sa.Column("expires_at", sa.DateTime(timezone=True)))
        batch_op.create_index("ix_vm_allocations_expires_at", ["expires_at"])


def downgrade():
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_index("ix_vm_allocations_expires_at")
        batch_op.drop_column("expires_at")
