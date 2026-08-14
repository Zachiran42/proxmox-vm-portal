"""Dernière adresse réseau et archivage des demandes.

Revision ID: 0010_vm_details_archive
Revises: 0009_guest_password_policy
Create Date: 2026-08-14
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_vm_details_archive"
down_revision = "0009_guest_password_policy"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "vm_allocations",
        sa.Column("last_ipv4", sa.String(length=15), nullable=True),
    )
    op.add_column(
        "vm_allocations",
        sa.Column("network_observed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "vm_allocations",
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade():
    op.drop_column("vm_allocations", "archived_at")
    op.drop_column("vm_allocations", "network_observed_at")
    op.drop_column("vm_allocations", "last_ipv4")
