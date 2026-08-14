"""Profils réseau VLAN et réservations NetBox.

Revision ID: 0012_network_profiles_netbox
Revises: 0011_network_and_ldap
Create Date: 2026-08-14
"""

import sqlalchemy as sa
from alembic import op

revision = "0012_network_profiles_netbox"
down_revision = "0011_network_and_ldap"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "network_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slug", sa.String(63), nullable=False, unique=True),
        sa.Column("label", sa.String(100), nullable=False),
        sa.Column("cidr", sa.String(18), nullable=False),
        sa.Column("gateway", sa.String(15), nullable=False),
        sa.Column("dns_servers", sa.String(64), nullable=False),
        sa.Column("bridge", sa.String(32), nullable=False, server_default="vmbr0"),
        sa.Column("vlan_tag", sa.Integer(), nullable=True),
        sa.Column("netbox_prefix_id", sa.Integer(), nullable=True),
        sa.Column("netbox_vrf_id", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("vlan_tag IS NULL OR (vlan_tag >= 1 AND vlan_tag <= 4094)", name="ck_network_profiles_vlan_tag"),
        sa.CheckConstraint("netbox_prefix_id IS NULL OR netbox_prefix_id > 0", name="ck_network_profiles_netbox_prefix"),
    )
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.add_column(sa.Column("network_profile_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("network_bridge", sa.String(32), nullable=True))
        batch_op.add_column(sa.Column("vlan_tag", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("netbox_ip_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("netbox_prefix_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("netbox_vrf_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_vm_allocations_network_profile",
            "network_profiles",
            ["network_profile_id"],
            ["id"],
            ondelete="RESTRICT",
        )


def downgrade():
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_constraint("fk_vm_allocations_network_profile", type_="foreignkey")
        batch_op.drop_column("netbox_ip_id")
        batch_op.drop_column("netbox_vrf_id")
        batch_op.drop_column("netbox_prefix_id")
        batch_op.drop_column("vlan_tag")
        batch_op.drop_column("network_bridge")
        batch_op.drop_column("network_profile_id")
    op.drop_table("network_profiles")
