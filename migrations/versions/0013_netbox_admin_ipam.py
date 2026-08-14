"""Configuration NetBox administrable et plages IPAM.

Revision ID: 0013_netbox_admin_ipam
Revises: 0012_network_profiles_netbox
Create Date: 2026-08-14
"""

import sqlalchemy as sa
from alembic import op

revision = "0013_netbox_admin_ipam"
down_revision = "0012_network_profiles_netbox"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "netbox_configuration",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("base_url", sa.String(512), nullable=False),
        sa.Column("api_token_ciphertext", sa.Text(), nullable=False),
        sa.Column("ca_certificate", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_by_id", sa.Integer(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_netbox_configuration_singleton"),
        sa.ForeignKeyConstraint(
            ["updated_by_id"], ["users.id"], ondelete="SET NULL"
        ),
    )
    op.create_table(
        "proxmox_configuration",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("api_url", sa.String(512), nullable=False),
        sa.Column("token_id", sa.String(255), nullable=False),
        sa.Column("token_secret_ciphertext", sa.Text(), nullable=False),
        sa.Column("ca_certificate", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_by_id", sa.Integer(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_proxmox_configuration_singleton"),
        sa.ForeignKeyConstraint(
            ["updated_by_id"], ["users.id"], ondelete="SET NULL"
        ),
    )
    with op.batch_alter_table("network_profiles") as batch_op:
        batch_op.add_column(sa.Column("pool_start", sa.String(15), nullable=True))
        batch_op.add_column(sa.Column("pool_end", sa.String(15), nullable=True))
        batch_op.add_column(
            sa.Column("excluded_ips", sa.String(1024), nullable=False, server_default="")
        )
        batch_op.add_column(
            sa.Column(
                "allow_manual_ip", sa.Boolean(), nullable=False, server_default=sa.true()
            )
        )
        batch_op.add_column(
            sa.Column(
                "allow_automatic_ip",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.create_check_constraint(
            "ck_network_profiles_ip_assignment",
            "allow_manual_ip = true OR allow_automatic_ip = true",
        )
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "automatic_ip", sa.Boolean(), nullable=False, server_default=sa.false()
            )
        )


def downgrade():
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_column("automatic_ip")
    with op.batch_alter_table("network_profiles") as batch_op:
        batch_op.drop_constraint(
            "ck_network_profiles_ip_assignment", type_="check"
        )
        batch_op.drop_column("allow_automatic_ip")
        batch_op.drop_column("allow_manual_ip")
        batch_op.drop_column("excluded_ips")
        batch_op.drop_column("pool_end")
        batch_op.drop_column("pool_start")
    op.drop_table("proxmox_configuration")
    op.drop_table("netbox_configuration")
