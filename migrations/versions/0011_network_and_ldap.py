"""Configuration réseau cloud-init et identités LDAP.

Revision ID: 0011_network_and_ldap
Revises: 0010_vm_details_archive
Create Date: 2026-08-14
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_network_and_ldap"
down_revision = "0010_vm_details_archive"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "network_mode", sa.String(8), nullable=False, server_default="dhcp"
            )
        )
        batch_op.add_column(sa.Column("ipv4_cidr", sa.String(18), nullable=True))
        batch_op.add_column(sa.Column("gateway", sa.String(15), nullable=True))
        batch_op.add_column(sa.Column("dns_servers", sa.String(64), nullable=True))
        batch_op.alter_column("network_mode", server_default=None)
        batch_op.create_check_constraint(
            "ck_vm_allocations_network_mode",
            "network_mode IN ('dhcp', 'static')",
        )
        batch_op.create_check_constraint(
            "ck_vm_allocations_network_fields",
            "(network_mode = 'dhcp' AND ipv4_cidr IS NULL AND gateway IS NULL "
            "AND dns_servers IS NULL) OR "
            "(network_mode = 'static' AND ipv4_cidr IS NOT NULL "
            "AND gateway IS NOT NULL AND dns_servers IS NOT NULL)",
        )
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_auth_identity", type_="check")
        batch_op.drop_constraint("ck_users_auth_provider", type_="check")
        batch_op.create_check_constraint(
            "ck_users_auth_provider", "auth_provider IN ('local', 'oidc', 'ldap')"
        )
        batch_op.create_check_constraint(
            "ck_users_auth_identity",
            "(auth_provider = 'local' AND password_hash IS NOT NULL "
            "AND external_issuer IS NULL AND external_subject IS NULL) OR "
            "(auth_provider IN ('oidc', 'ldap') AND password_hash IS NULL "
            "AND external_issuer IS NOT NULL AND external_subject IS NOT NULL)",
        )


def downgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_auth_identity", type_="check")
        batch_op.drop_constraint("ck_users_auth_provider", type_="check")
        batch_op.create_check_constraint(
            "ck_users_auth_provider", "auth_provider IN ('local', 'oidc')"
        )
        batch_op.create_check_constraint(
            "ck_users_auth_identity",
            "(auth_provider = 'local' AND password_hash IS NOT NULL "
            "AND external_issuer IS NULL AND external_subject IS NULL) OR "
            "(auth_provider = 'oidc' AND password_hash IS NULL "
            "AND external_issuer IS NOT NULL AND external_subject IS NOT NULL)",
        )
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_constraint("ck_vm_allocations_network_fields", type_="check")
        batch_op.drop_constraint("ck_vm_allocations_network_mode", type_="check")
        batch_op.drop_column("dns_servers")
        batch_op.drop_column("gateway")
        batch_op.drop_column("ipv4_cidr")
        batch_op.drop_column("network_mode")
