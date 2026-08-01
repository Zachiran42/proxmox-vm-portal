"""Identités OIDC fédérées.

Revision ID: 0002_oidc_identities
Revises: 0001_users_quotas_audit
Create Date: 2026-08-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_oidc_identities"
down_revision = "0001_users_quotas_audit"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "username",
            existing_type=sa.String(length=63),
            type_=sa.String(length=128),
            existing_nullable=False,
        )
        batch_op.alter_column(
            "password_hash",
            existing_type=sa.String(length=512),
            nullable=True,
        )
        batch_op.add_column(
            sa.Column(
                "auth_provider",
                sa.String(length=16),
                nullable=False,
                server_default="local",
            )
        )
        batch_op.add_column(
            sa.Column("external_issuer", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column("external_subject", sa.String(length=255), nullable=True)
        )
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
        batch_op.create_unique_constraint(
            "uq_users_external_identity", ["external_issuer", "external_subject"]
        )
        batch_op.alter_column("auth_provider", server_default=None)


def downgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("uq_users_external_identity", type_="unique")
        batch_op.drop_constraint("ck_users_auth_identity", type_="check")
        batch_op.drop_constraint("ck_users_auth_provider", type_="check")
        batch_op.drop_column("external_subject")
        batch_op.drop_column("external_issuer")
        batch_op.drop_column("auth_provider")
        batch_op.alter_column(
            "password_hash",
            existing_type=sa.String(length=512),
            nullable=False,
        )
        batch_op.alter_column(
            "username",
            existing_type=sa.String(length=128),
            type_=sa.String(length=63),
            existing_nullable=False,
        )
