"""Profils cloud-init et remise des identifiants.

Revision ID: 0004_cloud_init_credentials
Revises: 0003_profiles_and_jobs
Create Date: 2026-08-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_cloud_init_credentials"
down_revision = "0003_profiles_and_jobs"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("image_profiles") as batch_op:
        batch_op.add_column(
            sa.Column(
                "source_type",
                sa.String(length=16),
                nullable=False,
                server_default="iso",
            )
        )
        batch_op.add_column(
            sa.Column("template_node", sa.String(length=63), nullable=True)
        )
        batch_op.add_column(sa.Column("template_vmid", sa.Integer(), nullable=True))
        batch_op.alter_column(
            "iso", existing_type=sa.String(length=255), nullable=True
        )
        batch_op.create_check_constraint(
            "ck_image_profiles_source",
            "(source_type = 'iso' AND iso IS NOT NULL AND template_node IS NULL "
            "AND template_vmid IS NULL) OR (source_type = 'cloud_init' AND "
            "iso IS NULL AND template_node IS NOT NULL AND template_vmid IS NOT NULL)",
        )
        batch_op.alter_column("source_type", server_default=None)

    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.alter_column(
            "iso", existing_type=sa.String(length=255), nullable=True
        )
        batch_op.add_column(sa.Column("vmid", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column("guest_username", sa.String(length=32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("credential_url", sa.String(length=1024), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "credential_created_at", sa.DateTime(timezone=True), nullable=True
            )
        )
        batch_op.add_column(
            sa.Column("credential_expire_days", sa.Integer(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("credential_expire_views", sa.Integer(), nullable=True)
        )

    with op.batch_alter_table("provisioning_jobs") as batch_op:
        batch_op.add_column(
            sa.Column(
                "stage",
                sa.String(length=16),
                nullable=False,
                server_default="create",
            )
        )
        batch_op.add_column(
            sa.Column(
                "credential_attempts", sa.Integer(), nullable=False, server_default="0"
            )
        )
        batch_op.add_column(
            sa.Column("upstream_node", sa.String(length=63), nullable=True)
        )
        batch_op.create_check_constraint(
            "ck_provisioning_jobs_stage", "stage IN ('create', 'start')"
        )
        batch_op.alter_column("stage", server_default=None)
        batch_op.alter_column("credential_attempts", server_default=None)


def downgrade():
    with op.batch_alter_table("provisioning_jobs") as batch_op:
        batch_op.drop_constraint("ck_provisioning_jobs_stage", type_="check")
        batch_op.drop_column("upstream_node")
        batch_op.drop_column("credential_attempts")
        batch_op.drop_column("stage")
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_column("credential_expire_views")
        batch_op.drop_column("credential_expire_days")
        batch_op.drop_column("credential_created_at")
        batch_op.drop_column("credential_url")
        batch_op.drop_column("guest_username")
        batch_op.drop_column("vmid")
        batch_op.alter_column(
            "iso", existing_type=sa.String(length=255), nullable=False
        )
    with op.batch_alter_table("image_profiles") as batch_op:
        batch_op.drop_constraint("ck_image_profiles_source", type_="check")
        batch_op.alter_column(
            "iso", existing_type=sa.String(length=255), nullable=False
        )
        batch_op.drop_column("template_vmid")
        batch_op.drop_column("template_node")
        batch_op.drop_column("source_type")
