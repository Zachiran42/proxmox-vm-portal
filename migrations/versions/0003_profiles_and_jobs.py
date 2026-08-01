"""Profils d'images et file de provisionnement.

Revision ID: 0003_profiles_and_jobs
Revises: 0002_oidc_identities
Create Date: 2026-08-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_profiles_and_jobs"
down_revision = "0002_oidc_identities"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "image_profiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(length=63), nullable=False),
        sa.Column("label", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
        sa.Column("iso", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_constraint("ck_vm_allocations_status", type_="check")
        batch_op.create_check_constraint(
            "ck_vm_allocations_status",
            "status IN ('queued', 'provisioning', 'accepted', 'running', 'failed', 'deleted')",
        )
        batch_op.add_column(sa.Column("profile_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_vm_allocations_profile_id",
            "image_profiles",
            ["profile_id"],
            ["id"],
            ondelete="SET NULL",
        )
    op.create_table(
        "provisioning_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("allocation_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_by", sa.String(length=128), nullable=True),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'validating', 'submitting', 'submitted', 'polling', 'succeeded', 'failed', 'attention')",
            name="ck_provisioning_jobs_status",
        ),
        sa.ForeignKeyConstraint(
            ["allocation_id"], ["vm_allocations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("allocation_id"),
    )
    op.create_index(
        "ix_provisioning_jobs_status_available",
        "provisioning_jobs",
        ["status", "available_at"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        "ix_provisioning_jobs_status_available", table_name="provisioning_jobs"
    )
    op.drop_table("provisioning_jobs")
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_constraint("fk_vm_allocations_profile_id", type_="foreignkey")
        batch_op.drop_column("profile_id")
        batch_op.drop_constraint("ck_vm_allocations_status", type_="check")
        batch_op.create_check_constraint(
            "ck_vm_allocations_status",
            "status IN ('provisioning', 'accepted', 'running', 'failed', 'deleted')",
        )
    op.drop_table("image_profiles")
