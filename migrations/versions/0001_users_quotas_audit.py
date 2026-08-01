"""Utilisateurs, quotas, allocations et audit.

Revision ID: 0001_users_quotas_audit
Revises:
Create Date: 2026-07-26
"""

import sqlalchemy as sa
from alembic import op

revision = "0001_users_quotas_audit"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=63), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("quota_vms", sa.Integer(), nullable=False),
        sa.Column("quota_cpu", sa.Integer(), nullable=False),
        sa.Column("quota_ram_mb", sa.Integer(), nullable=False),
        sa.Column("quota_disk_gb", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "role IN ('admin', 'operator', 'user')", name="ck_users_role"
        ),
        sa.CheckConstraint("quota_vms >= 0", name="ck_users_quota_vms"),
        sa.CheckConstraint("quota_cpu >= 0", name="ck_users_quota_cpu"),
        sa.CheckConstraint("quota_ram_mb >= 0", name="ck_users_quota_ram"),
        sa.CheckConstraint("quota_disk_gb >= 0", name="ck_users_quota_disk"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("target_type", sa.String(length=40), nullable=False),
        sa.Column("target_id", sa.String(length=255), nullable=True),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("request_id", sa.String(length=36), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('success', 'failure', 'denied')",
            name="ck_audit_events_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_audit_events_created_at", "audit_events", ["created_at"], unique=False
    )
    op.create_table(
        "vm_allocations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=63), nullable=False),
        sa.Column("node", sa.String(length=63), nullable=False),
        sa.Column("iso", sa.String(length=255), nullable=False),
        sa.Column("cpu", sa.Integer(), nullable=False),
        sa.Column("ram_mb", sa.Integer(), nullable=False),
        sa.Column("disk_gb", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("upstream_request_id", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('provisioning', 'accepted', 'running', 'failed', 'deleted')",
            name="ck_vm_allocations_status",
        ),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "owner_id", "name", name="uq_vm_allocations_owner_name"
        ),
    )
    op.create_index(
        "ix_vm_allocations_owner_status",
        "vm_allocations",
        ["owner_id", "status"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        "ix_vm_allocations_owner_status", table_name="vm_allocations"
    )
    op.drop_table("vm_allocations")
    op.drop_index("ix_audit_events_created_at", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_table("users")
