"""File persistante pour le cycle de vie des VM.

Revision ID: 0006_vm_lifecycle
Revises: 0005_login_throttle_index
Create Date: 2026-08-02
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_vm_lifecycle"
down_revision = "0005_login_throttle_index"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_constraint("ck_vm_allocations_status", type_="check")
        batch_op.create_check_constraint(
            "ck_vm_allocations_status",
            "status IN ('queued', 'provisioning', 'accepted', 'running', "
            "'stopped', 'failed', 'deleted')",
        )

    op.create_table(
        "vm_operations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("allocation_id", sa.String(length=36), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("upstream_node", sa.String(length=63), nullable=True),
        sa.Column("upstream_request_id", sa.String(length=255), nullable=True),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_by", sa.String(length=128), nullable=True),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "action IN ('start', 'stop', 'reboot', 'delete')",
            name="ck_vm_operations_action",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'submitting', 'submitted', 'polling', "
            "'succeeded', 'failed', 'attention')",
            name="ck_vm_operations_status",
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["allocation_id"], ["vm_allocations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_vm_operations_status_available",
        "vm_operations",
        ["status", "available_at"],
    )
    op.create_index(
        "uq_vm_operations_active_allocation",
        "vm_operations",
        ["allocation_id"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('queued', 'submitting', 'submitted', 'polling')"
        ),
        sqlite_where=sa.text(
            "status IN ('queued', 'submitting', 'submitted', 'polling')"
        ),
    )


def downgrade():
    op.drop_index(
        "uq_vm_operations_active_allocation", table_name="vm_operations"
    )
    op.drop_index("ix_vm_operations_status_available", table_name="vm_operations")
    op.drop_table("vm_operations")
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_constraint("ck_vm_allocations_status", type_="check")
        batch_op.create_check_constraint(
            "ck_vm_allocations_status",
            "status IN ('queued', 'provisioning', 'accepted', 'running', "
            "'failed', 'deleted')",
        )
