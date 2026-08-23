"""Maintenance APT et isolation réseau des VM.

Revision ID: 0019_vm_maintenance_network
Revises: 0018_guest_password_reset
Create Date: 2026-08-21
"""

import sqlalchemy as sa
from alembic import op

revision = "0019_vm_maintenance_network"
down_revision = "0018_guest_password_reset"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "network_policy",
                sa.String(length=16),
                nullable=False,
                server_default="normal",
            )
        )
        batch_op.add_column(
            sa.Column("network_policy_updated_at", sa.DateTime(timezone=True))
        )
        batch_op.create_check_constraint(
            "ck_vm_allocations_network_policy",
            "network_policy IN ('normal', 'isolated')",
        )
        batch_op.alter_column("network_policy", server_default=None)

    op.create_table(
        "vm_maintenance_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("allocation_id", sa.String(length=36), nullable=False),
        sa.Column("actor_user_id", sa.Integer()),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("guest_pid", sa.Integer()),
        sa.Column("report", sa.JSON()),
        sa.Column("output_excerpt", sa.Text()),
        sa.Column("error_code", sa.String(length=80)),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_at", sa.DateTime(timezone=True)),
        sa.Column("locked_by", sa.String(length=128)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "action IN ('scan', 'update')",
            name="ck_vm_maintenance_jobs_action",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'submitting', 'submitted', 'succeeded', "
            "'failed', 'attention')",
            name="ck_vm_maintenance_jobs_status",
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
        "ix_vm_maintenance_jobs_status_available",
        "vm_maintenance_jobs",
        ["status", "available_at"],
    )
    op.create_index(
        "uq_vm_maintenance_jobs_active_allocation",
        "vm_maintenance_jobs",
        ["allocation_id"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('queued', 'submitting', 'submitted')"
        ),
        sqlite_where=sa.text(
            "status IN ('queued', 'submitting', 'submitted')"
        ),
    )


def downgrade():
    op.drop_index(
        "uq_vm_maintenance_jobs_active_allocation",
        table_name="vm_maintenance_jobs",
    )
    op.drop_index(
        "ix_vm_maintenance_jobs_status_available",
        table_name="vm_maintenance_jobs",
    )
    op.drop_table("vm_maintenance_jobs")
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_constraint("ck_vm_allocations_network_policy", type_="check")
        batch_op.drop_column("network_policy_updated_at")
        batch_op.drop_column("network_policy")
