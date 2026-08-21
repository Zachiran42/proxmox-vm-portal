"""Circuit optionnel d'approbation des demandes de VM.

Revision ID: 0015_vm_approval_workflow
Revises: 0014_vm_lifecycle_mco
Create Date: 2026-08-15
"""

import sqlalchemy as sa
from alembic import op

revision = "0015_vm_approval_workflow"
down_revision = "0014_vm_lifecycle_mco"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_constraint("ck_vm_allocations_status", type_="check")
        batch_op.create_check_constraint(
            "ck_vm_allocations_status",
            "status IN ('pending_approval', 'queued', 'provisioning', 'accepted', "
            "'running', 'stopped', 'rejected', 'failed', 'deleted')",
        )
        batch_op.add_column(
            sa.Column(
                "approval_status",
                sa.String(length=16),
                nullable=False,
                server_default="not_required",
            )
        )
        batch_op.add_column(sa.Column("approval_requested_at", sa.DateTime(timezone=True)))
        batch_op.add_column(sa.Column("approval_decided_at", sa.DateTime(timezone=True)))
        batch_op.add_column(sa.Column("approval_decided_by_id", sa.Integer()))
        batch_op.add_column(sa.Column("approval_reason", sa.String(length=500)))
        batch_op.create_check_constraint(
            "ck_vm_allocations_approval_status",
            "approval_status IN ('not_required', 'pending', 'approved', 'rejected')",
        )
        batch_op.create_foreign_key(
            "fk_vm_allocations_approval_decided_by",
            "users",
            ["approval_decided_by_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_vm_allocations_approval_status", ["approval_status"]
        )

    with op.batch_alter_table("provisioning_jobs") as batch_op:
        batch_op.drop_constraint("ck_provisioning_jobs_status", type_="check")
        batch_op.create_check_constraint(
            "ck_provisioning_jobs_status",
            "status IN ('approval_pending', 'queued', 'validating', 'submitting', "
            "'submitted', 'polling', 'succeeded', 'failed', 'attention')",
        )


def downgrade():
    with op.batch_alter_table("provisioning_jobs") as batch_op:
        batch_op.drop_constraint("ck_provisioning_jobs_status", type_="check")
        batch_op.create_check_constraint(
            "ck_provisioning_jobs_status",
            "status IN ('queued', 'validating', 'submitting', 'submitted', "
            "'polling', 'succeeded', 'failed', 'attention')",
        )

    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_index("ix_vm_allocations_approval_status")
        batch_op.drop_constraint(
            "fk_vm_allocations_approval_decided_by", type_="foreignkey"
        )
        batch_op.drop_constraint(
            "ck_vm_allocations_approval_status", type_="check"
        )
        batch_op.drop_column("approval_reason")
        batch_op.drop_column("approval_decided_by_id")
        batch_op.drop_column("approval_decided_at")
        batch_op.drop_column("approval_requested_at")
        batch_op.drop_column("approval_status")
        batch_op.drop_constraint("ck_vm_allocations_status", type_="check")
        batch_op.create_check_constraint(
            "ck_vm_allocations_status",
            "status IN ('queued', 'provisioning', 'accepted', 'running', "
            "'stopped', 'failed', 'deleted')",
        )
