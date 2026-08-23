"""Automatisation contrôlée du cycle de vie des VM.

Revision ID: 0020_lifecycle_enforcement
Revises: 0019_vm_maintenance_network
Create Date: 2026-08-21
"""

import sqlalchemy as sa
from alembic import op

revision = "0020_lifecycle_enforcement"
down_revision = "0019_vm_maintenance_network"
branch_labels = None
depends_on = None

constraint_name = "ck_user_notifications_kind"
previous_constraint = (
    "kind IN ('approval_requested', 'approval_approved', "
    "'approval_rejected', 'provisioning_succeeded', "
    "'provisioning_failed', 'provisioning_attention', "
    "'lifecycle_warning', 'lifecycle_expired', "
    "'guest_password_reset_requested', "
    "'guest_password_reset_completed')"
)
current_constraint = (
    "kind IN ('approval_requested', 'approval_approved', "
    "'approval_rejected', 'provisioning_succeeded', "
    "'provisioning_failed', 'provisioning_attention', "
    "'lifecycle_warning', 'lifecycle_expired', "
    "'lifecycle_quarantined', 'lifecycle_deletion_scheduled', "
    "'lifecycle_deleted', 'lifecycle_enforcement_failed', "
    "'guest_password_reset_requested', "
    "'guest_password_reset_completed')"
)


def upgrade():
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.add_column(
            sa.Column("lifecycle_quarantined_at", sa.DateTime(timezone=True))
        )
        batch_op.add_column(
            sa.Column("lifecycle_delete_after", sa.DateTime(timezone=True))
        )
        batch_op.add_column(
            sa.Column("lifecycle_enforcement_error", sa.String(length=80))
        )
    with op.batch_alter_table("user_notifications") as batch_op:
        batch_op.drop_constraint(constraint_name, type_="check")
        batch_op.create_check_constraint(constraint_name, current_constraint)


def downgrade():
    with op.batch_alter_table("user_notifications") as batch_op:
        batch_op.drop_constraint(constraint_name, type_="check")
        batch_op.create_check_constraint(constraint_name, previous_constraint)
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_column("lifecycle_enforcement_error")
        batch_op.drop_column("lifecycle_delete_after")
        batch_op.drop_column("lifecycle_quarantined_at")
