"""Réinitialisation encadrée des mots de passe invités.

Revision ID: 0018_guest_password_reset
Revises: 0017_lifecycle_notifications
Create Date: 2026-08-21
"""

import sqlalchemy as sa
from alembic import op

revision = "0018_guest_password_reset"
down_revision = "0017_lifecycle_notifications"
branch_labels = None
depends_on = None

constraint_name = "ck_user_notifications_kind"
previous_constraint = (
    "kind IN ('approval_requested', 'approval_approved', "
    "'approval_rejected', 'provisioning_succeeded', "
    "'provisioning_failed', 'provisioning_attention', "
    "'lifecycle_warning', 'lifecycle_expired')"
)
current_constraint = (
    "kind IN ('approval_requested', 'approval_approved', "
    "'approval_rejected', 'provisioning_succeeded', "
    "'provisioning_failed', 'provisioning_attention', "
    "'lifecycle_warning', 'lifecycle_expired', "
    "'guest_password_reset_requested', "
    "'guest_password_reset_completed')"
)


def upgrade():
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "guest_password_reset_requested_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
    with op.batch_alter_table("user_notifications") as batch_op:
        batch_op.drop_constraint(constraint_name, type_="check")
        batch_op.create_check_constraint(constraint_name, current_constraint)


def downgrade():
    with op.batch_alter_table("user_notifications") as batch_op:
        batch_op.drop_constraint(constraint_name, type_="check")
        batch_op.create_check_constraint(constraint_name, previous_constraint)
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_column("guest_password_reset_requested_at")
