"""Notifications d'échéance des machines.

Revision ID: 0017_lifecycle_notifications
Revises: 0016_user_notifications
Create Date: 2026-08-21
"""

from alembic import op

revision = "0017_lifecycle_notifications"
down_revision = "0016_user_notifications"
branch_labels = None
depends_on = None

constraint_name = "ck_user_notifications_kind"
previous_constraint = (
    "kind IN ('approval_requested', 'approval_approved', "
    "'approval_rejected', 'provisioning_succeeded', "
    "'provisioning_failed', 'provisioning_attention')"
)
current_constraint = (
    "kind IN ('approval_requested', 'approval_approved', "
    "'approval_rejected', 'provisioning_succeeded', "
    "'provisioning_failed', 'provisioning_attention', "
    "'lifecycle_warning', 'lifecycle_expired')"
)


def upgrade():
    with op.batch_alter_table("user_notifications") as batch_op:
        batch_op.drop_constraint(constraint_name, type_="check")
        batch_op.create_check_constraint(constraint_name, current_constraint)


def downgrade():
    with op.batch_alter_table("user_notifications") as batch_op:
        batch_op.drop_constraint(constraint_name, type_="check")
        batch_op.create_check_constraint(constraint_name, previous_constraint)
