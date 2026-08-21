"""Centre de notifications internes.

Revision ID: 0016_user_notifications
Revises: 0015_vm_approval_workflow
Create Date: 2026-08-15
"""

import sqlalchemy as sa
from alembic import op

revision = "0016_user_notifications"
down_revision = "0015_vm_approval_workflow"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_notifications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("message", sa.String(length=1000), nullable=False),
        sa.Column("target_type", sa.String(length=32)),
        sa.Column("target_id", sa.String(length=64)),
        sa.Column("dedup_key", sa.String(length=160), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "kind IN ('approval_requested', 'approval_approved', "
            "'approval_rejected', 'provisioning_succeeded', "
            "'provisioning_failed', 'provisioning_attention')",
            name="ck_user_notifications_kind",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_id", "dedup_key", name="uq_user_notifications_user_dedup"
        ),
    )
    op.create_index(
        "ix_user_notifications_user_read_created",
        "user_notifications",
        ["user_id", "read_at", "created_at"],
    )


def downgrade():
    op.drop_index(
        "ix_user_notifications_user_read_created",
        table_name="user_notifications",
    )
    op.drop_table("user_notifications")
