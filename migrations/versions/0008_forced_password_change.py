"""Changement obligatoire du mot de passe initial.

Revision ID: 0008_forced_password_change
Revises: 0007_operations_supervision
Create Date: 2026-08-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_forced_password_change"
down_revision = "0007_operations_supervision"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade():
    op.drop_column("users", "must_change_password")
