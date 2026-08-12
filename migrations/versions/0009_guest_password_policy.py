"""Mot de passe invité choisi et politique administrable.

Revision ID: 0009_guest_password_policy
Revises: 0008_forced_password_change
Create Date: 2026-08-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_guest_password_policy"
down_revision = "0008_forced_password_change"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "portal_settings",
        sa.Column("key", sa.String(length=80), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.add_column(
        "provisioning_jobs",
        sa.Column("guest_password_ciphertext", sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_column("provisioning_jobs", "guest_password_ciphertext")
    op.drop_table("portal_settings")
