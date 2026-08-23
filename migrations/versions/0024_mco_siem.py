"""Ajoute la configuration de l'export SIEM en mode pull.

Revision ID: 0024_mco_siem
Revises: 0023_image_lifecycle
"""

import sqlalchemy as sa
from alembic import op

revision = "0024_mco_siem"
down_revision = "0023_image_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "siem_configuration",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("pull_token_ciphertext", sa.Text(), nullable=False),
        sa.Column(
            "minimum_outcome",
            sa.String(length=16),
            nullable=False,
            server_default="all",
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_by_id", sa.Integer()),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("id = 1", name="ck_siem_configuration_singleton"),
        sa.CheckConstraint(
            "minimum_outcome IN ('all', 'failure', 'denied')",
            name="ck_siem_configuration_minimum_outcome",
        ),
        sa.ForeignKeyConstraint(["updated_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("siem_configuration")
