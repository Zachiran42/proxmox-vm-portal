"""Ajoute la politique de connectivité aux profils réseau.

Revision ID: 0021_network_connectivity
Revises: 0020_lifecycle_enforcement
"""

import sqlalchemy as sa
from alembic import op

revision = "0021_network_connectivity"
down_revision = "0020_lifecycle_enforcement"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("network_profiles") as batch_op:
        batch_op.add_column(
            sa.Column(
                "connectivity_mode",
                sa.String(length=32),
                nullable=False,
                server_default="internal",
            )
        )
        batch_op.add_column(
            sa.Column(
                "connectivity_description",
                sa.String(length=300),
                nullable=False,
                server_default="",
            )
        )
        batch_op.create_check_constraint(
            "ck_network_profiles_connectivity_mode",
            "connectivity_mode IN ('isolated', 'internal', 'internet', 'ticket_required')",
        )


def downgrade() -> None:
    with op.batch_alter_table("network_profiles") as batch_op:
        batch_op.drop_constraint(
            "ck_network_profiles_connectivity_mode", type_="check"
        )
        batch_op.drop_column("connectivity_description")
        batch_op.drop_column("connectivity_mode")
