"""Ajoute la finalité de test et la preuve d'acceptation de la politique de données.

Revision ID: 0022_vm_usage_policy
Revises: 0021_network_connectivity
"""

import sqlalchemy as sa
from alembic import op

revision = "0022_vm_usage_policy"
down_revision = "0021_network_connectivity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "usage_purpose",
                sa.String(length=32),
                nullable=False,
                server_default="technical_test",
            )
        )
        batch_op.add_column(
            sa.Column(
                "data_policy_version",
                sa.String(length=40),
                nullable=False,
                server_default="legacy-unacknowledged",
            )
        )
        batch_op.add_column(
            sa.Column("data_policy_acknowledged_at", sa.DateTime(timezone=True))
        )
        batch_op.create_check_constraint(
            "ck_vm_allocations_usage_purpose",
            "usage_purpose IN ('technical_test', 'functional_test', 'training', 'security_test')",
        )


def downgrade() -> None:
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_constraint("ck_vm_allocations_usage_purpose", type_="check")
        batch_op.drop_column("data_policy_acknowledged_at")
        batch_op.drop_column("data_policy_version")
        batch_op.drop_column("usage_purpose")
