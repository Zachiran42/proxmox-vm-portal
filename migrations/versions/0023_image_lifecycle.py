"""Versionne les images et conserve leur version dans chaque allocation.

Revision ID: 0023_image_lifecycle
Revises: 0022_vm_usage_policy
"""

import sqlalchemy as sa
from alembic import op

revision = "0023_image_lifecycle"
down_revision = "0022_vm_usage_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("image_profiles") as batch_op:
        batch_op.add_column(
            sa.Column(
                "version", sa.String(length=64), nullable=False, server_default="legacy"
            )
        )
        batch_op.add_column(
            sa.Column(
                "lifecycle_status",
                sa.String(length=16),
                nullable=False,
                server_default="active",
            )
        )
        batch_op.add_column(sa.Column("supported_until", sa.Date()))
        batch_op.add_column(sa.Column("replacement_slug", sa.String(length=63)))
        batch_op.create_check_constraint(
            "ck_image_profiles_lifecycle_status",
            "lifecycle_status IN ('active', 'deprecated', 'retired')",
        )
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.add_column(sa.Column("image_profile_slug", sa.String(length=63)))
        batch_op.add_column(sa.Column("image_version", sa.String(length=64)))


def downgrade() -> None:
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_column("image_version")
        batch_op.drop_column("image_profile_slug")
    with op.batch_alter_table("image_profiles") as batch_op:
        batch_op.drop_constraint(
            "ck_image_profiles_lifecycle_status", type_="check"
        )
        batch_op.drop_column("replacement_slug")
        batch_op.drop_column("supported_until")
        batch_op.drop_column("lifecycle_status")
        batch_op.drop_column("version")
