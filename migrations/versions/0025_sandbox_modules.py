"""Ajoute le confinement sandbox et le catalogue logiciel hors ligne.

Revision ID: 0025_sandbox_modules
Revises: 0024_mco_siem
"""

import sqlalchemy as sa
from alembic import op

revision = "0025_sandbox_modules"
down_revision = "0024_mco_siem"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("user_notifications") as batch_op:
        batch_op.drop_constraint("ck_user_notifications_kind", type_="check")
        batch_op.create_check_constraint(
            "ck_user_notifications_kind",
            "kind IN ('approval_requested', 'approval_approved', 'approval_rejected', "
            "'provisioning_succeeded', 'provisioning_failed', 'provisioning_attention', "
            "'lifecycle_warning', 'lifecycle_expired', 'lifecycle_quarantined', "
            "'lifecycle_deletion_scheduled', 'lifecycle_deleted', "
            "'lifecycle_enforcement_failed', 'guest_password_reset_requested', "
            "'guest_password_reset_completed', 'sandbox_release_requested', "
            "'sandbox_release_decided', 'sandbox_release_expired')",
        )
    with op.batch_alter_table("network_profiles") as batch_op:
        batch_op.drop_constraint("ck_network_profiles_connectivity_mode", type_="check")
        batch_op.create_check_constraint(
            "ck_network_profiles_connectivity_mode",
            "connectivity_mode IN ('sandbox', 'isolated', 'internal', 'internet', 'ticket_required')",
        )
        for name in (
            "sandbox_ssh_sources",
            "sandbox_ntp_servers",
            "sandbox_apt_endpoints",
            "sandbox_registry_endpoints",
            "sandbox_monitoring_endpoints",
        ):
            batch_op.add_column(
                sa.Column(name, sa.Text(), nullable=False, server_default="")
            )
        batch_op.add_column(
            sa.Column("sandbox_policy_revision", sa.Integer(), nullable=False, server_default="1")
        )

    op.create_table(
        "software_modules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(length=63), nullable=False),
        sa.Column("label", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("install_mode", sa.String(length=16), nullable=False),
        sa.Column("artifacts", sa.Text(), nullable=False, server_default=""),
        sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "install_mode IN ('preinstalled', 'apt', 'container')",
            name="ck_software_modules_install_mode",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )

    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_constraint("ck_vm_allocations_network_policy", type_="check")
        batch_op.create_check_constraint(
            "ck_vm_allocations_network_policy",
            "network_policy IN ('normal', 'sandbox', 'isolated')",
        )
        batch_op.add_column(sa.Column("network_policy_revision", sa.Integer()))
        batch_op.add_column(
            sa.Column("sandbox_release_status", sa.String(length=16), nullable=False, server_default="not_requested")
        )
        batch_op.add_column(sa.Column("sandbox_release_requested_at", sa.DateTime(timezone=True)))
        batch_op.add_column(sa.Column("sandbox_release_decided_at", sa.DateTime(timezone=True)))
        batch_op.add_column(sa.Column("sandbox_release_decided_by_id", sa.Integer()))
        batch_op.add_column(sa.Column("sandbox_release_reason", sa.String(length=500)))
        batch_op.add_column(sa.Column("sandbox_release_ticket", sa.String(length=100)))
        batch_op.add_column(sa.Column("sandbox_release_duration_hours", sa.Integer()))
        batch_op.add_column(sa.Column("sandbox_release_expires_at", sa.DateTime(timezone=True)))
        batch_op.add_column(
            sa.Column("software_modules", sa.JSON(), nullable=False, server_default="[]")
        )
        batch_op.create_check_constraint(
            "ck_vm_allocations_sandbox_release_status",
            "sandbox_release_status IN ('not_requested', 'pending', 'approved', 'rejected')",
        )
        batch_op.create_foreign_key(
            "fk_vm_allocations_sandbox_release_decided_by",
            "users",
            ["sandbox_release_decided_by_id"],
            ["id"],
            ondelete="SET NULL",
        )

    with op.batch_alter_table("provisioning_jobs") as batch_op:
        batch_op.drop_constraint("ck_provisioning_jobs_stage", type_="check")
        batch_op.create_check_constraint(
            "ck_provisioning_jobs_stage", "stage IN ('create', 'start', 'modules')"
        )
        batch_op.add_column(sa.Column("module_attempts", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("guest_pid", sa.Integer()))


def downgrade() -> None:
    with op.batch_alter_table("provisioning_jobs") as batch_op:
        batch_op.drop_column("guest_pid")
        batch_op.drop_column("module_attempts")
        batch_op.drop_constraint("ck_provisioning_jobs_stage", type_="check")
        batch_op.create_check_constraint("ck_provisioning_jobs_stage", "stage IN ('create', 'start')")
    with op.batch_alter_table("vm_allocations") as batch_op:
        batch_op.drop_constraint("fk_vm_allocations_sandbox_release_decided_by", type_="foreignkey")
        batch_op.drop_constraint("ck_vm_allocations_sandbox_release_status", type_="check")
        for name in (
            "software_modules", "sandbox_release_expires_at",
            "sandbox_release_duration_hours", "sandbox_release_ticket",
            "sandbox_release_reason", "sandbox_release_decided_by_id",
            "sandbox_release_decided_at", "sandbox_release_requested_at",
            "sandbox_release_status", "network_policy_revision",
        ):
            batch_op.drop_column(name)
        batch_op.drop_constraint("ck_vm_allocations_network_policy", type_="check")
        batch_op.create_check_constraint("ck_vm_allocations_network_policy", "network_policy IN ('normal', 'isolated')")
    op.drop_table("software_modules")
    with op.batch_alter_table("network_profiles") as batch_op:
        for name in (
            "sandbox_policy_revision", "sandbox_monitoring_endpoints",
            "sandbox_registry_endpoints", "sandbox_apt_endpoints",
            "sandbox_ntp_servers", "sandbox_ssh_sources",
        ):
            batch_op.drop_column(name)
        batch_op.drop_constraint("ck_network_profiles_connectivity_mode", type_="check")
        batch_op.create_check_constraint(
            "ck_network_profiles_connectivity_mode",
            "connectivity_mode IN ('isolated', 'internal', 'internet', 'ticket_required')",
        )
    with op.batch_alter_table("user_notifications") as batch_op:
        batch_op.drop_constraint("ck_user_notifications_kind", type_="check")
        batch_op.create_check_constraint(
            "ck_user_notifications_kind",
            "kind IN ('approval_requested', 'approval_approved', 'approval_rejected', "
            "'provisioning_succeeded', 'provisioning_failed', 'provisioning_attention', "
            "'lifecycle_warning', 'lifecycle_expired', 'lifecycle_quarantined', "
            "'lifecycle_deletion_scheduled', 'lifecycle_deleted', "
            "'lifecycle_enforcement_failed', 'guest_password_reset_requested', "
            "'guest_password_reset_completed')",
        )
