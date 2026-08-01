"""Index de limitation des tentatives de connexion.

Revision ID: 0005_login_throttle_index
Revises: 0004_cloud_init_credentials
Create Date: 2026-08-01
"""

from alembic import op

revision = "0005_login_throttle_index"
down_revision = "0004_cloud_init_credentials"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "ix_audit_events_login_throttle",
        "audit_events",
        ["action", "target_id", "outcome", "created_at"],
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            """
            CREATE FUNCTION prevent_audit_event_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'audit_events is append-only';
            END;
            $$ LANGUAGE plpgsql
            """
        )
        op.execute(
            """
            CREATE TRIGGER audit_events_append_only
            BEFORE UPDATE OR DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION prevent_audit_event_mutation();
            """
        )


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER audit_events_append_only ON audit_events")
        op.execute("DROP FUNCTION prevent_audit_event_mutation()")
    op.drop_index("ix_audit_events_login_throttle", table_name="audit_events")
