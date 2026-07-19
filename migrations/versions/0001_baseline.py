"""Create the initial NetSentinel schema.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-07-19
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.String(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=True),
        sa.Column("source_ip", sa.String(), nullable=True),
        sa.Column("dest_ip", sa.String(), nullable=True),
        sa.Column("alert_type", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("recommended_action", sa.Text(), nullable=True),
        sa.Column("mitre_attack", sa.String(), nullable=True),
        sa.UniqueConstraint("alert_id"),
    )
    op.create_index("ix_alerts_alert_type", "alerts", ["alert_type"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_source_ip", "alerts", ["source_ip"])
    op.create_index("ix_alerts_dest_ip", "alerts", ["dest_ip"])
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])

    op.create_table(
        "packets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(), nullable=True),
        sa.Column("source_mac", sa.String(), nullable=True),
        sa.Column("dest_mac", sa.String(), nullable=True),
        sa.Column("source_ip", sa.String(), nullable=True),
        sa.Column("dest_ip", sa.String(), nullable=True),
        sa.Column("protocol", sa.String(), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("dest_port", sa.Integer(), nullable=True),
        sa.Column("packet_size", sa.Integer(), nullable=True),
        sa.Column("tcp_flags", sa.String(), nullable=True),
        sa.Column("dns_query", sa.String(), nullable=True),
        sa.Column("http_host", sa.String(), nullable=True),
        sa.Column("http_path", sa.String(), nullable=True),
        sa.Column("payload_raw", sa.Text(), nullable=True),
        sa.Column("payload_printable", sa.Text(), nullable=True),
        sa.Column("tls_version", sa.String(), nullable=True),
        sa.Column("ja3_hash", sa.String(), nullable=True),
    )
    op.create_index("ix_packets_dest_ip", "packets", ["dest_ip"])
    op.create_index("ix_packets_ja3_hash", "packets", ["ja3_hash"])
    op.create_index("ix_packets_source_ip", "packets", ["source_ip"])
    op.create_index("ix_packets_timestamp", "packets", ["timestamp"])

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=True),
        sa.UniqueConstraint("username"),
    )
    op.create_index("ix_users_username", "users", ["username"])

    op.create_table(
        "cases",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("alert_id", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("tags", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.alert_id"]),
        sa.UniqueConstraint("case_id"),
    )
    op.create_index("ix_cases_severity", "cases", ["severity"])
    op.create_index("ix_cases_status", "cases", ["status"])

    op.create_table(
        "netsentinel_schema",
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("applied_at", sa.DateTime(), server_default=sa.func.current_timestamp(), nullable=False),
        sa.PrimaryKeyConstraint("version"),
    )
    op.execute("INSERT INTO netsentinel_schema (version) VALUES (1)")


def downgrade():
    raise RuntimeError("Destructive downgrade of the baseline schema is intentionally disabled")
