"""Add case ownership and immutable audit history.

Revision ID: 0002_case_audit_ownership
Revises: 0001_baseline
Create Date: 2026-09-04
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_case_audit_ownership"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("cases", sa.Column("owner", sa.String(length=128), nullable=True))
    op.create_index("ix_cases_owner", "cases", ["owner"])

    op.create_table(
        "case_audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("previous_value", sa.String(length=512), nullable=False),
        sa.Column("new_value", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.case_id"]),
        sa.UniqueConstraint("event_id"),
    )
    op.create_index("ix_case_audit_events_case_id", "case_audit_events", ["case_id"])
    op.create_index(
        "ix_case_audit_events_event_type",
        "case_audit_events",
        ["event_type"],
    )
    op.create_index("ix_case_audit_events_actor", "case_audit_events", ["actor"])
    op.create_index(
        "ix_case_audit_events_created_at",
        "case_audit_events",
        ["created_at"],
    )


def downgrade():
    raise RuntimeError(
        "Downgrade would destroy case audit evidence and is intentionally disabled"
    )
