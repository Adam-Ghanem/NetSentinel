"""Add append-only structured case evidence.

Revision ID: 0003_case_structured_evidence
Revises: 0002_case_audit_ownership
Create Date: 2026-09-05
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_case_structured_evidence"
down_revision = "0002_case_audit_ownership"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "case_evidence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("evidence_id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=256), nullable=False),
        sa.Column("reference", sa.String(length=512), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("added_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.case_id"]),
        sa.UniqueConstraint("evidence_id"),
    )
    op.create_index("ix_case_evidence_case_id", "case_evidence", ["case_id"])
    op.create_index("ix_case_evidence_evidence_type", "case_evidence", ["evidence_type"])
    op.create_index("ix_case_evidence_added_by", "case_evidence", ["added_by"])
    op.create_index("ix_case_evidence_created_at", "case_evidence", ["created_at"])


def downgrade():
    raise RuntimeError(
        "Downgrade would destroy structured case evidence and is intentionally disabled"
    )
