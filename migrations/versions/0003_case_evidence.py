"""Add structured case evidence references.

Revision ID: 0003_case_evidence
Revises: 0002_case_audit_ownership
Create Date: 2026-09-04
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_case_evidence"
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
        sa.Column("reference", sa.String(length=2048), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("added_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.case_id"]),
        sa.UniqueConstraint("evidence_id"),
    )
    op.create_index("ix_case_evidence_case_id", "case_evidence", ["case_id"])
    op.create_index(
        "ix_case_evidence_evidence_type",
        "case_evidence",
        ["evidence_type"],
    )
    op.create_index("ix_case_evidence_sha256", "case_evidence", ["sha256"])
    op.create_index("ix_case_evidence_added_by", "case_evidence", ["added_by"])
    op.create_index("ix_case_evidence_created_at", "case_evidence", ["created_at"])


def downgrade():
    raise RuntimeError(
        "Downgrade would destroy case evidence references and is intentionally disabled"
    )
