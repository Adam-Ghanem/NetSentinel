"""Normalize the username lookup index to match application metadata.

Revision ID: 0004_users_username_index
Revises: 0003_case_structured_evidence
Create Date: 2026-09-05
"""

from alembic import op

revision = "0004_users_username_index"
down_revision = "0003_case_structured_evidence"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_index("ix_users_username", table_name="users")
    op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade():
    raise RuntimeError(
        "Downgrade would weaken the normalized username index and is intentionally disabled"
    )
