"""Add netskope_config table

Revision ID: 003
Revises: 002
Create Date: 2026-06-09

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "netskope_config",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant", sa.String(255)),
        sa.Column("scim_token", sa.String(500)),
        sa.Column("verify_ssl", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("netskope_config")
