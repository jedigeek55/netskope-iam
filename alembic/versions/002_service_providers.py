"""Add service_providers table

Revision ID: 002
Revises: 001
Create Date: 2026-06-08

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NAME_ID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"


def upgrade() -> None:
    op.create_table(
        "service_providers",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("entity_id", sa.String(500), nullable=False, unique=True),
        sa.Column("acs_url", sa.String(500), nullable=False),
        sa.Column("slo_url", sa.String(500)),
        sa.Column(
            "name_id_format",
            sa.String(255),
            nullable=False,
            server_default=NAME_ID_EMAIL,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("sp_cert", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("service_providers")
