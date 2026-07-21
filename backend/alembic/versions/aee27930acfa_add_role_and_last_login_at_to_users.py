"""add role and last_login_at to users

Revision ID: aee27930acfa
Revises: 11480bac1122
Create Date: 2026-07-22 00:32:14.305515
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers
revision: str = "aee27930acfa"
down_revision: Union[str, Sequence[str], None] = "11480bac1122"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create PostgreSQL ENUM type
    user_role_enum = postgresql.ENUM(
        "USER",
        "ADMIN",
        name="user_role",
        create_type=True,
    )

    user_role_enum.create(op.get_bind(), checkfirst=True)

    # Add role column
    op.add_column(
        "users",
        sa.Column(
            "role",
            user_role_enum,
            nullable=False,
            server_default="USER",
        ),
    )

    # Add last_login_at column
    op.add_column(
        "users",
        sa.Column(
            "last_login_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # Remove default after existing rows are populated
    op.alter_column(
        "users",
        "role",
        server_default=None,
    )


def downgrade() -> None:
    op.drop_column("users", "last_login_at")
    op.drop_column("users", "role")

    user_role_enum = postgresql.ENUM(
        "USER",
        "ADMIN",
        name="user_role",
    )

    user_role_enum.drop(op.get_bind(), checkfirst=True)