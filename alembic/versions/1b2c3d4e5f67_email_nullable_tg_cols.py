"""email nullable; tg columns

Revision ID: 1b2c3d4e5f67
Revises: 006e7d995c28
Create Date: 2025-11-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1b2c3d4e5f67'
down_revision: Union[str, None] = '006e7d995c28'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Make email nullable (safe if already nullable)
    try:
        op.alter_column('users', 'email', existing_type=sa.VARCHAR(), nullable=True)
    except Exception:
        pass

    # Add Telegram columns if missing
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_id BIGINT")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_username VARCHAR")

    # Unique index on telegram_id (safe if it already exists)
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_telegram_id_key ON users (telegram_id)")


def downgrade() -> None:
    # Drop unique index and telegram columns (use IF EXISTS for safety)
    op.execute("DROP INDEX IF EXISTS users_telegram_id_key")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS telegram_username")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS telegram_id")

    # Optionally, revert email to NOT NULL (may fail if nulls exist)
    try:
        op.alter_column('users', 'email', existing_type=sa.VARCHAR(), nullable=False)
    except Exception:
        pass

