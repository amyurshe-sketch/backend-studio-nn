"""tighten users constraints

Revision ID: d998458dab79
Revises: a1b2c3d4e57
Create Date: 2025-11-10 18:45:16.406262

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd998458dab79'
down_revision: Union[str, None] = 'a1b2c3d4e57'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1) Ensure no NULLs before adding NOT NULL constraints
    op.execute("UPDATE users SET created_at = NOW() WHERE created_at IS NULL;")
    # If any names are NULL, assign a unique placeholder based on id
    op.execute("UPDATE users SET name = CONCAT('user_', id) WHERE name IS NULL;")

    # 2) Apply NOT NULL constraints
    op.alter_column('users', 'name', existing_type=sa.String(), nullable=False)
    op.alter_column('users', 'created_at', existing_type=sa.TIMESTAMP(timezone=False), nullable=False)

    # 3) Drop redundant index on id (PK already provides it)
    try:
        op.drop_index('ix_users_id', table_name='users')
    except Exception:
        # ignore if it doesn't exist
        pass


def downgrade() -> None:
    # Recreate the index if needed (optional)
    try:
        op.create_index('ix_users_id', 'users', ['id'])
    except Exception:
        pass
    # Allow NULLs again (reverse of upgrade)
    op.alter_column('users', 'created_at', existing_type=sa.TIMESTAMP(timezone=False), nullable=True)
    op.alter_column('users', 'name', existing_type=sa.String(), nullable=True)
