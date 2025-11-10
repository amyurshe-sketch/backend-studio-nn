"""merge heads to single head

Revision ID: a1b2c3d4e57
Revises: 0a1b2c3d4e56, 9e8f7d6c5b4a
Create Date: 2025-11-10 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e57'
down_revision: Union[str, Sequence[str], None] = ('0a1b2c3d4e56', '9e8f7d6c5b4a')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Merge point only, no schema changes.
    pass


def downgrade() -> None:
    # Typically, no-op; unmerging heads is not supported in simple downgrade.
    pass

