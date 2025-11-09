"""email nullable; tg columns

Revision ID: 05f5764b7cd4
Revises: 006e7d995c28
Create Date: 2025-11-09 11:39:02.761529

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '05f5764b7cd4'
down_revision: Union[str, None] = '006e7d995c28'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
