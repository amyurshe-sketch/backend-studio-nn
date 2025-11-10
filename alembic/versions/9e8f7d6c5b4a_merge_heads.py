"""merge heads (stub to satisfy missing revision on prod)

Revision ID: 9e8f7d6c5b4a
Revises: 05f5764b7cd4
Create Date: 2025-11-09 00:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9e8f7d6c5b4a'
down_revision: Union[str, None] = '05f5764b7cd4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # No-op merge stub to bridge missing revision in prod.
    pass


def downgrade() -> None:
    # No-op.
    pass

