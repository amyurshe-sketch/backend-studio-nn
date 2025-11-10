"""add created_at to quotes tables if missing

Revision ID: b0c1d2e3f45
Revises: d998458dab79
Create Date: 2025-11-10 19:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b0c1d2e3f45'
down_revision: Union[str, None] = 'd998458dab79'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(inspector, table: str, column: str) -> bool:
    try:
        cols = inspector.get_columns(table)
    except Exception:
        return False
    return any(c.get('name') == column for c in cols)


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    # quotes.created_at
    if 'quotes' in insp.get_table_names():
        if not _has_column(insp, 'quotes', 'created_at'):
            op.add_column('quotes', sa.Column('created_at', sa.TIMESTAMP(timezone=False), server_default=sa.func.now(), nullable=False))
            # Optional: remove server_default after backfilling (keep it simple and leave as is)

    # quotes_ru.created_at
    if 'quotes_ru' in insp.get_table_names():
        if not _has_column(insp, 'quotes_ru', 'created_at'):
            op.add_column('quotes_ru', sa.Column('created_at', sa.TIMESTAMP(timezone=False), server_default=sa.func.now(), nullable=False))


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'quotes_ru' in insp.get_table_names() and _has_column(insp, 'quotes_ru', 'created_at'):
        try:
            op.drop_column('quotes_ru', 'created_at')
        except Exception:
            pass
    if 'quotes' in insp.get_table_names() and _has_column(insp, 'quotes', 'created_at'):
        try:
            op.drop_column('quotes', 'created_at')
        except Exception:
            pass

