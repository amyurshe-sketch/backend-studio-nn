"""seed quotes (en/ru) from JSON files

Revision ID: 0a1b2c3d4e56
Revises: 05f5764b7cd4
Create Date: 2025-11-10 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from pathlib import Path
import json


# revision identifiers, used by Alembic.
revision: str = '0a1b2c3d4e56'
down_revision: Union[str, None] = '05f5764b7cd4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _load_json(filename: str):
    base = Path(__file__).resolve().parent.parent  # alembic/
    path = (base / 'seeds' / filename).resolve()
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    def ensure_table(name: str):
        if name not in inspector.get_table_names():
            if name == 'quotes':
                op.create_table(
                    'quotes',
                    sa.Column('id', sa.Integer, primary_key=True),
                    sa.Column('text', sa.Text, nullable=False),
                    sa.Column('author', sa.String),
                )
            elif name == 'quotes_ru':
                op.create_table(
                    'quotes_ru',
                    sa.Column('id', sa.Integer, primary_key=True),
                    sa.Column('text', sa.Text, nullable=False),
                    sa.Column('author', sa.String),
                )

    # Ensure tables exist (idempotent)
    ensure_table('quotes')
    # refresh inspector cache as schema changed
    inspector = sa.inspect(conn)
    ensure_table('quotes_ru')

    # Ensure unique constraints exist (idempotent)
    try:
        uqs = {c.get('name') for c in inspector.get_unique_constraints('quotes')}
        if 'uq_quotes_text' not in uqs:
            op.create_unique_constraint('uq_quotes_text', 'quotes', ['text'])
    except Exception:
        pass
    inspector = sa.inspect(conn)
    try:
        uqs_ru = {c.get('name') for c in inspector.get_unique_constraints('quotes_ru')}
        if 'uq_quotes_ru_text' not in uqs_ru:
            op.create_unique_constraint('uq_quotes_ru_text', 'quotes_ru', ['text'])
    except Exception:
        pass

    meta = sa.MetaData()
    quotes = sa.Table('quotes', meta,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('text', sa.Text, nullable=False),
        sa.Column('author', sa.String),
    )
    quotes_ru = sa.Table('quotes_ru', meta,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('text', sa.Text, nullable=False),
        sa.Column('author', sa.String),
    )

    # Load seeds
    try:
        en_items = _load_json('quotes_en.json')
    except Exception:
        en_items = []
    try:
        ru_items = _load_json('quotes_ru.json')
    except Exception:
        ru_items = []

    # Insert EN quotes idempotently
    if en_items:
        existing = {row[0] for row in conn.execute(sa.text('SELECT text FROM quotes'))}
        rows = [dict(text=i['text'], author=i.get('author')) for i in en_items if i.get('text') and i['text'] not in existing]
        if rows:
            op.bulk_insert(quotes, rows)

    # Insert RU quotes idempotently
    if ru_items:
        existing_ru = {row[0] for row in conn.execute(sa.text('SELECT text FROM quotes_ru'))}
        rows_ru = [dict(text=i['text'], author=i.get('author')) for i in ru_items if i.get('text') and i['text'] not in existing_ru]
        if rows_ru:
            op.bulk_insert(quotes_ru, rows_ru)


def downgrade() -> None:
    # Usually we don't delete seeded data on downgrade.
    pass
