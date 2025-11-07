# rss_bootstrap.py
from database import Base, engine
import rss_models  # noqa: F401 — важно импортировать, чтобы таблицы зарегистрировались
from rss_router import router as rss_router
import os

def register_rss(app):
    # В продакшне используем Alembic; автоматическое создание таблиц только при DEV_CREATE_ALL=true
    if os.getenv("DEV_CREATE_ALL", "false").lower() == "true":
        Base.metadata.create_all(bind=engine)
    # подключим роутер
    app.include_router(rss_router)
