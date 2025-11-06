# rss_bootstrap.py
from database import Base, engine
import rss_models  # noqa: F401 — важно импортировать, чтобы таблицы зарегистрировались
from rss_router import router as rss_router

def register_rss(app):
    # создадим таблицы, если миграции не используются
    Base.metadata.create_all(bind=engine)
    # подключим роутер
    app.include_router(rss_router)
