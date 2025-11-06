# rss_crud.py
from sqlalchemy.orm import Session
from sqlalchemy import select
from datetime import datetime, timedelta, timezone
import rss_models as models
import rss_schemas as schemas

def upsert_rss_item(db: Session, data: schemas.RssItemCreate, model_class):
    """Дедуп по link для конкретной модели"""
    item = db.execute(
        select(model_class).where(model_class.link == str(data.link))
    ).scalar_one_or_none()

    if item is None:
        item = model_class(
            title=data.title,
            link=str(data.link),
            summary=data.summary,
            published_at=data.published_at,
            is_deleted=False,
        )
        db.add(item)
    else:
        # мягкое обновление
        item.title = data.title or item.title
        item.summary = data.summary if data.summary else item.summary
        item.published_at = data.published_at or item.published_at
        item.is_deleted = False

    db.commit()
    db.refresh(item)
    return item

def list_rss_items(db: Session, model_class, limit: int = 50):
    items = (
        db.query(model_class)
        .filter(model_class.is_deleted == False)
        .order_by(model_class.published_at.desc().nullslast(),
                  model_class.fetched_at.desc())
        .limit(limit)
        .all()
    )
    
    # Добавляем источник для фронтенда
    if model_class == models.CNewsRssItem:
        source_name = "CNews"
    elif model_class == models.HabrRssItem:
        source_name = "Habr"
    elif hasattr(models, 'WiredRssItem') and model_class == models.WiredRssItem:
        source_name = "Wired"
    elif hasattr(models, 'ArsTechnicaRssItem') and model_class == models.ArsTechnicaRssItem:
        source_name = "Ars Technica"
    else:
        source_name = "Unknown"
    for item in items:
        item.source = source_name
        
    return items

def list_all_rss_items(db: Session, limit: int = 50):
    """Получить новости из всех источников (текущие фронтенд-источники: CNews + Habr)"""
    cnews_items = (
        db.query(models.CNewsRssItem)
        .filter(models.CNewsRssItem.is_deleted == False)
        .all()
    )
    habr_items = (
        db.query(models.HabrRssItem)
        .filter(models.HabrRssItem.is_deleted == False)
        .all()
    )
    for item in cnews_items:
        item.source = "CNews"
    for item in habr_items:
        item.source = "Habr"
    all_items = cnews_items + habr_items
    all_items.sort(
        key=lambda x: (
            x.published_at if x.published_at else x.fetched_at,
            x.fetched_at
        ),
        reverse=True
    )
    
    return all_items[:limit]


def list_rss_items_for_sources(db: Session, sources: list, limit: int = 50):
    """Гибкая выборка для заданных моделей-источников (без изменения фронтенда)."""
    collected = []
    for model_class, source_name in sources:
        items = (
            db.query(model_class)
            .filter(model_class.is_deleted == False)
            .all()
        )
        for i in items:
            i.source = source_name
        collected.extend(items)
    collected.sort(
        key=lambda x: (
            x.published_at if x.published_at else x.fetched_at,
            x.fetched_at
        ),
        reverse=True
    )
    return collected[:limit]


# --- Fetch meta helpers ---
def get_fetch_meta(db: Session, source_key: str) -> models.RssFetchMeta | None:
    return db.execute(
        select(models.RssFetchMeta).where(models.RssFetchMeta.source_key == source_key)
    ).scalar_one_or_none()


def touch_fetch_meta(db: Session, source_key: str) -> models.RssFetchMeta:
    meta = get_fetch_meta(db, source_key)
    now = datetime.now(timezone.utc)
    if meta is None:
        meta = models.RssFetchMeta(source_key=source_key, last_fetched_at=now)
        db.add(meta)
    else:
        meta.last_fetched_at = now
    db.commit()
    db.refresh(meta)
    return meta


def needs_refresh(db: Session, source_key: str, min_age_hours: int = 24) -> bool:
    meta = get_fetch_meta(db, source_key)
    if meta is None:
        return True
    # Normalize to aware datetime if needed
    last = meta.last_fetched_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - last) >= timedelta(hours=min_age_hours)
