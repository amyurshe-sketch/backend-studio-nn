# rss_router.py
from fastapi import APIRouter, Depends, BackgroundTasks, Query, HTTPException, Request
from sqlalchemy.orm import Session
import feedparser
from dateutil import parser as dtparse

from database import get_db
import rss_crud as crud
import rss_schemas as schemas
import rss_models as models
import os
import time
from collections import deque
from typing import Dict, List

router = APIRouter(prefix="/rss", tags=["rss"])

# Simple per-process IP rate limit for RSS endpoints
_RL: Dict[str, deque] = {}

def _allow(key: str, limit: int, window_sec: int) -> bool:
    now = time.time()
    dq = _RL.get(key)
    if dq is None:
        dq = deque()
        _RL[key] = dq
    cutoff = now - window_sec
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) >= limit:
        return False
    dq.append(now)
    return True

# Конфигурация RSS-источников
RSS_SOURCES = {
    "cnews": {
        "url": "https://www.cnews.ru/inc/rss/news.xml",
        "name": "CNews",
        "model": models.CNewsRssItem
    },
    "habr": {
        "url": "https://habr.com/ru/rss/",
        "name": "Habr", 
        "model": models.HabrRssItem
    },
    "wired": {
        "url": "https://www.wired.com/feed/rss",
        "name": "Wired",
        "model": models.WiredRssItem
    },
    "ars": {
        "url": "https://feeds.arstechnica.com/arstechnica/index/",
        "name": "Ars Technica",
        "model": models.ArsTechnicaRssItem
    }
}

def _fetch_and_store_rss(db: Session, source_key: str):
    """Универсальная функция для парсинга любого RSS-источника"""
    if source_key not in RSS_SOURCES:
        raise ValueError(f"Unknown RSS source: {source_key}")
    
    config = RSS_SOURCES[source_key]
    feed = feedparser.parse(config["url"])
    
    # Берем только первые 5 новостей
    for e in feed.entries[:5]:
        title = getattr(e, "title", None)
        link = getattr(e, "link", None)
        summary = getattr(e, "summary", None) or getattr(e, "description", None)

        published_at = None
        if getattr(e, "published", None):
            try:
                published_at = dtparse.parse(e.published)
            except Exception:
                published_at = None
        elif getattr(e, "updated", None):
            try:
                published_at = dtparse.parse(e.updated)
            except Exception:
                published_at = None

        if not title or not link:
            continue

        data = schemas.RssItemCreate(
            title=title,
            link=link,
            summary=summary,
            published_at=published_at,
        )
        crud.upsert_rss_item(db, data, config["model"])
    # update fetch timestamp for the source
    crud.touch_fetch_meta(db, source_key)


def _ensure_fresh(db: Session, sources: List[str], min_age_hours: int = 24):
    """Refresh selected sources once per TTL, on-demand (no timers)."""
    for s in sources:
        try:
            if crud.needs_refresh(db, s, min_age_hours=min_age_hours):
                _fetch_and_store_rss(db, s)
        except Exception:
            # fail open; serve cached data
            pass


def require_admin_api_key(request: Request):
    """Allow access to fetch endpoints only when X-API-Key matches ADMIN_API_KEY.
    If ADMIN_API_KEY is not set, allow in dev by default.
    """
    admin_key = os.getenv("ADMIN_API_KEY", "").strip()
    if not admin_key:
        return
    key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if key != admin_key:
        raise HTTPException(status_code=403, detail="Forbidden")


def rss_rate_limit(request: Request):
    """Limit RSS GET requests per IP. Defaults: 60 req / 5 min."""
    try:
        ip = request.client.host if request and request.client else "?"
    except Exception:
        ip = "?"
    limit = int(os.getenv("RSS_RATE_LIMIT_COUNT", "60"))
    window = int(os.getenv("RSS_RATE_LIMIT_WINDOW", "300"))
    key = f"rss:ip:{ip}"
    if not _allow(key, limit, window):
        raise HTTPException(status_code=429, detail="Too many RSS requests. Please slow down.")

@router.post("/fetch/{source}", summary="Скачать 5 новостей из указанного источника")
def rss_fetch(source: str, db: Session = Depends(get_db), _: None = Depends(require_admin_api_key)):
    if source not in RSS_SOURCES:
        return {"status": "error", "message": f"Unknown source. Available: {list(RSS_SOURCES.keys())}"}
    
    _fetch_and_store_rss(db, source)
    return {"status": "ok", "message": f"Загружено до 5 новостей из {RSS_SOURCES[source]['name']}"}

@router.post("/fetch-bg/{source}", summary="Запланировать скачивание 5 новостей в фоне")
def rss_fetch_bg(source: str, background: BackgroundTasks, db: Session = Depends(get_db), _: None = Depends(require_admin_api_key)):
    if source not in RSS_SOURCES:
        return {"status": "error", "message": f"Unknown source. Available: {list(RSS_SOURCES.keys())}"}
    
    background.add_task(_fetch_and_store_rss, db, source)
    return {"status": "scheduled", "message": f"Запланирована загрузка до 5 новостей из {RSS_SOURCES[source]['name']}"}

@router.get("/sources", summary="Получить список доступных RSS-источников")
def get_rss_sources():
    return {
        "sources": {
            key: {"name": config["name"], "url": config["url"]} 
            for key, config in RSS_SOURCES.items()
        }
    }

@router.get("/latest/{source}", response_model=List[schemas.RssItemRead], summary="Последние новости из конкретного источника")
def rss_latest_by_source(
    source: str,
    limit: int = Query(50, ge=1, le=200), 
    db: Session = Depends(get_db),
    _: None = Depends(rss_rate_limit),
):
    if source not in RSS_SOURCES:
        return {"status": "error", "message": f"Unknown source. Available: {list(RSS_SOURCES.keys())}"}
    
    model_class = RSS_SOURCES[source]["model"]
    _ensure_fresh(db, [source], min_age_hours=24)
    return crud.list_rss_items(db, model_class, limit=limit)

@router.get("/latest", response_model=List[schemas.RssItemRead], summary="Последние новости из всех источников")
def rss_latest(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db), _: None = Depends(rss_rate_limit)):
    _ensure_fresh(db, list(RSS_SOURCES.keys()), min_age_hours=24)
    return crud.list_all_rss_items(db, limit=limit)

# Эндпоинты для фронтенда
@router.get("/news/cnews", response_model=List[schemas.RssItemRead], summary="Новости CNews для фронтенда")
def get_cnews_for_frontend(
    limit: int = Query(5, ge=1, le=25, description="Количество новостей CNews (1-25)"),
    db: Session = Depends(get_db),
    _: None = Depends(rss_rate_limit),
):
    """Эндпоинт специально для новостей CNews на фронтенде"""
    _ensure_fresh(db, ["cnews"], min_age_hours=24)
    return crud.list_rss_items(db, models.CNewsRssItem, limit=limit)

@router.get("/news/habr", response_model=List[schemas.RssItemRead], summary="Новости Habr для фронтенда")
def get_habr_for_frontend(
    limit: int = Query(5, ge=1, le=25, description="Количество новостей Habr (1-25)"),
    db: Session = Depends(get_db),
    _: None = Depends(rss_rate_limit),
):
    """Эндпоинт специально для новостей Habr на фронтенде"""
    _ensure_fresh(db, ["habr"], min_age_hours=24)
    return crud.list_rss_items(db, models.HabrRssItem, limit=limit)

@router.get("/news", response_model=List[schemas.RssItemRead], summary="Получить последние новости для фронтенда")
def get_news_for_frontend(
    limit: str = Query("10", description="Количество новостей (1-50) или 'all' для всех"),
    db: Session = Depends(get_db),
    _: None = Depends(rss_rate_limit),
):
    """
    Эндпоинт специально для фронтенда LeisurePage.
    Возвращает последние новости из всех источников в формате, удобном для отображения в интерфейсе.
    """
    # Обновляем все источники, чтобы новые (wired/ars) тоже подтягивались, 
    # но ниже возвращаем только cnews+habr для фронтенда
    _ensure_fresh(db, list(RSS_SOURCES.keys()), min_age_hours=24)
    if limit == "all":
        # Возвращаем все новости (например, до 100)
        return crud.list_all_rss_items(db, limit=100)
    else:
        try:
            limit_int = int(limit)
            if limit_int < 1 or limit_int > 50:
                limit_int = 10
            return crud.list_all_rss_items(db, limit=limit_int)
        except ValueError:
            return crud.list_all_rss_items(db, limit=10)
