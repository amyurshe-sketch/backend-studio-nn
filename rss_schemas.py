# rss_schemas.py
from pydantic import BaseModel, AnyHttpUrl
from datetime import datetime
from typing import Optional

class RssItemBase(BaseModel):
    title: str
    link: AnyHttpUrl
    summary: Optional[str] = None
    published_at: Optional[datetime] = None

class RssItemCreate(RssItemBase):
    pass

class RssItemRead(RssItemBase):
    id: int
    fetched_at: Optional[datetime] = None
    is_deleted: bool
    source: str  # Добавлено поле source

    class Config:
        from_attributes = True