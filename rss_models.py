# rss_models.py
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, func, UniqueConstraint
from database import Base

class RssItemBase:
    """Базовый класс с общими полями для всех RSS-таблиц"""
    id = Column(Integer, primary_key=True, index=True)
    title = Column(Text, nullable=False)
    link = Column(Text, nullable=False)
    summary = Column(Text)
    published_at = Column(DateTime(timezone=True))
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())
    is_deleted = Column(Boolean, nullable=False, default=False)

class CNewsRssItem(Base, RssItemBase):
    __tablename__ = "cnews_rss_items"
    
    __table_args__ = (
        UniqueConstraint("link", name="uq_cnews_link"),
    )

class HabrRssItem(Base, RssItemBase):
    __tablename__ = "habr_rss_items"
    
    __table_args__ = (
        UniqueConstraint("link", name="uq_habr_link"),
    )


class WiredRssItem(Base, RssItemBase):
    __tablename__ = "wired_rss_items"
    
    __table_args__ = (
        UniqueConstraint("link", name="uq_wired_link"),
    )


class ArsTechnicaRssItem(Base, RssItemBase):
    __tablename__ = "arstechnica_rss_items"
    
    __table_args__ = (
        UniqueConstraint("link", name="uq_arstechnica_link"),
    )


class RssFetchMeta(Base):
    __tablename__ = "rss_fetch_meta"
    
    id = Column(Integer, primary_key=True, index=True)
    source_key = Column(String, unique=True, nullable=False, index=True)
    last_fetched_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
