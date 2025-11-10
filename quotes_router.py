from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from database import get_db
import models

router = APIRouter(tags=["quotes"])


@router.get("/quotes/random")
def random_quote(lang: str = Query('en'), db: Session = Depends(get_db)):
    is_ru = (lang or '').lower().startswith('ru')
    model = models.QuoteRu if is_ru else models.Quote
    q = db.query(model).order_by(func.random()).first()
    if not q:
        # Fallback if table exists but empty
        if is_ru:
            return {"text": "Продолжай двигаться вперёд.", "author": ""}
        return {"text": "Keep going, keep growing.", "author": ""}
    return {"id": q.id, "text": q.text, "author": q.author or ""}
