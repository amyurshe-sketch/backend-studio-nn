from fastapi import APIRouter, Depends, HTTPException, Request
from typing import List, Tuple
from sqlalchemy.orm import Session
from datetime import datetime
from collections import deque
import time
import os
try:
    from redis.asyncio import from_url as redis_from_url
except Exception:
    redis_from_url = None

from database import get_db
import models
from schemas import UserProfileUpdate, UserProfileOut
from jose import jwt, JWTError
from config import settings

router = APIRouter(tags=["profiles"])
_REDIS = None

@router.on_event("startup")
async def _init_profiles_redis():
    global _REDIS
    url = os.getenv("REDIS_URL") or getattr(settings, 'REDIS_URL', None)
    if url and redis_from_url is not None:
        try:
            _REDIS = redis_from_url(url, encoding="utf-8", decode_responses=True)
            await _REDIS.ping()
        except Exception:
            _REDIS = None


def _current_user_id(request: Request) -> int:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="No session")
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = int(payload.get("user_id"))
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# --- Simple per-process rate limiter for profile updates ---
_RL_STORE = {}

def _client_ip(request: Request) -> str:
    xfwd = request.headers.get('x-forwarded-for') or request.headers.get('X-Forwarded-For')
    if xfwd:
        return xfwd.split(',')[0].strip()
    return request.client.host if request and request.client else 'unknown'

def _allow_rate(key: str, limit: int, window_sec: int) -> bool:
    now = time.time()
    dq: deque = _RL_STORE.get(key)
    if dq is None:
        dq = deque()
        _RL_STORE[key] = dq
    cutoff = now - window_sec
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) >= limit:
        return False
    dq.append(now)
    return True

async def _r_limit(keys: List[Tuple[str, int, int]]):
    if _REDIS is None:
        # fallback: validate with in-memory limiter
        for k, limit, window in keys:
            if not _allow_rate(k, limit, window):
                raise HTTPException(status_code=429, detail="Too many requests")
        return
    for k, limit, window in keys:
        try:
            val = await _REDIS.incr(k)
            if val == 1:
                await _REDIS.expire(k, window)
            if val > limit:
                raise HTTPException(status_code=429, detail="Too many requests")
        except HTTPException:
            raise
        except Exception:
            # degrade gracefully to in-memory limiter
            if not _allow_rate(k, limit, window):
                raise HTTPException(status_code=429, detail="Too many requests")


@router.get("/profiles/me", response_model=UserProfileOut)
def get_my_profile(request: Request, db: Session = Depends(get_db)):
    uid = _current_user_id(request)
    prof = db.query(models.UserProfile).filter(models.UserProfile.user_id == uid).first()
    if not prof:
        return UserProfileOut(user_id=uid, gender=None, age=None, about=None, avatar_url=None)
    return prof


@router.put("/profiles/me", response_model=UserProfileOut)
async def upsert_my_profile(payload: UserProfileUpdate, request: Request, db: Session = Depends(get_db)):
    uid = _current_user_id(request)
    # Rate limit (Redis if available): relaxed for batch edits, distributed across instances
    ip = _client_ip(request)
    await _r_limit([
        (f"prof:ip:{ip}", 60, 60),
        (f"prof:user:{uid}:min", 20, 60),
        (f"prof:user:{uid}:hour", 200, 3600),
    ])
    prof = db.query(models.UserProfile).filter(models.UserProfile.user_id == uid).first()
    if not prof:
        prof = models.UserProfile(user_id=uid)
        db.add(prof)
    if payload.gender is not None:
        prof.gender = payload.gender.strip() or None
    if payload.age is not None:
        prof.age = payload.age
    if payload.about is not None:
        prof.about = payload.about.strip() or None
    if payload.avatar_url is not None:
        prof.avatar_url = payload.avatar_url.strip() or None
    prof.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(prof)
    return prof


@router.get("/profiles/{user_id}", response_model=UserProfileOut)
def get_user_profile(user_id: int, db: Session = Depends(get_db)):
    prof = db.query(models.UserProfile).filter(models.UserProfile.user_id == user_id).first()
    if not prof:
        return UserProfileOut(user_id=user_id, gender=None, age=None, about=None, avatar_url=None)
    return prof
