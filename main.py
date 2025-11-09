from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import os
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import get_db, engine
from schemas import (
    UserCreate,
    Token,
    TelegramAuth,
)
import models
import crud
from datetime import datetime, timedelta
from rss_bootstrap import register_rss
from jose import jwt, JWTError
from fastapi import Request
from config import settings
from sse_router import router as sse_router
from users_router import router as users_router
from notifications_router import router as notifications_router
from ws_router import router as ws_router
from collections import deque
import time
import asyncio
import os
from typing import Deque, Dict
from logger import logger
try:
    from redis.asyncio import from_url as redis_from_url
except Exception:
    redis_from_url = None
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse, ORJSONResponse
import logging
import hmac, hashlib, time
import requests
import secrets as _secrets

# Disable default docs; we’ll mount protected docs below. Use ORJSONResponse for speed.
app = FastAPI(
    title="Studio NN API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    default_response_class=ORJSONResponse,
)

# CORS: allow local dev and deployed frontend; extra origins via env ALLOW_ORIGINS (comma-separated)
_DEFAULT_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "https://studio-nn.vercel.app",
]
_EXTRA = [o.strip() for o in os.getenv("ALLOW_ORIGINS", "").split(",") if o.strip()]
FRONTEND_ORIGINS = _DEFAULT_ORIGINS + _EXTRA

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        # Clickjacking / MIME / referrer
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        # Limit powerful features by default
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # Conservative CSP addition without breaking assets
        response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
        # HSTS only when secure cookies are enabled (assume HTTPS in prod)
        if os.getenv("COOKIE_SECURE", "false").lower() == "true":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
        return response


app.add_middleware(SecurityHeadersMiddleware)
from starlette.middleware.gzip import GZipMiddleware
# GZip large responses (e.g., RSS lists)
app.add_middleware(GZipMiddleware, minimum_size=1024)

# Suppress noisy access logs for health checks only
class _HealthzAccessFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        return "/healthz" not in msg

logging.getLogger("uvicorn.access").addFilter(_HealthzAccessFilter())

# --- Basic Auth helper (currently not used on public routes) ---
security = HTTPBasic()
BASIC_USER = os.getenv("BASIC_AUTH_USER", "")
BASIC_PASS = os.getenv("BASIC_AUTH_PASSWORD", "")

def require_basic(credentials: HTTPBasicCredentials = Depends(security)):
    if not BASIC_USER or not BASIC_PASS:
        return
    ok_u = _secrets.compare_digest(credentials.username, BASIC_USER)
    ok_p = _secrets.compare_digest(credentials.password, BASIC_PASS)
    if not (ok_u and ok_p):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )

@app.on_event("startup")
def ensure_db_columns():
    # Lightweight compatibility migration for existing DBs
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now()"))
        # Email verification flow removed; no need to maintain registration_tokens table
        # Relax NOT NULL on legacy users columns (backward-compat)
        try:
            conn.execute(text("ALTER TABLE users ALTER COLUMN name DROP NOT NULL"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE users ALTER COLUMN age DROP NOT NULL"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE users ALTER COLUMN gender DROP NOT NULL"))
        except Exception:
            pass
        # Make email optional (nullable) for Telegram-only login
        try:
            conn.execute(text("ALTER TABLE users ALTER COLUMN email DROP NOT NULL"))
        except Exception:
            pass
        # Telegram columns (id/username)
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_id BIGINT"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_username VARCHAR"))
        except Exception:
            pass
        try:
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS users_telegram_id_key ON users (telegram_id)"))
        except Exception:
            pass


# --- Simple in-memory rate limiter (per-process) ---
_RL_STORE: Dict[str, Deque[float]] = {}
_REDIS = None
_BOT_UN_CACHE = None

@app.on_event("startup")
async def _init_redis():
    global _REDIS
    url = os.getenv("REDIS_URL")
    if url and redis_from_url is not None:
        try:
            _REDIS = redis_from_url(url, encoding="utf-8", decode_responses=True)
            # ping to verify
            await _REDIS.ping()
            logger.info("Redis rate limiter: connected")
        except Exception as e:
            _REDIS = None
            logger.warning(f"Redis not available, falling back to in-memory rate limits: {e}")

def _allow_rate(key: str, limit: int, window_sec: int) -> bool:
    now = time.time()
    dq = _RL_STORE.get(key)
    if dq is None:
        dq = deque()
        _RL_STORE[key] = dq
    # Drop old timestamps
    cutoff = now - window_sec
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) >= limit:
        return False
    dq.append(now)
    return True

async def _enforce_limits(pairs: list[tuple[str, int, int]], reason: str):
    for key, limit, window in pairs:
        allowed = True
        if _REDIS is not None:
            try:
                # atomic counter with TTL window
                val = await _REDIS.incr(key)
                if val == 1:
                    await _REDIS.expire(key, window)
                allowed = val <= limit
            except Exception as e:
                logger.warning(f"Redis limiter error: {e}; using in-memory fallback")
                allowed = _allow_rate(key, limit, window)
        else:
            allowed = _allow_rate(key, limit, window)

        if not allowed:
            logger.warning(f"Rate limit exceeded for key={key} reason={reason}")
            try:
                await asyncio.sleep(0.2)
            except Exception:
                pass
            raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")
    


@app.get("/")
def home():
    return {"status": "Studio NN API работает"}

# Public health endpoint (no auth) for Render health checks and wake-ups
@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"ok": True}

# Protected OpenAPI JSON and Swagger UI
@app.get("/openapi.json", include_in_schema=False)
def openapi_json():
    return JSONResponse(app.openapi())

@app.get("/docs", include_in_schema=False)
def docs():
    return get_swagger_ui_html(openapi_url="/openapi.json", title="API docs")


@app.get("/me")
def me(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="No session")
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = int(payload.get("user_id"))
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = crud.get_user_by_id(db, user_id)
    auth = crud.get_auth_by_user_id(db, user_id)
    if not user or not auth:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user_id": user.id, "name": user.name or "", "role": auth.role}


@app.post("/refresh-token")
def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    """Rotate refresh token and issue new access token via HttpOnly cookies."""
    _require_csrf(request)
    refresh = request.cookies.get("refresh_token")
    if not refresh:
        raise HTTPException(status_code=401, detail="No refresh token")
    rotation = crud.refresh_session(db, refresh)
    if not rotation:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    access_token = rotation["access_token"]
    new_refresh_token = rotation["refresh_token"]
    set_session_cookies(response, access_token, new_refresh_token)
    user = rotation["user"]
    auth = rotation["auth"]
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "user_id": user.id,
        "name": user.name,
        "role": auth.role,
    }

# Mount RSS routes
register_rss(app)

# Mount other routers
app.include_router(sse_router)
app.include_router(users_router)
app.include_router(notifications_router)
app.include_router(ws_router)


@app.get("/statistics")
def statistics(db: Session = Depends(get_db)):
    """System-wide user statistics."""
    total_users = db.query(models.User).count()
    female_users = db.query(models.User).filter(models.User.gender == 'женский').count()
    male_users = db.query(models.User).filter(models.User.gender == 'мужской').count()
    online_users = db.query(models.Auth).filter(models.Auth.is_online == True).count()
    return {
        "total_users": total_users,
        "female_users": female_users,
        "male_users": male_users,
        "online_users": online_users,
    }




def set_session_cookies(response: Response, access_token: str, refresh_token: str | None = None):
    """Set HttpOnly cookies for session.

    In production (separate frontend/backend domains, HTTPS), set SameSite=None; Secure=True.
    For local development (http://localhost), use SameSite=Lax; Secure=False.
    Configure via env var COOKIE_SECURE=true to force Secure/None.
    """
    secure_env = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    secure = secure_env
    samesite = "none" if secure else "lax"

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite=samesite,
        secure=secure,
        path="/",
    )
    if refresh_token:
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            samesite=samesite,
            secure=secure,
            path="/",
        )

    # Issue CSRF token cookie (non-HttpOnly) so clients can echo via X-CSRF-Token
    try:
        csrf = _secrets.token_urlsafe(32)
        response.set_cookie(
            key="csrf_token",
            value=csrf,
            httponly=False,
            samesite=samesite,
            secure=secure,
            path="/",
        )
    except Exception:
        pass


def _require_csrf(request: Request):
    """Validate CSRF for cookie-based POSTs when COOKIE_SECURE=true (prod)."""
    if os.getenv("COOKIE_SECURE", "false").lower() != "true":
        return
    header = request.headers.get("x-csrf-token") or request.headers.get("X-CSRF-Token")
    cookie = request.cookies.get("csrf_token")
    if not header or not cookie or not _secrets.compare_digest(header, cookie):
        raise HTTPException(status_code=403, detail="CSRF token invalid or missing")


def clear_session_cookies(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")


def _verify_telegram_auth(data: dict, bot_token: str) -> bool:
    try:
        received_hash = data.get('hash')
        if not received_hash:
            return False
        pairs = []
        for k in sorted([k for k in data.keys() if k != 'hash']):
            v = data[k]
            pairs.append(f"{k}={v}")
        data_check_string = '\n'.join(pairs)
        secret_key = hashlib.sha256(bot_token.encode('utf-8')).digest()
        calc_hash = hmac.new(secret_key, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calc_hash, received_hash):
            return False
        # Optional: reject stale auth (older than 24h)
        try:
            auth_date = int(data.get('auth_date') or 0)
            if auth_date and (time.time() - auth_date) > 86400:
                return False
        except Exception:
            pass
        return True
    except Exception:
        return False


@app.post("/auth/telegram", response_model=Token)
async def auth_telegram(payload: TelegramAuth, db: Session = Depends(get_db), response: Response = None):
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN') or getattr(settings, 'TELEGRAM_BOT_TOKEN', None)
    if not bot_token:
        raise HTTPException(status_code=500, detail="Telegram auth is not configured")
    data = payload.dict()
    if not _verify_telegram_auth(data, bot_token):
        raise HTTPException(status_code=401, detail="Invalid Telegram signature")

    result = crud.upsert_user_from_telegram(db, data)
    user = result["user"]
    auth = result["auth"]
    access_token = crud.create_access_token({"user_id": user.id})
    refresh_token = crud.create_refresh_token(db, user.id)
    if response is not None:
        set_session_cookies(response, access_token, refresh_token)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "name": user.name,
        "role": auth.role if auth else "user",
        "refresh_token": refresh_token,
    }


def _bot_username() -> str | None:
    global _BOT_UN_CACHE
    if _BOT_UN_CACHE:
        return _BOT_UN_CACHE
    un = getattr(settings, 'TELEGRAM_BOT_USERNAME', None) or os.getenv('TELEGRAM_BOT_USERNAME')
    if un:
        _BOT_UN_CACHE = un.lstrip('@')
        return _BOT_UN_CACHE
    token = os.getenv('TELEGRAM_BOT_TOKEN') or getattr(settings, 'TELEGRAM_BOT_TOKEN', None)
    if not token:
        return None
    try:
        r = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=5)
        j = r.json()
        if j.get('ok') and j.get('result', {}).get('username'):
            _BOT_UN_CACHE = j['result']['username']
            return _BOT_UN_CACHE
    except Exception:
        return None
    return None


@app.post("/auth/telegram/send-login")
def send_telegram_login(request: Request):
    token = os.getenv('TELEGRAM_BOT_TOKEN') or getattr(settings, 'TELEGRAM_BOT_TOKEN', None)
    chat_id = os.getenv('TELEGRAM_CHAT_ID') or getattr(settings, 'TELEGRAM_CHAT_ID', None)
    if not token:
        raise HTTPException(status_code=500, detail="Telegram bot token not configured (set TELEGRAM_BOT_TOKEN)")
    if not chat_id:
        raise HTTPException(status_code=500, detail="Telegram chat id not configured (set TELEGRAM_CHAT_ID)")
    bot_un = _bot_username()
    if not bot_un:
        raise HTTPException(status_code=500, detail="Cannot resolve bot username")

    origin = request.headers.get('origin') or 'http://localhost:3000'
    return_to = origin.rstrip('/') + '/tg-callback'
    oauth_url = (
        f"https://oauth.telegram.org/auth?bot={bot_un}&origin={origin}"
        f"&embed=1&request_access=write&return_to={return_to}"
    )
    ok = False
    api_error = None
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id": int(chat_id),
                "text": "Нажмите кнопку, чтобы войти на сайт",
                "reply_markup": {
                    "inline_keyboard": [[{
                        "text": "Войти через Telegram",
                        "login_url": {
                            "url": oauth_url,
                            "request_write_access": True,
                        }
                    }]]
                }
            },
            timeout=8,
        )
        ok = bool(resp.ok)
        if not ok:
            try:
                api_error = resp.text
            except Exception:
                api_error = "telegram sendMessage failed"
    except Exception as e:
        ok = False
        api_error = str(e)
    return {
        "ok": ok,
        "bot_username": bot_un,
        "deep_link": f"https://t.me/{bot_un}",
        "oauth_url": oauth_url,
        "error": api_error,
    }


# Email verification developer helpers have been removed


@app.post("/logout")
async def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Invalidate session: mark user offline and revoke refresh tokens.

    Accept either Authorization: Bearer or HttpOnly cookie.
    """
    _require_csrf(request)
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    else:
        token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Set user offline if auth record exists
    auth = crud.get_auth_by_user_id(db, int(user_id))
    if auth:
        auth.is_online = False
        db.commit()

    # Revoke all refresh tokens for this user
    crud.revoke_user_refresh_tokens(db, int(user_id))
    clear_session_cookies(response)

    return {"message": "Logged out"}


@app.post("/presence/offline")
def presence_offline(request: Request, db: Session = Depends(get_db)):
    _require_csrf(request)
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="No session")
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = int(payload.get("user_id"))
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    auth = crud.get_auth_by_user_id(db, user_id)
    if auth:
        auth.is_online = False
        auth.last_login = datetime.utcnow()
        db.commit()
    return {"ok": True}
