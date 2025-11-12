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
    LoginRequest,
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
from quotes_router import router as quotes_router
from profiles_router import router as profiles_router
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
import time
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
        # Ensure core columns exist
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now()"))
        # Drop legacy columns if they exist
        for col in ("age", "email", "gender", "is_verified", "telegram_id", "telegram_username"):
            try:
                conn.execute(text(f"ALTER TABLE users DROP COLUMN IF EXISTS {col}"))
            except Exception:
                pass
        # Ensure FKs have ON DELETE CASCADE
        try:
            conn.execute(text("ALTER TABLE auth DROP CONSTRAINT IF EXISTS auth_user_id_fkey"))
            conn.execute(text("ALTER TABLE auth ADD CONSTRAINT auth_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE refresh_tokens DROP CONSTRAINT IF EXISTS refresh_tokens_user_id_fkey"))
            conn.execute(text("ALTER TABLE refresh_tokens ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_sender_id_fkey"))
            conn.execute(text("ALTER TABLE notifications ADD CONSTRAINT notifications_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_receiver_id_fkey"))
            conn.execute(text("ALTER TABLE notifications ADD CONSTRAINT notifications_receiver_id_fkey FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE"))
        except Exception:
            pass
        # Quotes table (id, text, author, created_at)
        try:
            conn.execute(text(
                """
                CREATE TABLE IF NOT EXISTS quotes (
                  id SERIAL PRIMARY KEY,
                  text TEXT NOT NULL,
                  author VARCHAR NULL,
                  created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now() NOT NULL
                )
                """
            ))
        except Exception:
            pass
        # User profiles table
        try:
            conn.execute(text(
                """
                CREATE TABLE IF NOT EXISTS user_profiles (
                  id SERIAL PRIMARY KEY,
                  user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                  gender VARCHAR NULL,
                  age INTEGER NULL,
                  about VARCHAR(100) NULL,
                  avatar_url VARCHAR NULL,
                  created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now() NOT NULL,
                  updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now() NOT NULL
                )
                """
            ))
        except Exception:
            pass
        # Russian quotes table
        try:
            conn.execute(text(
                """
                CREATE TABLE IF NOT EXISTS quotes_ru (
                  id SERIAL PRIMARY KEY,
                  text TEXT NOT NULL,
                  author VARCHAR NULL,
                  created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now() NOT NULL
                )
                """
            ))
        except Exception:
            pass
        # Seed a few quotes if table is empty
        try:
            count = conn.execute(text("SELECT COUNT(*) FROM quotes")).scalar() or 0
            if count == 0:
                conn.execute(text("INSERT INTO quotes (text, author) VALUES (:t, :a)"), [
                    {"t": "The best way to get started is to stop talking and start doing.", "a": "Walt Disney"},
                    {"t": "Simplicity is the soul of efficiency.", "a": "Austin Freeman"},
                    {"t": "Programs must be written for people to read, and only incidentally for machines to execute.", "a": "Harold Abelson"},
                    {"t": "Talk is cheap. Show me the code.", "a": "Linus Torvalds"},
                    {"t": "Premature optimization is the root of all evil.", "a": "Donald Knuth"},
                ])
        except Exception:
            pass
        # Seed RU quotes if table is empty or contains only generic/old entries (no authors)
        try:
            total_ru = conn.execute(text("SELECT COUNT(*) FROM quotes_ru")).scalar() or 0
            authored_ru = conn.execute(text("SELECT COUNT(*) FROM quotes_ru WHERE author IS NOT NULL AND trim(author) <> ''")).scalar() or 0
            if total_ru == 0 or authored_ru == 0:
                # Replace with modern Russian quotes (переводы известных цитат)
                try:
                    conn.execute(text("TRUNCATE TABLE quotes_ru RESTART IDENTITY"))
                except Exception:
                    pass
                conn.execute(text("INSERT INTO quotes_ru (text, author) VALUES (:t, :a)"), [
                    {"t": "Лучший способ начать — перестать говорить и начать делать.", "a": "Уолт Дисней"},
                    {"t": "Простота — душа эффективности.", "a": "Остин Фриман"},
                    {"t": "Программы должны писаться для людей, а лишь попутно для машин, которые их исполняют.", "a": "Гарольд Абельсон"},
                    {"t": "Говорить легко. Покажите мне код.", "a": "Линус Торвальдс"},
                    {"t": "Преждевременная оптимизация — корень всех зол.", "a": "Дональд Кнут"},
                    {"t": "Дизайн — это не только то, как выглядит и ощущается. Дизайн — это то, как это работает.", "a": "Стив Джобс"},
                ])
        except Exception:
            pass


# --- Simple in-memory rate limiter (per-process) ---
_RL_STORE: Dict[str, Deque[float]] = {}
# Simple in-process lock/failure stores (fallback when Redis is not used)
_LOCKS: Dict[str, float] = {}
_FAILS: Dict[str, Deque[float]] = {}
_REDIS = None
 

@app.on_event("startup")
async def _init_redis():
    global _REDIS
    url = os.getenv("REDIS_URL") or getattr(settings, 'REDIS_URL', None)
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

def _limit_sync(pairs: list[tuple[str, int, int]], reason: str):
    """Synchronous in-process limiter (per-process). Uses in-memory deque."""
    for key, limit, window in pairs:
        if not _allow_rate(key, limit, window):
            raise HTTPException(status_code=429, detail=f"Too many attempts: {reason}")

def _client_ip(request: Request) -> str:
    xfwd = request.headers.get('x-forwarded-for') or request.headers.get('X-Forwarded-For')
    if xfwd:
        # first IP in list
        return xfwd.split(',')[0].strip()
    return request.client.host if request and request.client else 'unknown'

def _is_locked(key: str) -> float:
    """Return seconds remaining if locked, or 0 if not locked."""
    now = time.time()
    until = _LOCKS.get(key, 0.0)
    if until and until > now:
        return max(0.0, until - now)
    if until and until <= now:
        _LOCKS.pop(key, None)
    return 0.0

def _set_lock(key: str, seconds: int):
    _LOCKS[key] = time.time() + max(0, seconds)

def _record_fail(key: str, window_sec: int, lock_after: int, lock_sec: int) -> int:
    """Record a failure for key; if lock_after within window, set lock for lock_sec.
    Returns current count in window.
    """
    now = time.time()
    dq = _FAILS.get(key)
    if dq is None:
        dq = deque()
        _FAILS[key] = dq
    cutoff = now - window_sec
    while dq and dq[0] < cutoff:
        dq.popleft()
    dq.append(now)
    if len(dq) >= lock_after:
        # map fail key to lock key for in-memory lock as well
        if key.startswith("fail:login:ip:"):
            _set_lock("lock:login:ip:" + key.split("fail:login:ip:", 1)[1], lock_sec)
        elif key.startswith("fail:login:user:"):
            _set_lock("lock:login:user:" + key.split("fail:login:user:", 1)[1], lock_sec)
        else:
            _set_lock("lock:" + key, lock_sec)
    return len(dq)

def _clear_fails(key: str):
    _FAILS.pop(key, None)

# --- Redis-backed helpers (if Redis is available) ---
async def _r_incr_with_ttl(key: str, window_sec: int) -> int:
    if _REDIS is None:
        raise RuntimeError("Redis is not available")
    val = await _REDIS.incr(key)
    if val == 1:
        await _REDIS.expire(key, window_sec)
    return int(val)

async def _r_limit(keys: list[tuple[str, int, int]], reason: str):
    if _REDIS is None:
        raise RuntimeError("Redis not available")
    for key, limit, window in keys:
        try:
            val = await _r_incr_with_ttl(key, window)
            if val > limit:
                raise HTTPException(status_code=429, detail=f"Too many attempts: {reason}")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Redis limiter error ({reason}): {e}")
            # fall back to in-memory
            if not _allow_rate(key, limit, window):
                raise HTTPException(status_code=429, detail=f"Too many attempts: {reason}")

async def _r_lock_remaining(key: str) -> int:
    if _REDIS is None:
        raise RuntimeError("Redis not available")
    ttl = await _REDIS.ttl(key)
    if ttl is None or ttl < 0:
        return 0
    return int(ttl)

async def _r_set_lock(key: str, seconds: int):
    if _REDIS is None:
        raise RuntimeError("Redis not available")
    try:
        await _REDIS.set(key, "1", ex=max(1, seconds))
    except Exception:
        pass

def _lock_key_for_fail(key: str) -> str:
    # Map fail-keys to lock-keys used by checks
    if key.startswith("fail:login:ip:"):
        return "lock:login:ip:" + key.split("fail:login:ip:", 1)[1]
    if key.startswith("fail:login:user:"):
        return "lock:login:user:" + key.split("fail:login:user:", 1)[1]
    return "lock:" + key

async def _r_record_fail(key: str, window_sec: int, lock_after: int, lock_sec: int) -> int:
    if _REDIS is None:
        raise RuntimeError("Redis not available")
    try:
        val = await _r_incr_with_ttl(key, window_sec)
        if val >= lock_after:
            await _r_set_lock(_lock_key_for_fail(key), lock_sec)
        return int(val)
    except Exception as e:
        logger.warning(f"Redis fail recorder error: {e}")
        # fall back to in-memory
        count = _record_fail(key, window_sec, lock_after, lock_sec)
        return count

async def _r_clear_fails(key: str):
    if _REDIS is None:
        raise RuntimeError("Redis not available")
    try:
        await _REDIS.delete(key)
    except Exception:
        pass

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


@app.get("/self-test")
def self_test(request: Request, db: Session = Depends(get_db)):
    """Lightweight end-to-end test: API, DB, Redis, auth cookie."""
    api_ok = True
    db_ok = False
    redis_ok = None
    auth_cookie = bool(request.cookies.get("access_token"))
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    # In ASGI context, we avoid blocking the running loop; report connection presence
    try:
        if _REDIS is not None:
            redis_ok = True
    except Exception:
        redis_ok = False
    return {
        "api_ok": api_ok,
        "db_ok": db_ok,
        "redis_ok": redis_ok,
        "authenticated": auth_cookie,
        "time": datetime.utcnow().isoformat() + "Z",
    }

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
app.include_router(quotes_router)
app.include_router(profiles_router)


@app.get("/statistics")
def statistics(db: Session = Depends(get_db)):
    """System-wide user statistics."""
    total_users = db.query(models.User).count()
    online_users = db.query(models.Auth).filter(models.Auth.is_online == True).count()
    return {
        "total_users": total_users,
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

@app.post("/login", response_model=Token)
async def login(payload: LoginRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    """Username/password login. Issues HttpOnly cookies and returns token info."""
    name = (payload.name or "").strip()
    password = payload.password or ""
    ip = _client_ip(request)
    # Check locks
    # Locks and rates via Redis if available; fallback to memory
    if _REDIS is not None:
        rem_ip = await _r_lock_remaining(f"lock:login:ip:{ip}")
        if rem_ip:
            raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {int(rem_ip)}s")
        rem_user = await _r_lock_remaining(f"lock:login:user:{name.lower()}")
        if rem_user:
            raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {int(rem_user)}s")
        await _r_limit([
            (f"rl:login:ip:{ip}", 20, 60),
            (f"rl:login:user:{name.lower()}", 10, 300),
        ], reason="login")
    else:
        rem = _is_locked(f"lock:login:ip:{ip}")
        if rem:
            raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {int(rem)}s")
        rem = _is_locked(f"lock:login:user:{name.lower()}")
        if rem:
            raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {int(rem)}s")
        _limit_sync([
            (f"rl:login:ip:{ip}", 20, 60),
            (f"rl:login:user:{name.lower()}", 10, 300),
        ], reason="login")
    if not name or not password:
        raise HTTPException(status_code=400, detail="Name and password required")

    user = crud.get_user_by_name(db, name)
    if not user:
        # record failures on unknown usernames by IP only
        if _REDIS is not None:
            await _r_record_fail(f"fail:login:ip:{ip}", window_sec=600, lock_after=20, lock_sec=900)
        else:
            _record_fail(f"fail:login:ip:{ip}", window_sec=600, lock_after=20, lock_sec=900)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    auth = crud.get_auth_by_user_id(db, user.id)
    if not auth or not auth.password_hash:
        if _REDIS is not None:
            await _r_record_fail(f"fail:login:ip:{ip}", window_sec=600, lock_after=20, lock_sec=900)
            await _r_record_fail(f"fail:login:user:{name.lower()}", window_sec=300, lock_after=5, lock_sec=900)
        else:
            _record_fail(f"fail:login:ip:{ip}", window_sec=600, lock_after=20, lock_sec=900)
            _record_fail(f"fail:login:user:{name.lower()}", window_sec=300, lock_after=5, lock_sec=900)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not crud.verify_password(password, auth.password_hash):
        # record failed attempt; lock user after 5 fails/5min; IP after 20/10min
        if _REDIS is not None:
            await _r_record_fail(f"fail:login:user:{name.lower()}", window_sec=300, lock_after=5, lock_sec=900)
            await _r_record_fail(f"fail:login:ip:{ip}", window_sec=600, lock_after=20, lock_sec=900)
        else:
            _record_fail(f"fail:login:user:{name.lower()}", window_sec=300, lock_after=5, lock_sec=900)
            _record_fail(f"fail:login:ip:{ip}", window_sec=600, lock_after=20, lock_sec=900)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Mark user online and set last_login
    auth.is_online = True
    auth.last_login = datetime.utcnow()
    db.commit()
    # clear failure counters on success
    if _REDIS is not None:
        await _r_clear_fails(f"fail:login:user:{name.lower()}")
    else:
        _clear_fails(f"fail:login:user:{name.lower()}")

    access_token = crud.create_access_token({"user_id": user.id})
    refresh_token = crud.create_refresh_token(db, user.id)
    set_session_cookies(response, access_token, refresh_token)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "name": user.name or "",
        "role": auth.role or "user",
        "refresh_token": refresh_token,
    }

@app.post("/register", response_model=Token)
async def register(
    payload: UserCreate,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
):
    """Register a new user with unique name and password; start a session via cookies."""
    name = (payload.name or "").strip()
    password = payload.password or ""
    ip = _client_ip(request)
    # Rate limit registrations per IP
    if _REDIS is not None:
        await _r_limit([
            (f"rl:register:ip:{ip}", 3, 600),
            (f"rl:register:ip-hour:{ip}", 10, 3600),
        ], reason="register")
    else:
        _limit_sync([
            (f"rl:register:ip:{ip}", 3, 600),
            (f"rl:register:ip-hour:{ip}", 10, 3600),
        ], reason="register")
    if not name or not password:
        raise HTTPException(status_code=400, detail="Name and password required")
    try:
        user = crud.create_user(db, payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to create user")

    auth = crud.get_auth_by_user_id(db, user.id)
    access_token = crud.create_access_token({"user_id": user.id})
    refresh_token = crud.create_refresh_token(db, user.id)
    set_session_cookies(response, access_token, refresh_token)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "name": user.name or "",
        "role": auth.role if auth else "user",
        "refresh_token": refresh_token,
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
    # Publish presence offline for other instances via Redis
    try:
        if _REDIS is not None:
            await _REDIS.publish("presence", json.dumps({"user_id": int(user_id), "is_online": False}))
    except Exception:
        pass

    return {"message": "Logged out"}


@app.post("/presence/offline")
async def presence_offline(request: Request, db: Session = Depends(get_db)):
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
    # Publish presence offline
    try:
        if _REDIS is not None:
            await _REDIS.publish("presence", json.dumps({"user_id": user_id, "is_online": False}))
    except Exception:
        pass
    return {"ok": True}
