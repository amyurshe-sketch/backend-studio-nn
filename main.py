from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import os
import os
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import get_db, engine
from schemas import (
    UserCreate,
    EmailVerification,
    RegistrationInitResponse,
    Token,
    UserLogin,
    VerificationResponse,
)
import models
import crud
from datetime import datetime, timedelta
from rss_bootstrap import register_rss
import secrets
from jose import jwt, JWTError
from fastapi import Request
from config import settings
from jose import jwt, JWTError
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

app = FastAPI(title="Studio NN Registration API")

# CORS: allow local dev and deployed frontend; extra origins via env ALLOW_ORIGINS (comma-separated)
_DEFAULT_ORIGINS = [
    "http://localhost:3000",
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

@app.on_event("startup")
def ensure_db_columns():
    # Lightweight compatibility migration for existing DBs
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now()"))
        # Keep legacy registration_tokens table compatible with new flow
        conn.execute(text("ALTER TABLE registration_tokens ADD COLUMN IF NOT EXISTS name VARCHAR"))
        conn.execute(text("ALTER TABLE registration_tokens ADD COLUMN IF NOT EXISTS age INTEGER"))
        conn.execute(text("ALTER TABLE registration_tokens ADD COLUMN IF NOT EXISTS gender VARCHAR"))
        conn.execute(text("ALTER TABLE registration_tokens ADD COLUMN IF NOT EXISTS password_hash VARCHAR"))
        # Relax NOT NULL if present (safe if already nullable)
        try:
            conn.execute(text("ALTER TABLE registration_tokens ALTER COLUMN name DROP NOT NULL"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE registration_tokens ALTER COLUMN age DROP NOT NULL"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE registration_tokens ALTER COLUMN gender DROP NOT NULL"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE registration_tokens ALTER COLUMN password_hash DROP NOT NULL"))
        except Exception:
            pass
        # Relax NOT NULL on legacy users columns to support email-only signup
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


# --- Simple in-memory rate limiter (per-process) ---
_RL_STORE: Dict[str, Deque[float]] = {}
_REDIS = None

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


@app.post("/register", response_model=RegistrationInitResponse)
async def register_user(user: UserCreate, request: Request, db: Session = Depends(get_db)):
    # Rate-limit to mitigate abuse of email sender
    ip = (request.client.host if request and request.client else "?")
    email_key = f"reg:email:{(user.email or '').lower()}"
    ip_key = f"reg:ip:{ip}"
    await _enforce_limits([
        (ip_key, 10, 10 * 60),    # 10 per 10 minutes per IP
        (email_key, 5, 10 * 60),  # 5 per 10 minutes per email
    ], reason="register")
    try:
        result = await crud.initiate_registration(db, user)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка регистрации: {e}")


@app.post("/verify-email", response_model=Token)
async def verify_email(
    data: EmailVerification,
    db: Session = Depends(get_db),
    response: Response = None,
):
    result = await crud.complete_registration(db, data.email, data.code)
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    user_id = result.get("user_id")
    user = crud.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found after verification")

    auth = crud.get_auth_by_user_id(db, user.id)
    if not auth:
        # Create default auth record if missing (legacy/incomplete token data)
        db.add(models.Auth(
            user_id=user.id,
            password_hash=crud.get_password_hash(secrets.token_urlsafe(24)),
            role="user",
        ))
        db.commit()
        auth = crud.get_auth_by_user_id(db, user.id)

    auth.last_login = datetime.utcnow()
    auth.is_online = True
    db.commit()

    access_token = crud.create_access_token({"user_id": user.id})
    refresh_token = crud.create_refresh_token(db, user.id)

    # Auto-login: set HttpOnly cookies so client is authenticated immediately
    if response is not None:
        set_session_cookies(response, access_token, refresh_token)

    # Ensure name is a string for the response model
    safe_name = user.name or user.email.split("@")[0]

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "name": safe_name,
        "role": auth.role,
        "refresh_token": refresh_token,
    }


@app.get("/")
def home():
    return {"status": "Studio NN Email Verification API работает"}


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


def clear_session_cookies(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")


@app.post("/login", response_model=Token)
async def login_for_access_token(
    user_login: UserLogin,
    db: Session = Depends(get_db),
    response: Response = None,
    request: Request = None,
):
    # Rate-limit login to deter brute-force
    ip = (request.client.host if request and request.client else "?")
    name_key = f"login:user:{(user_login.name or '').lower()}"
    ip_key = f"login:ip:{ip}"
    await _enforce_limits([
        (ip_key, 20, 10 * 60),   # 20 per 10 minutes per IP
        (name_key, 8, 10 * 60),  # 8 per 10 minutes per username
    ], reason="login")
    result = crud.authenticate_user(db, user_login.name, user_login.password)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = result["user"]
    auth = result["auth"]

    auth.last_login = datetime.utcnow()
    auth.is_online = True
    db.commit()

    access_token = crud.create_access_token({"user_id": user.id})
    refresh_token = crud.create_refresh_token(db, user.id)

    payload = {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "name": user.name,
        "role": auth.role,
        "refresh_token": refresh_token,
    }
    if response is not None:
        set_session_cookies(response, access_token, refresh_token)
    return payload


# Dev helper: fetch last verification code for an email (enabled only when DEV_TOOLS=true)
if os.getenv("DEV_TOOLS", "false").lower() == "true":
    @app.get("/dev/last-code")
    def dev_last_code(email: str, db: Session = Depends(get_db)):
        token = (
            db.query(models.RegistrationToken)
            .filter(models.RegistrationToken.email == email.lower())
            .order_by(models.RegistrationToken.id.desc())
            .first()
        )
        if not token:
            raise HTTPException(status_code=404, detail="No code found for email")
        return {
            "email": email.lower(),
            "code": token.code,
            "expires_at": token.expires_at.isoformat() if token.expires_at else None,
        }


@app.post("/logout")
async def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Invalidate session: mark user offline and revoke refresh tokens.

    Accept either Authorization: Bearer or HttpOnly cookie.
    """
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
