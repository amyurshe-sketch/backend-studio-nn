from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse
from jose import jwt, JWTError
from typing import Generator, Dict, Set, Optional
import json
import time
import asyncio

from config import settings
try:
    from redis.asyncio import from_url as redis_from_url
except Exception:
    redis_from_url = None
from database import SessionLocal
import models
import crud


router = APIRouter(prefix="/sse", tags=["sse"])


ALGORITHM = "HS256"


def _decode_token(token: str) -> int:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return int(user_id)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def _sse_format(event: Optional[str], data: dict | str) -> str:
    payload = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
    lines = []
    if event:
        lines.append(f"event: {event}")
    for ln in payload.splitlines() or [""]:
        lines.append(f"data: {ln}")
    lines.append("")
    return "\n".join(lines) + "\n"


# In-memory pub/sub for instant notification pushes (single-process)
_notif_queues: Dict[int, Set[asyncio.Queue]] = {}


def _subscribe(user_id: int) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue()
    _notif_queues.setdefault(user_id, set()).add(q)
    return q


def _unsubscribe(user_id: int, q: asyncio.Queue) -> None:
    try:
        if user_id in _notif_queues:
            _notif_queues[user_id].discard(q)
            if not _notif_queues[user_id]:
                _notif_queues.pop(user_id, None)
    except Exception:
        pass


def publish_notification_event(user_id: int) -> None:
    """Notify SSE streams that user has a new notification or status change."""
    qs = list(_notif_queues.get(user_id, ()))
    for q in qs:
        try:
            # Non-blocking put: if queue is full, skip
            q.put_nowait({"t": time.time()})
        except asyncio.QueueFull:
            pass
    # Also publish to Redis channel for WS fanout across instances
    try:
        url = getattr(settings, 'REDIS_URL', None)
        if url and redis_from_url is not None:
            async def _pub():
                try:
                    r = redis_from_url(url, encoding="utf-8", decode_responses=True)
                    await r.publish("notifications", json.dumps({"receiver_id": user_id}))
                except Exception:
                    pass
            try:
                loop = asyncio.get_event_loop()
                if loop and loop.is_running():
                    loop.create_task(_pub())
                else:
                    asyncio.run(_pub())
            except Exception:
                pass
    except Exception:
        pass


@router.get("/online-status")
async def sse_online_status(token: str = Query(..., description="Access token")):
    user_id = _decode_token(token)

    async def event_stream() -> Generator[bytes, None, None]:
        db = SessionLocal()
        try:
            # Initial snapshot
            auth = db.query(models.Auth).filter(models.Auth.user_id == user_id).first()
            is_online = bool(auth.is_online) if auth else False
            yield _sse_format("status", {"user_id": user_id, "is_online": is_online}).encode()

            # Heartbeat loop
            while True:
                await asyncio.sleep(10)
                # Refresh online flag periodically
                auth = db.query(models.Auth).filter(models.Auth.user_id == user_id).first()
                is_online = bool(auth.is_online) if auth else False
                yield _sse_format("heartbeat", {"user_id": user_id, "is_online": is_online}).encode()
        except asyncio.CancelledError:
            # Client disconnected
            raise
        finally:
            db.close()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/online-status/snapshot")
def online_status_snapshot(token: str = Query(..., description="Access token")):
    """One-shot JSON snapshot for clients that use fetch()."""
    user_id = _decode_token(token)
    db = SessionLocal()
    try:
        auth = db.query(models.Auth).filter(models.Auth.user_id == user_id).first()
        is_online = bool(auth.is_online) if auth else False
        return {"user_id": user_id, "is_online": is_online}
    finally:
        db.close()


@router.get("/notifications")
async def sse_notifications(token: str = Query(..., description="Access token")):
    user_id = _decode_token(token)

    async def event_stream() -> Generator[bytes, None, None]:
        db = SessionLocal()
        q = _subscribe(user_id)
        try:
            # Initial snapshot (one DB read on connect)
            count = crud.get_unread_notifications_count(db, user_id)
            latest = (
                db.query(models.Notification)
                .filter(models.Notification.receiver_id == user_id)
                .order_by(models.Notification.id.desc())
                .first()
            )
            payload = {
                "user_id": user_id,
                "unread_count": count,
                "latest": (
                    {
                        "id": latest.id,
                        "sender_id": latest.sender_id,
                        "receiver_id": latest.receiver_id,
                        "message_text": latest.message_text,
                        "created_at": latest.created_at.isoformat() if latest and latest.created_at else None,
                        "is_read": latest.is_read if latest else None,
                    }
                    if latest
                    else None
                ),
            }
            yield _sse_format("notification", payload).encode()

            while True:
                # Wait indefinitely for a push; on timeout, only heartbeat (no DB queries)
                try:
                    await asyncio.wait_for(q.get(), timeout=30.0)
                except asyncio.TimeoutError:
                    # Lightweight keep-alive without DB access
                    yield _sse_format("heartbeat", {"t": int(time.time())}).encode()
                    continue

                # On push: refresh summary from DB and notify client
                count = crud.get_unread_notifications_count(db, user_id)
                latest = (
                    db.query(models.Notification)
                    .filter(models.Notification.receiver_id == user_id)
                    .order_by(models.Notification.id.desc())
                    .first()
                )
                payload = {
                    "user_id": user_id,
                    "unread_count": count,
                    "latest": (
                        {
                            "id": latest.id,
                            "sender_id": latest.sender_id,
                            "receiver_id": latest.receiver_id,
                            "message_text": latest.message_text,
                            "created_at": latest.created_at.isoformat() if latest and latest.created_at else None,
                            "is_read": latest.is_read if latest else None,
                        }
                        if latest
                        else None
                    ),
                }
                yield _sse_format("notification", payload).encode()
        except asyncio.CancelledError:
            raise
        finally:
            _unsubscribe(user_id, q)
            db.close()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/notifications/summary")
def notifications_summary(token: str = Query(..., description="Access token")):
    """One-shot JSON summary for clients that use fetch()."""
    user_id = _decode_token(token)
    db = SessionLocal()
    try:
        count = crud.get_unread_notifications_count(db, user_id)
        latest = (
            db.query(models.Notification)
            .filter(models.Notification.receiver_id == user_id)
            .order_by(models.Notification.id.desc())
            .first()
        )
        latest_id = latest.id if latest else None
        return {"user_id": user_id, "unread_count": count, "latest_id": latest_id}
    finally:
        db.close()
