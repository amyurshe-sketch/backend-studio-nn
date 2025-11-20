from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
import os
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError
from datetime import datetime, timedelta
import asyncio, json
from config import settings
import threading
import psycopg2
import select as _select
from database import SessionLocal
import models, crud
import time
from collections import deque
try:
    from redis.asyncio import from_url as redis_from_url
except Exception:
    redis_from_url = None

router = APIRouter()

PING_INTERVAL = 180
PONG_TIMEOUT = 600

class Conn:
    def __init__(self, ws: WebSocket, user_id: int):
        self.ws = ws
        self.user_id = user_id
        self.last_seen = datetime.utcnow()

conns: dict[int, Conn] = {}
_REDIS = None

# Simple per-user rate limiter for WS RPCs
_WS_RL: dict[int, deque] = {}

def _ws_allow(uid: int, limit: int, window_sec: int) -> bool:
    now = time.time()
    dq = _WS_RL.get(uid)
    if dq is None:
        dq = deque()
        _WS_RL[uid] = dq
    cutoff = now - window_sec
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) >= limit:
        return False
    dq.append(now)
    return True


async def auth_ws(ws: WebSocket) -> int:
    # Enforce Origin check to mitigate WS-CSRF
    try:
      origin = ws.headers.get("origin")
    except Exception:
      origin = None
    allowed = set([o.strip() for o in (os.getenv("ALLOW_ORIGINS", "").split(",")) if o.strip()])
    if not allowed:
        allowed = {
            "http://localhost:3000",
            "https://studio-nn.vercel.app",
            "https://studio-nn.online",
            "https://www.studio-nn.online",
        }
    if origin and origin not in allowed:
        try:
            await ws.close(code=4403, reason="forbidden origin")
        except Exception:
            pass
        raise WebSocketDisconnect

    cookie = ws.headers.get("cookie") or ws.headers.get("Cookie") or ""
    token = None
    for part in cookie.split(";"):
        k, _, v = part.strip().partition("=")
        if k == "access_token":
            token = v
            break
    if not token:
        # No token: close gracefully before aborting to avoid handshake warnings
        try:
            await ws.close(code=4401, reason="no token")
        except Exception:
            pass
        # Do not accept invalid connections
        raise WebSocketDisconnect
    try:
        # Allow small leeway to reduce flakiness around token rotation
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=["HS256"],
            options={"verify_exp": True},
        )
        user_id = int(payload.get("user_id"))
        return user_id
    except ExpiredSignatureError:
        # Close gracefully with a specific code; avoid noisy tracebacks
        try:
            await ws.close(code=4401, reason="token expired")
        except Exception:
            pass
        raise WebSocketDisconnect
    except JWTError:
        try:
            await ws.close(code=4401)
        except Exception:
            pass
        raise WebSocketDisconnect


async def mark_online(user_id: int, flag: bool):
    db = SessionLocal()
    try:
        auth = db.query(models.Auth).filter(models.Auth.user_id == user_id).first()
        if auth:
            auth.is_online = flag
            auth.last_login = datetime.utcnow()
            db.commit()
    finally:
        db.close()


@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    try:
        user_id = await auth_ws(ws)
    except WebSocketDisconnect:
        # auth failed/expired; connection already closed above
        return

    # Only accept after successful auth
    await ws.accept()

    # Enforce single active connection per user
    old = conns.get(user_id)
    if old is not None:
        try:
            await old.ws.close(code=1000)
        except Exception:
            pass
        conns.pop(user_id, None)

    this_conn = Conn(ws, user_id)
    conns[user_id] = this_conn
    await mark_online(user_id, True)
    # broadcast + publish presence online
    try:
        await _broadcast_presence(user_id, True)
        if _REDIS is not None:
            await _REDIS.publish("presence", json.dumps({"user_id": user_id, "is_online": True}))
    except Exception:
        pass

    # Catch-up: deliver unread notifications that were created while user was offline
    try:
        db = SessionLocal()
        try:
            unread = (
                db.query(models.Notification)
                .filter(models.Notification.receiver_id == user_id, models.Notification.is_read == False)  # noqa: E712
                .order_by(models.Notification.created_at.asc())
                .all()
            )
            for n in unread:
                # If connection has been superseded, stop
                if conns.get(user_id) is not this_conn:
                    break
                payload = {
                    "id": n.id,
                    "sender_id": n.sender_id,
                    "receiver_id": n.receiver_id,
                    "message_text": n.message_text,
                    "created_at": n.created_at.isoformat() if n.created_at else None,
                }
                try:
                    await ws.send_text(json.dumps({"type": "event", "event": "notification.new", "payload": payload}))
                except Exception:
                    break
        finally:
            db.close()
    except Exception:
        # Ignore catch-up errors to avoid breaking the session
        pass

    async def pinger():
        while conns.get(user_id) is not None:
            await asyncio.sleep(PING_INTERVAL)
            try:
                await ws.send_text(json.dumps({"type": "event", "event": "ping", "payload": {"ts": datetime.utcnow().timestamp()}}))
            except Exception:
                break

    ping_task = asyncio.create_task(pinger())
    try:
        while True:
            raw = await ws.receive_text()
            data = json.loads(raw)
            messages = data["messages"] if data.get("type") == "batch" else [data]
            # Ignore messages if this connection was superseded
            if conns.get(user_id) is not this_conn:
                break
            for m in messages:
                mtype = m.get("type"); kind = m.get("kind"); mid = m.get("id")
                if mid:
                    try:
                        await ws.send_text(json.dumps({"type": "ack", "id": mid}))
                    except Exception:
                        pass
                if kind == "event":
                    if mtype in ("pong", "presence.heartbeat"):
                        if user_id in conns:
                            conns[user_id].last_seen = datetime.utcnow()
                    elif mtype == "presence.offline":
                        await mark_online(user_id, False)
                elif kind == "rpc":
                    if mtype == "notifications.send":
                        # Rate-limit sending notifications per user (e.g., 20 per 60s)
                        if not _ws_allow(user_id, int(os.getenv("WS_SEND_LIMIT", "20")), int(os.getenv("WS_SEND_WINDOW", "60"))):
                            await ws.send_text(json.dumps({"type": "rpc_error", "id": mid, "error": {"message": "Rate limit exceeded", "code": 429}}))
                            continue
                        payload_in = m.get("payload", {}) or {}
                        receiver_id = int(payload_in.get("receiver_id"))
                        message_text = str(payload_in.get("message_text", ""))[:100]
                        if not receiver_id or not message_text:
                            await ws.send_text(json.dumps({"type": "rpc_error", "id": mid, "error": {"message": "Invalid payload", "code": 400}}))
                            continue
                        db = SessionLocal()
                        try:
                            note = models.Notification(
                                sender_id=user_id,
                                receiver_id=receiver_id,
                                message_text=message_text,
                            )
                            db.add(note)
                            db.commit()
                            db.refresh(note)
                            result = {"id": note.id, "created_at": note.created_at.isoformat() if note.created_at else None}
                        finally:
                            db.close()
                        # Push WS event to receiver immediately (no DB NOTIFY required)
                        try:
                            payload = {
                                "id": result.get("id"),
                                "sender_id": user_id,
                                "receiver_id": receiver_id,
                                "message_text": message_text,
                                "created_at": result.get("created_at"),
                            }
                            msg = json.dumps({"type": "event", "event": "notification.new", "payload": payload})
                            c = conns.get(receiver_id)
                            if c is not None:
                                await c.ws.send_text(msg)
                            # publish to Redis for other instances
                            if _REDIS is not None:
                                try:
                                    await _REDIS.publish("notifications", json.dumps(payload))
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        await ws.send_text(json.dumps({"type": "rpc_result", "id": mid, "result": result}))
                    elif mtype == "notifications.ack":
                        payload_in = m.get("payload", {}) or {}
                        nid = int(payload_in.get("id", 0))
                        if not nid:
                            await ws.send_text(json.dumps({"type": "rpc_error", "id": mid, "error": {"message": "Invalid id", "code": 400}}))
                            continue
                        db = SessionLocal()
                        try:
                            q = db.query(models.Notification).filter(models.Notification.id == nid, models.Notification.receiver_id == user_id)
                            obj = q.first()
                            if obj is None:
                                await ws.send_text(json.dumps({"type": "rpc_error", "id": mid, "error": {"message": "Not found", "code": 404}}))
                            else:
                                obj.is_read = True
                                db.commit()
                                await ws.send_text(json.dumps({"type": "rpc_result", "id": mid, "result": {"ok": True}}))
                        finally:
                            db.close()
                    if mtype == "users.with_info":
                        page = int(m.get("payload", {}).get("page", 1))
                        limit = int(m.get("payload", {}).get("limit", 10))
                        db = SessionLocal()
                        try:
                            total = db.query(models.User).count()
                            offset = (page - 1) * limit
                            users = (
                                db.query(models.User)
                                .order_by(models.User.id.asc())
                                .offset(offset)
                                .limit(limit)
                                .all()
                            )
                            user_ids = [u.id for u in users]
                            auth_map = {
                                a.user_id: a for a in db.query(models.Auth).filter(models.Auth.user_id.in_(user_ids)).all()
                            } if user_ids else {}
                            # Pull profile genders to support filtering on frontend
                            prof_map = {
                                p.user_id: p for p in db.query(models.UserProfile).filter(models.UserProfile.user_id.in_(user_ids)).all()
                            } if user_ids else {}
                            items = []
                            for u in users:
                                a = auth_map.get(u.id)
                                items.append({
                                    "id": u.id,
                                    "name": u.name,
                                    "gender": (prof_map.get(u.id).gender if prof_map.get(u.id) else None),
                                    "created_at": u.created_at.isoformat() if u.created_at else None,
                                    "role": a.role if a else None,
                                    "is_online": a.is_online if a else False,
                                    "last_login": a.last_login.isoformat() if (a and a.last_login) else None,
                                })
                            result = {
                                "users": items,
                                "pagination": {
                                    "page": page,
                                    "limit": limit,
                                    "total": total,
                                    "pages": (total + limit - 1) // limit,
                                },
                            }
                        finally:
                            db.close()
                        await ws.send_text(json.dumps({"type": "rpc_result", "id": mid, "result": result}))
                    elif mtype == "user.profile":
                        target_id = int(m.get("payload", {}).get("user_id", user_id))
                        db = SessionLocal()
                        try:
                            u = db.query(models.User).filter(models.User.id == target_id).first()
                            if not u:
                                await ws.send_text(json.dumps({"type": "rpc_error", "id": mid, "error": {"message": "User not found", "code": 404}}))
                                continue
                            a = db.query(models.Auth).filter(models.Auth.user_id == target_id).first()
                            prof = db.query(models.UserProfile).filter(models.UserProfile.user_id == target_id).first()
                            profile = {
                                "id": u.id,
                                "name": u.name,
                                "created_at": u.created_at.isoformat() if u.created_at else None,
                                "gender": (prof.gender if prof else None),
                                "age": (prof.age if prof else None),
                                "avatar_url": (prof.avatar_url if prof else None),
                                "role": a.role if a else None,
                                "is_online": a.is_online if a else False,
                                "last_login": a.last_login.isoformat() if (a and a.last_login) else None,
                            }
                        finally:
                            db.close()
                        await ws.send_text(json.dumps({"type": "rpc_result", "id": mid, "result": profile}))
                    elif mtype == "system.statistics":
                        db = SessionLocal()
                        try:
                            total_users = db.query(models.User).count()
                            online_users = db.query(models.Auth).filter(models.Auth.is_online == True).count()
                            stats = {
                                "total_users": total_users,
                                "online_users": online_users,
                            }
                        finally:
                            db.close()
                        await ws.send_text(json.dumps({"type": "rpc_result", "id": mid, "result": stats}))
    except WebSocketDisconnect:
        pass
    finally:
        ping_task.cancel()
        # Only clear mapping if this connection is still the active one
        if conns.get(user_id) is this_conn:
            conns.pop(user_id, None)
            await mark_online(user_id, False)
            try:
                await _broadcast_presence(user_id, False)
                if _REDIS is not None:
                    await _REDIS.publish("presence", json.dumps({"user_id": user_id, "is_online": False}))
            except Exception:
                pass


async def watchdog():
    while True:
        now = datetime.utcnow()
        to_close = [uid for uid, c in list(conns.items()) if (now - c.last_seen) > timedelta(seconds=PONG_TIMEOUT)]
        for uid in to_close:
            try:
                await conns[uid].ws.close()
            except Exception:
                pass
            conns.pop(uid, None)
            await mark_online(uid, False)
        await asyncio.sleep(10)


@router.on_event("startup")
async def start_watchdog():
    asyncio.create_task(watchdog())
    # Init Redis for presence pub/sub
    global _REDIS
    url = os.getenv("REDIS_URL") or getattr(settings, 'REDIS_URL', None)
    if url and redis_from_url is not None:
        try:
            _REDIS = redis_from_url(url, encoding="utf-8", decode_responses=True)
            await _REDIS.ping()
            async def _sub_presence():
                try:
                    pubsub = _REDIS.pubsub()
                    await pubsub.subscribe("presence")
                    async for m in pubsub.listen():
                        if not m or m.get('type') != 'message':
                            continue
                        try:
                            data = json.loads(m.get('data') or '{}')
                            uid = int(data.get('user_id'))
                            flag = bool(data.get('is_online'))
                            await _broadcast_presence(uid, flag)
                        except Exception:
                            continue
                except Exception:
                    pass
            asyncio.create_task(_sub_presence())
            async def _sub_notifications():
                try:
                    pubsub = _REDIS.pubsub()
                    await pubsub.subscribe("notifications")
                    async for m in pubsub.listen():
                        if not m or m.get('type') != 'message':
                            continue
                        try:
                            data = json.loads(m.get('data') or '{}')
                            rid = int(data.get('receiver_id') or 0)
                            msg = json.dumps({"type": "event", "event": "notification.new", "payload": data})
                            c = conns.get(rid)
                            if c is not None:
                                await c.ws.send_text(msg)
                        except Exception:
                            continue
                except Exception:
                    pass
            asyncio.create_task(_sub_notifications())
        except Exception:
            _REDIS = None

async def _broadcast_presence(user_id: int, is_online: bool):
    payload = {"user_id": user_id, "is_online": bool(is_online)}
    msg = json.dumps({"type": "event", "event": "presence.update", "payload": payload})
    for c in list(conns.values()):
        try:
            await c.ws.send_text(msg)
        except Exception:
            pass


def _listen_notifications(loop: asyncio.AbstractEventLoop):
    try:
        conn = psycopg2.connect(settings.DATABASE_URL)
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        cur.execute("LISTEN notifications_channel;")
        while True:
            _select.select([conn], [], [])
            conn.poll()
            while conn.notifies:
                notify = conn.notifies.pop(0)
                try:
                    data = json.loads(notify.payload)
                except Exception:
                    continue
                receiver_id = int(data.get("receiver_id") or 0)

                async def _send():
                    c = conns.get(receiver_id)
                    if c is not None:
                        try:
                            await c.ws.send_text(json.dumps({"type": "event", "event": "notification.new", "payload": data}))
                        except Exception:
                            pass

                try:
                    asyncio.run_coroutine_threadsafe(_send(), loop)
                except Exception:
                    pass
    except Exception:
        # Listener exits on error; in production, add supervision/restart
        return


@router.on_event("startup")
async def start_notifications_listener():
    loop = asyncio.get_event_loop()
    t = threading.Thread(target=_listen_notifications, args=(loop,), daemon=True)
    t.start()
