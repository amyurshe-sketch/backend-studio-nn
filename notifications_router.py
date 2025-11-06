from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from database import get_db
from config import settings
import crud
import models
import schemas
from sse_router import publish_notification_event


router = APIRouter(tags=["notifications"])


ALGORITHM = "HS256"


def _current_user_id_from_bearer(request: Request) -> int:
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return int(user_id)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.post("/notifications", response_model=schemas.Notification)
def create_notification(
    data: schemas.NotificationCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    sender_id = _current_user_id_from_bearer(request)

    # Validate receiver exists
    receiver = crud.get_user_by_id(db, data.receiver_id)
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")

    notif = crud.create_notification(db, sender_id, data)
    # Push to receiver and sender via SSE (if connected)
    publish_notification_event(data.receiver_id)
    publish_notification_event(sender_id)
    return notif


@router.get("/notifications", response_model=list[schemas.Notification])
def list_notifications(
    request: Request,
    unread_only: bool = Query(False),
    db: Session = Depends(get_db),
):
    user_id = _current_user_id_from_bearer(request)
    items = crud.get_user_notifications(db, user_id, unread_only=unread_only)
    return items


@router.get("/notifications/sent", response_model=list[schemas.Notification])
def list_sent_notifications(request: Request, db: Session = Depends(get_db)):
    """List notifications the current user has sent (outbox)."""
    user_id = _current_user_id_from_bearer(request)
    items = (
        db.query(models.Notification)
        .filter(models.Notification.sender_id == user_id)
        .order_by(models.Notification.created_at.desc())
        .all()
    )
    return items


@router.get("/notifications/thread/{other_user_id}", response_model=list[schemas.Notification])
def conversation_with_user(
    other_user_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    """Return both incoming and outgoing notifications with a specific user."""
    user_id = _current_user_id_from_bearer(request)
    items = (
        db.query(models.Notification)
        .filter(
            (
                (models.Notification.sender_id == user_id)
                & (models.Notification.receiver_id == other_user_id)
            )
            | (
                (models.Notification.sender_id == other_user_id)
                & (models.Notification.receiver_id == user_id)
            )
        )
        .order_by(models.Notification.created_at.asc())
        .all()
    )
    return items


@router.post("/notifications/{notification_id}/read", response_model=schemas.Notification)
def mark_as_read(notification_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = _current_user_id_from_bearer(request)
    notif = db.query(models.Notification).filter(models.Notification.id == notification_id).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    if notif.receiver_id != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    updated = crud.mark_notification_as_read(db, notification_id)
    # Push update so clients can refresh unread counters
    publish_notification_event(user_id)
    return updated


@router.get("/notifications/unread-count")
def unread_count(request: Request, db: Session = Depends(get_db)):
    user_id = _current_user_id_from_bearer(request)
    count = crud.get_unread_notifications_count(db, user_id)
    return {"unread_count": count}
