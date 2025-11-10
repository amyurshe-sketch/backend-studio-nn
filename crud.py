from sqlalchemy.orm import Session
import models
import schemas
from schemas import UserCreate
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import time
import re
import secrets
import hashlib
from logger import logger

# Импортируем настройки из config
from config import settings

# Локальные значения по умолчанию для устаревших частей (если они будут использоваться)
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30
SECRET_KEY = settings.SECRET_KEY

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_refresh_token(db: Session, user_id: int) -> str:
    """Создать и сохранить refresh токен для пользователя"""
    raw_token = secrets.token_urlsafe(48)
    token_hash = _hash_token(raw_token)
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    db.query(models.RefreshToken).filter(
        models.RefreshToken.user_id == user_id
    ).delete(synchronize_session=False)

    refresh = models.RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at
    )
    db.add(refresh)
    db.commit()
    return raw_token


def verify_refresh_token(db: Session, refresh_token: str):
    """Проверить refresh токен и вернуть запись, если она действительна"""
    token_hash = _hash_token(refresh_token)
    record = db.query(models.RefreshToken).filter(
        models.RefreshToken.token_hash == token_hash
    ).first()

    if not record:
        return None

    if record.expires_at < datetime.utcnow():
        db.delete(record)
        db.commit()
        return None

    return record


def rotate_refresh_token(db: Session, refresh_token: str):
    """Проверить refresh токен и выдать новый"""
    record = verify_refresh_token(db, refresh_token)
    if not record:
        return None

    user_id = record.user_id
    db.delete(record)
    db.commit()
    new_refresh = create_refresh_token(db, user_id)
    return user_id, new_refresh


def revoke_user_refresh_tokens(db: Session, user_id: int):
    """Удалить refresh токены пользователя"""
    db.query(models.RefreshToken).filter(
        models.RefreshToken.user_id == user_id
    ).delete(synchronize_session=False)
    db.commit()


def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        return False

def get_user_by_id(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_name(db: Session, name: str):
    """Находит пользователя по имени (регистрозависимо)"""
    return db.query(models.User).filter(models.User.name == name).first()

# Email no longer used
def get_user_by_email(db: Session, email: str):
    return None

def get_auth_by_user_id(db: Session, user_id: int):
    return db.query(models.Auth).filter(models.Auth.user_id == user_id).first()

## Telegram upsert removed

# Username/password authentication removed

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def refresh_session(db: Session, refresh_token: str):
    """Обновляет access токен по действующему refresh токену"""
    rotation = rotate_refresh_token(db, refresh_token)
    if not rotation:
        return None

    user_id, new_refresh_token = rotation
    user = get_user_by_id(db, user_id)
    if not user:
        return None

    auth = get_auth_by_user_id(db, user_id)
    if not auth:
        return None

    auth.last_login = datetime.utcnow()
    auth.is_online = True
    db.commit()

    access_token = create_access_token(
        {"user_id": user.id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "user": user,
        "auth": auth
    }

def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()

def create_user(db: Session, user: schemas.UserCreate):
    """Создание пользователя с минимальными полями (name + пароль)."""
    existing_user = db.query(models.User).filter(models.User.name == user.name).first()
    if existing_user:
        raise ValueError("Пользователь с таким именем уже существует")

    db_user = models.User(name=user.name)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    password_hash = get_password_hash(user.password)
    db_auth = models.Auth(user_id=db_user.id, password_hash=password_hash, role="user")
    db.add(db_auth)
    db.commit()

    return db_user

# Email verification flow removed: no code generation / mail sending

def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def create_notification(db: Session, sender_id: int, notification_data: schemas.NotificationCreate):
    """Создать новое уведомление"""
    try:
        db_notification = models.Notification(
            sender_id=sender_id,
            receiver_id=notification_data.receiver_id,
            message_text=notification_data.message_text
        )
        db.add(db_notification)
        db.commit()
        db.refresh(db_notification)
        
        return db_notification
        
    except Exception as e:
        db.rollback()
        raise

def get_user_notifications(db: Session, user_id: int, unread_only: bool = False):
    """Получить уведомления пользователя.

    Если unread_only=True — вернуть только непрочитанные, иначе вернуть все уведомления.
    """
    query = db.query(models.Notification).filter(
        models.Notification.receiver_id == user_id
    )

    if unread_only:
        query = query.filter(models.Notification.is_read == False)

    return query.order_by(models.Notification.created_at.desc()).all()

def mark_notification_as_read(db: Session, notification_id: int):
    """Пометить уведомление как прочитанное (и автоматически удалить текст)"""
    notification = db.query(models.Notification).filter(models.Notification.id == notification_id).first()
    if notification and not notification.is_read:
        notification.is_read = True
        notification.message_text = 'deleted'
        db.commit()
    return notification

def get_unread_notifications_count(db: Session, user_id: int):
    """Получить количество непрочитанных уведомлений"""
    return db.query(models.Notification).filter(
        models.Notification.receiver_id == user_id,
        models.Notification.is_read == False
    ).count()
