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

def get_user_by_id(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_name(db: Session, name: str):
    """Находит пользователя по имени (регистрозависимо)"""
    return db.query(models.User).filter(models.User.name == name).first()

def get_user_by_email(db: Session, email: str):
    """Находит пользователя по email"""
    return db.query(models.User).filter(models.User.email == email).first()

def get_auth_by_user_id(db: Session, user_id: int):
    return db.query(models.Auth).filter(models.Auth.user_id == user_id).first()

# Telegram upsert: find or create a user by Telegram data
def upsert_user_from_telegram(db: Session, tg: dict):
    tg_id = int(tg.get('id'))
    username = (tg.get('username') or tg.get('first_name') or f'user_{tg_id}')

    # Prefer lookup by telegram_id now that email is optional
    user = db.query(models.User).filter(getattr(models.User, 'telegram_id') == tg_id).first()
    if not user:
        user = models.User(
            name=username,
            age=None,
            email=None,
            gender=None,
            is_verified=True,
        )
        # Set telegram fields if present (columns added on startup)
        try:
            setattr(user, 'telegram_id', tg_id)
            if tg.get('username'):
                setattr(user, 'telegram_username', tg.get('username'))
        except Exception:
            pass
        db.add(user)
        db.commit()
        db.refresh(user)

        db_auth = models.Auth(
            user_id=user.id,
            password_hash=get_password_hash(secrets.token_urlsafe(24)),
            role="user",
        )
        db.add(db_auth)
        db.commit()
    else:
        # Update telegram fields if missing
        changed = False
        try:
            if not getattr(user, 'telegram_id', None):
                setattr(user, 'telegram_id', tg_id)
                changed = True
            if tg.get('username') and getattr(user, 'telegram_username', None) != tg.get('username'):
                setattr(user, 'telegram_username', tg.get('username'))
                changed = True
        except Exception:
            pass
        if changed:
            db.commit()

    auth = get_auth_by_user_id(db, user.id)
    if auth:
        auth.last_login = datetime.utcnow()
        auth.is_online = True
        db.commit()

    return {"user": user, "auth": auth}
# Telegram upsert removed

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
    """Создание пользователя (простая версия без верификации)"""
    # Дополнительная проверка email на стороне сервера
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, user.email):
        raise ValueError("Некорректный формат email")
    
    # Проверка тестовых доменов (разрешаем yandex.ru и mail.ru)
    forbidden_domains = ['example.com', 'test.com', 'localhost']
    domain = user.email.split('@')[-1].lower()
    if domain in forbidden_domains:
        raise ValueError("Использование тестового домена запрещено")
    
    # Проверяем существующего пользователя
    existing_user = db.query(models.User).filter(
        (models.User.name == user.name) | 
        (models.User.email == user.email.lower())
    ).first()
    
    if existing_user:
        raise ValueError("Пользователь с такими данными уже существует")
    
    # Создаем пользователя
    db_user = models.User(
        name=user.name, 
        age=user.age, 
        email=user.email.lower(),
        gender=user.gender
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Создаем запись аутентификации (парольная аутентификация отключена; храним случайный хеш)
    password_hash = get_password_hash(secrets.token_urlsafe(24))

    db_auth = models.Auth(
        user_id=db_user.id,
        password_hash=password_hash,
        role="user"
    )
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
