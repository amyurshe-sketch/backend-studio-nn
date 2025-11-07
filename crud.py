from sqlalchemy.orm import Session
import models
import schemas
from schemas import UserCreate
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from email.message import EmailMessage
import asyncio
import time
import re
import random
import aiosmtplib
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

def generate_verification_code() -> str:
    """Генерирует 6-значный код подтверждения."""
    return str(random.randint(100000, 999999))


async def send_verification_email(user_email: str, code: str):
    """
    Отправка письма с кодом подтверждения через SMTP Яндекс.
    """
    smtp_host = settings.SMTP_HOST
    smtp_port = settings.SMTP_PORT
    smtp_user = settings.SMTP_USER
    smtp_pass = settings.SMTP_PASS
    from_name = settings.SMTP_FROM_NAME
    use_tls = settings.SMTP_USE_TLS

    subject = "Код подтверждения регистрации"
    text_content = f"Ваш код подтверждения: {code}"

    html_content = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background-color:#f4f4f4; padding:30px;">
        <div style="max-width:500px;margin:auto;background:#fff;padding:25px;border-radius:12px;
                    box-shadow:0 0 10px rgba(0,0,0,0.1);">
          <h2 style="color:#111; text-align:center; font-weight:600;">Studio NN</h2>
          <p style="font-size:16px; color:#444; line-height:1.6;">
            Здравствуйте! <br><br>
            Спасибо за регистрацию на <b>Studio NN</b>.<br><br>
            Ваш код подтверждения:
          </p>
          <div style="text-align:center; margin:30px 0;">
            <span style="display:inline-block; font-size:32px; font-weight:bold; 
                         letter-spacing:4px; color:#222; border:2px solid #222;
                         padding:10px 20px; border-radius:8px;">
              {code}
            </span>
          </div>
          <p style="color:#888; font-size:14px; text-align:center;">
            Если вы не запрашивали код — просто проигнорируйте это письмо.
          </p>
        </div>
      </body>
    </html>
    """

    msg = EmailMessage()
    msg["From"] = f"{from_name} <{smtp_user}>"
    msg["To"] = user_email
    msg["Subject"] = subject
    msg.set_content(text_content)
    msg.add_alternative(html_content, subtype="html")

    # Connection strategy:
    # - If implicit TLS (port 465 or SMTP_USE_TLS=true), use TLS.
    # - Otherwise prefer STARTTLS on submission ports (e.g., 587).
    start_tls = False
    use_tls_flag = bool(use_tls)
    if smtp_port == 465:
        use_tls_flag = True
        start_tls = False
    elif smtp_port in (587, 25):
        # Many providers require STARTTLS on 587
        use_tls_flag = False if use_tls_flag is False else False
        start_tls = True
    try:
        await aiosmtplib.send(
            msg,
            hostname=smtp_host,
            port=smtp_port,
            username=smtp_user,
            password=smtp_pass,
            use_tls=use_tls_flag,
            start_tls=start_tls,
            timeout=20.0,
            validate_certs=True,
        )
        logger.info(f"✅ Verification email sent to {user_email}")
    except Exception as e:
        logger.error(f"❌ Failed to send email to {user_email}: {e}")
        raise

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

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

def authenticate_user(db: Session, name: str, password: str):
    """Аутентифицирует пользователя по имени и паролю"""
    # Фиксированное время выполнения для защиты от timing attacks
    start_time = time.time()
    
    user = get_user_by_name(db, name)
    if not user:
        # Всегда выполняем хеширование для выравнивания времени
        pwd_context.hash("dummy_password")
        elapsed = time.time() - start_time
        if elapsed < 0.5:  # Минимальное время аутентификации
            time.sleep(0.5 - elapsed)
        return None
        
    auth = get_auth_by_user_id(db, user.id)
    if not auth or not auth.password_hash:
        pwd_context.hash("dummy_password")
        elapsed = time.time() - start_time
        if elapsed < 0.5:
            time.sleep(0.5 - elapsed)
        return None
    
    password_valid = verify_password(password, auth.password_hash)
    
    # Выравниваем время ответа
    elapsed = time.time() - start_time
    if elapsed < 0.5:
        time.sleep(0.5 - elapsed)
        
    if not password_valid:
        return None
        
    return {"user": user, "auth": auth}

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
    
    # Создаем запись аутентификации с хешем пароля
    password_hash = get_password_hash(user.password)
    
    db_auth = models.Auth(
        user_id=db_user.id,
        password_hash=password_hash,
        role="user"
    )
    db.add(db_auth)
    db.commit()
    
    return db_user

async def initiate_registration(db: Session, user: UserCreate):
    """
    Начинает регистрацию пользователя: создаёт токен, отправляет код на e-mail.
    """
    email = user.email.lower()
    code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    token = db.query(models.RegistrationToken).filter_by(email=email).first()
    if token:
        token.code = code
        token.expires_at = expires_at
    else:
        token = models.RegistrationToken(email=email, code=code, expires_at=expires_at)
        db.add(token)
    
    # Persist initial registration data in the token until verification
    # Hash the password and store all provided fields
    try:
        token.name = user.name
        token.age = user.age
        token.gender = user.gender
        token.password_hash = get_password_hash(user.password)
    except Exception:
        # If legacy DB doesn't have columns, columns are added on startup; ignore silently here
        pass
    db.commit()

    asyncio.create_task(send_verification_email(email, code))

    return {
        "message": "Код подтверждения отправлен",
        "email": email,
        "code_sent": True,
    }

async def complete_registration(db: Session, email: str, code: str):
    """
    Завершает регистрацию после проверки кода.
    """
    token = (
        db.query(models.RegistrationToken)
        .filter_by(email=email.lower(), code=code)
        .first()
    )

    if not token:
        return {"error": "Invalid or expired code"}

    if token.expires_at < datetime.utcnow():
        return {"error": "Code expired"}

    existing_user = db.query(models.User).filter_by(email=email.lower()).first()
    if existing_user:
        return {"error": "User already exists"}

    # Build user from preserved registration data if available
    user_kwargs = {
        "email": email.lower(),
        "is_verified": True,
    }
    if hasattr(token, "name") and token.name:
        user_kwargs["name"] = token.name
    if hasattr(token, "age") and token.age is not None:
        user_kwargs["age"] = token.age
    if hasattr(token, "gender") and token.gender:
        user_kwargs["gender"] = token.gender

    # Ensure a username exists; default to email local-part when absent
    if not user_kwargs.get("name"):
        user_kwargs["name"] = email.split("@")[0]

    user = models.User(**user_kwargs)
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create auth record; prefer preserved password_hash, otherwise generate random
    try:
        pwd_hash = None
        if hasattr(token, "password_hash") and token.password_hash:
            pwd_hash = token.password_hash
        else:
            pwd_hash = get_password_hash(secrets.token_urlsafe(24))

        db_auth = models.Auth(
            user_id=user.id,
            password_hash=pwd_hash,
            role="user",
        )
        db.add(db_auth)
        db.commit()
    except Exception:
        db.rollback()

    db.delete(token)
    db.commit()

    return {
        "message": "Registration completed",
        "user_id": user.id,
        "username": user.name,
    }

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
