from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from datetime import datetime
import re

class UserBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=50, description="Имя пользователя")
    age: int = Field(..., ge=1, le=120, description="Возраст от 1 до 120 лет")
    email: str = Field(..., description="Email адрес")
    gender: str = Field(..., description="Пол обязателен для выбора")

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not v:
            raise ValueError('Email обязателен')
        
        # Проверка формата email с поддержкой плюс-адресов
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, v):
            raise ValueError('Некорректный формат email')
        
        # Проверка домена
        domain = v.split('@')[-1]
        if domain in ['example.com', 'test.com', 'localhost']:
            raise ValueError('Использование тестовых доменов запрещено')
            
        return v.lower()  # Приводим к нижнему регистру

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Имя не может быть пустым')
        
        # Проверка на допустимые символы
        if not re.match(r'^[a-zA-Zа-яА-Я0-9_\- ]+$', v):
            raise ValueError('Имя может содержать только буквы, цифры, пробелы, дефисы и подчеркивания')
        
        if len(v) < 2:
            raise ValueError('Имя должно содержать минимум 2 символа')
            
        return v.strip()

    @field_validator('gender')
    @classmethod
    def validate_gender(cls, v):
        allowed_genders = ['мужской', 'женский']
        if v not in allowed_genders:
            raise ValueError(f'Пол должен быть одним из: {", ".join(allowed_genders)}')
        return v

class UserCreate(UserBase):
    password: str = Field(..., min_length=3, max_length=100, description="Пароль от 3 до 100 символов")

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not v.strip():
            raise ValueError('Пароль не может быть пустым')
        
        # Простые проверки пароля
        if len(v) < 3:
            raise ValueError('Пароль должен содержать минимум 3 символа')
            
        return v

class User(UserBase):
    id: int
    
    class Config:
        from_attributes = True

class UserResponse(BaseModel):
    id: int
    name: str
    age: int
    gender: str
    
    class Config:
        from_attributes = True

class PaginatedUsers(BaseModel):
    users: List[UserResponse]
    pagination: dict

class UserInfo(BaseModel):
    id: int
    name: Optional[str] = None
    age: Optional[int] = None
    gender: Optional[str] = None
    email: str
    created_at: Optional[datetime] = None
    is_verified: bool
    role: Optional[str] = None
    is_online: bool = False
    last_login: Optional[datetime] = None

# Схемы для аутентификации
# Username/password auth removed

class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    name: str
    role: str
    refresh_token: str

class TokenData(BaseModel):
    user_id: Optional[int] = None
    role: Optional[str] = None

class RefreshTokenRequest(BaseModel):
    refresh_token: str

# Telegram Login payload
class TelegramAuth(BaseModel):
    id: int
    first_name: str | None = None
    last_name: str | None = None
    username: str | None = None
    photo_url: str | None = None
    auth_date: int
    hash: str

# Email verification schemas were removed

# Схемы для сообщений
class MessageBase(BaseModel):
    receiver_id: int
    message_text: str

class MessageCreate(MessageBase):
    pass

class Message(MessageBase):
    id: int
    sender_id: int
    created_at: datetime
    is_read: bool
    
    class Config:
        from_attributes = True

class MessageWithUsers(Message):
    sender_name: str
    receiver_name: str

class Conversation(BaseModel):
    other_user_id: int
    other_user_name: str
    last_message: Optional[str] = None
    last_message_time: Optional[datetime] = None
    unread_count: int = 0

# Схемы для уведомлений
class NotificationBase(BaseModel):
    receiver_id: int
    message_text: str = Field(..., max_length=100)

class NotificationCreate(NotificationBase):
    pass

class Notification(NotificationBase):
    id: int
    sender_id: int
    created_at: datetime
    is_read: bool
    
    class Config:
        from_attributes = True

class NotificationWithSender(Notification):
    sender_name: str

    
