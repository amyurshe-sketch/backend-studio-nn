from pydantic import BaseModel, Field, field_validator, model_validator
from typing import List, Optional, Literal
from datetime import datetime
import re

# --- AI chat schemas ---
Role = Literal["system", "user", "assistant"]


class AIChatMessage(BaseModel):
    role: Role = "user"
    content: str = Field(..., min_length=1)


class AIChatRequest(BaseModel):
    message: str = Field(..., min_length=1)
    chat_id: Optional[str] = None
    history: List[AIChatMessage] = Field(default_factory=list)
    channel: str = Field(default="web")
    user_id: Optional[int] = None
    user_profile: Optional[dict] = None


class AIChatResponse(BaseModel):
    answer: str
    chat_id: str
    channel: str = "web"

class UserBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=50, description="Имя пользователя")

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Имя не может быть пустым')
        if not re.match(r'^[a-zA-Zа-яА-Я0-9_\- ]+$', v):
            raise ValueError('Имя может содержать только буквы, цифры, пробелы, дефисы и подчеркивания')
        if len(v) < 2:
            raise ValueError('Имя должно содержать минимум 2 символа')
        return v.strip()

class UserCreate(UserBase):
    password: str = Field(..., min_length=5, max_length=100, description="Пароль от 5 до 100 символов")

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not v.strip():
            raise ValueError('Пароль не может быть пустым')
        
        # Простые проверки пароля
        if len(v) < 5:
            raise ValueError('Пароль должен содержать минимум 5 символов')
        
        # Запрещённые самые распространённые и слабые пароли (50)
        banned_passwords = {
            '123456','password','123456789','12345','12345678','qwerty','abc123','football','1234567','111111',
            '123123','welcome','monkey','login','princess','solo','letmein','master','sunshine','hello',
            'freedom','whatever','qazwsx','trustno1','dragon','iloveyou','passw0rd','admin','root','000000',
            '1q2w3e4r','1234','qwertyuiop','starwars','superman','michael','shadow','pokemon','zaq12wsx','password1',
            'asdfgh','baseball','football1','jennifer','hunter','buster','soccer','killer','google','batman',
        }
        if v.strip().lower() in banned_passwords:
            raise ValueError('Этот пароль слишком распространён и запрещён. Выберите более надёжный пароль.')
        
        return v

    @model_validator(mode='after')
    def validate_password_not_contains_name(self):
        try:
            name = (self.name or '').strip().lower()
            pwd = (self.password or '').strip().lower()
            if name and name in pwd:
                raise ValueError('Пароль не должен содержать имя пользователя')
        except AttributeError:
            pass
        return self

class User(UserBase):
    id: int
    
    class Config:
        from_attributes = True

class UserResponse(BaseModel):
    id: int
    name: str
    
    class Config:
        from_attributes = True

class PaginatedUsers(BaseModel):
    users: List[UserResponse]
    pagination: dict

class UserInfo(BaseModel):
    id: int
    name: Optional[str] = None
    created_at: Optional[datetime] = None
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

# Login schema
class LoginRequest(BaseModel):
    name: str
    password: str


# User profile schemas
class UserProfileUpdate(BaseModel):
    gender: str | None = None
    age: int | None = Field(default=None, ge=1, le=120)
    about: str | None = Field(default=None, max_length=100)
    avatar_url: str | None = None

    @field_validator('gender')
    @classmethod
    def validate_gender(cls, v):
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None
        # allow common russian values or free-form 1-20 chars
        allowed = {'мужской', 'женский'}
        if v.lower() in allowed:
            return v
        if len(v) < 1 or len(v) > 20:
            raise ValueError('Некорректное значение пола')
        return v

class UserProfileOut(BaseModel):
    user_id: int
    gender: str | None = None
    age: int | None = None
    about: str | None = None
    avatar_url: str | None = None
    
    class Config:
        from_attributes = True

    
