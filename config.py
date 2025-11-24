from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str
    SECRET_KEY: str
    REDIS_URL: Optional[str] = None
    AI_AGENT_URL: Optional[str] = None
    AI_AGENT_SECRET: Optional[str] = None


settings = Settings()
