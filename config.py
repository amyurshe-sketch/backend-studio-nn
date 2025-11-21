from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str
    SECRET_KEY: str
    REDIS_URL: str | None = None
    AI_AGENT_URL: str | None = None
    AI_AGENT_SECRET: str | None = None


settings = Settings()
