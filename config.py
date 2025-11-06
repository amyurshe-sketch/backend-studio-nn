from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str

    SMTP_HOST: str = "smtp.yandex.ru"
    SMTP_PORT: int = 465
    SMTP_USER: str
    SMTP_PASS: str
    SMTP_FROM_NAME: str = "Studio NN"
    SMTP_USE_TLS: bool = True

    class Config:
        env_file = ".env"


settings = Settings()
