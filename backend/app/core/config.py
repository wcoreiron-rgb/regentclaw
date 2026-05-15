from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "RegentClaw"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://regentclaw:regentclaw@db:5432/regentclaw"
    DATABASE_URL_SYNC: str = "postgresql://regentclaw:regentclaw@db:5432/regentclaw"

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"

    # Security
    SECRET_KEY: str = "change-me-in-production-use-a-long-random-string"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # CORS
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000", "http://frontend:3000"]

    class Config:
        env_file = ".env"


settings = Settings()
