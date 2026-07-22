from functools import lru_cache
from sqlalchemy.engine import URL
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    # Application
    APP_NAME: str
    APP_VERSION: str
    ENVIRONMENT: str
    DEBUG: bool

    # API
    HOST: str
    PORT: int

    # CORS
    ALLOWED_ORIGINS: str

    # Model
    LOCAL_MODEL_PATH: str

    # AWS
    AWS_REGION: str
    S3_BUCKET: str
    S3_MODEL_KEY: str

    # Database
    DATABASE_HOST: str
    DATABASE_PORT: int
    DATABASE_NAME: str
    DATABASE_USERNAME: str
    DATABASE_PASSWORD: str

    @property
    def database_url(self):
        return URL.create(
            drivername="postgresql+psycopg2",
            username=self.DATABASE_USERNAME,
            password=self.DATABASE_PASSWORD,
            host=self.DATABASE_HOST,
            port=self.DATABASE_PORT,
            database=self.DATABASE_NAME,
        )

    # JWT
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True
    )

    # MAIL
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_PORT: int
    MAIL_SERVER: str
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False
    MAIL_FROM_NAME: str = "Phishing Guardian"

    # REDIS
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None


@lru_cache
def get_settings():
    return Settings()


settings = get_settings()