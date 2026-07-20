from functools import lru_cache

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

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True
    )


@lru_cache
def get_settings():
    return Settings()


settings = get_settings()