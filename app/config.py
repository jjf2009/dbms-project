"""Application settings, read from environment / .env (NFR7)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    postgres_user: str = "siem"
    postgres_password: str = "siem_pw"
    postgres_db: str = "siem"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    app_secret: str = "change-me"
    app_port: int = 8000

    # Ingestion batching (FR10 / NFR1)
    batch_max_events: int = 1000
    batch_max_seconds: float = 1.0

    # Scheduler intervals (seconds)
    detect_interval: int = 10
    partition_interval: int = 3600
    archive_interval: int = 3600

    @property
    def dsn(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()
