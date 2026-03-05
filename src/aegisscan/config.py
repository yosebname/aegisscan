"""설정 로드 (환경변수 / .env)."""
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # DB
    database_url: str = "sqlite+aiosqlite:///./aegisscan.db"

    # 외부 API (선택)
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None

    # 스캔 기본값
    default_timeout_sec: float = 3.0
    default_retries: int = 2
    default_rate_limit_per_sec: int = 100

    # 보고서
    report_output_dir: Path = Path("./reports")


def get_settings() -> Settings:
    return Settings()
