from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APPSEC_", case_sensitive=False)
    base_dir: Path = Path(__file__).resolve().parents[2]

    app_name: str = "App Security Audit"
    api_token: str = Field(default="changeme-token")
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    database_url: str = Field(default="sqlite:///./app_security_audit.db")
    export_dir: Path = Field(default=Path("./exports"))
    dev_recreate_db: bool = False
    command_timeout_seconds: int = 8
    find_timeout_seconds: int = 12
    command_output_limit: int = 20000
    default_scan_mode: str = "agentless"
    agent_endpoint: str | None = None
    agent_token: str | None = None
    rules_file: Path = Field(default=Path(__file__).resolve().parents[1] / "config" / "rules.json")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
