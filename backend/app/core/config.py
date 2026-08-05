from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "SecureCode Copilot"
    app_version: str = "2.0.0"
    api_prefix: str = "/api/v1"
    app_url: str = "http://localhost:5173"

    llm_provider: str = "heuristic"  # heuristic | local | openai
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    model_path: str = "../ml/inference/checkpoints/codet5-lora"
    use_ml_detector: bool = True
    use_ml_discovery: bool = False

    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"

    # SaaS
    database_url: str = "sqlite:///./scc.db"
    jwt_secret: str = "dev-change-me-scc-jwt-secret-min-32-chars!!"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24
    refresh_token_expire_days: int = 14
    bcrypt_rounds: int = 12

    email_server: str = ""
    email_from: str = "noreply@securecode.local"
    email_enabled: bool = False

    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    billing_mock: bool = True

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
