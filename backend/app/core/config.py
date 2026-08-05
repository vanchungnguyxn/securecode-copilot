from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "SecureCode Copilot"
    app_version: str = "1.0.0"
    api_prefix: str = "/api/v1"

    llm_provider: str = "heuristic"  # heuristic | local | openai
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    model_path: str = "../ml/inference/checkpoints/codet5-lora"
    use_ml_detector: bool = True  # CodeBERT anti-FP when checkpoint exists
    use_ml_discovery: bool = False  # sliding ML windows — high recall but high FPR; off by default

    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
