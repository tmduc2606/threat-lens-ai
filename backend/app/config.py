from __future__ import annotations

import os
from dotenv import load_dotenv
load_dotenv()
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import List


def _parse_csv(value: str | None) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "ThreatLensAI API")
    environment: str = os.getenv("ENVIRONMENT", "development")
    database_url: str = os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:postgres@localhost:5432/threatlensai")
    # PostgreSQL: postgresql+psycopg2://user:pass@host/db (set DATABASE_URL in .env)
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    cors_origins: List[str] = None  # type: ignore[assignment]

    # Model plug-in controls
    enable_ml_model: bool = os.getenv("ENABLE_ML_MODEL", "true").lower() == "true"
    joblib_model_path: str = os.getenv("JOBLIB_MODEL_PATH", "")
    models_dir: str = os.getenv("MODELS_DIR", "../ml/models")

    # Frontend / deployment helpers
    frontend_api_base: str = os.getenv("FRONTEND_API_BASE", "")

    # API Keys
    nvd_api_key: str = os.getenv("NVD_API_KEY", "")
    otx_api_key: str = os.getenv("OTX_API_KEY", "")
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    urlscan_api_key: str = os.getenv("URLSCAN_API_KEY", "")
    threatfox_auth_key: str = os.getenv("THREATFOX_AUTH_KEY", "")
    urlhaus_auth_key: str = os.getenv("URLHAUS_AUTH_KEY", "")
    malwarebazaar_auth_key: str = os.getenv("MALWAREBAZAAR_AUTH_KEY", "")
    whoisjson_api_key: str = os.getenv("WHOISJSON_API_KEY", "")

    # Cache TTLs (seconds)
    cache_ttl_ip: int = int(os.getenv("CACHE_TTL_IP", "86400"))       # 24 hours
    cache_ttl_domain: int = int(os.getenv("CACHE_TTL_DOMAIN", "259200"))  # 3 days
    cache_ttl_cve: int = int(os.getenv("CACHE_TTL_CVE", "604800"))    # 7 days
    cache_ttl_otx: int = int(os.getenv("CACHE_TTL_OTX", "604800"))    # 7 days

    # Feature flags
    enable_nmap_scan: bool = os.getenv("ENABLE_NMAP_SCAN", "false").lower() == "true"
    enable_llm_fallback: bool = os.getenv("ENABLE_LLM_FALLBACK", "false").lower() == "true"
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "mistral:7b")

    # Rate limiting
    nvd_requests_per_30s: int = int(os.getenv("NVD_RATE_LIMIT", "5"))  # 5 by default, 50 with API key
    abuseipdb_daily_limit: int = int(os.getenv("ABUSEIPDB_DAILY_LIMIT", "1000"))

    def __post_init__(self):
        object.__setattr__(
            self,
            "cors_origins",
            _parse_csv(os.getenv("CORS_ORIGINS", "*")) or ["*"],
        )

    @property
    def models_path(self) -> Path:
        return Path(self.models_dir)


@lru_cache
def get_settings() -> Settings:
    return Settings()