from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from .base_client import BaseAPIClient
from ...config import get_settings

logger = logging.getLogger(__name__)

class AbuseIPDBClient(BaseAPIClient):
    def __init__(self):
        settings = get_settings()
        self.api_key = settings.abuseipdb_api_key
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        super().__init__(base_url="https://api.abuseipdb.com/api/v2", headers=headers)

    async def check_ip(self, ip: str, max_age_days: int = 90) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured. Skipping live enrichment.")
            return None

        params = {
            "ipAddress": ip,
            "maxAgeInDays": max_age_days,
            "verbose": "true",
        }
        
        response = await self._request("GET", "check", params=params)
        if response and response.status_code == 200:
            data = response.json()
            return data.get("data")
        return None
