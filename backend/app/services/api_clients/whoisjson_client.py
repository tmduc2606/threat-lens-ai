from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .base_client import BaseAPIClient
from ...config import get_settings

logger = logging.getLogger(__name__)


class WhoisJSONClient(BaseAPIClient):
    def __init__(self):
        settings = get_settings()
        self.api_key = settings.whoisjson_api_key
        super().__init__(base_url="https://whoisjson.com/api/v1", timeout=10.0)

    async def get_domain_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            logger.warning("WhoisJSON API key not configured. Skipping.")
            return None

        response = await self._request(
            "GET", "whois",
            params={"domain": domain, "api_key": self.api_key}
        )
        if response and response.status_code == 200:
            return response.json()
        return None
