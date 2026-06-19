from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .base_client import BaseAPIClient
from ...config import get_settings

logger = logging.getLogger(__name__)


class ThreatFoxClient(BaseAPIClient):
    def __init__(self):
        settings = get_settings()
        self.auth_key = settings.threatfox_auth_key
        headers = {}
        if self.auth_key:
            headers["Auth-Key"] = self.auth_key
        super().__init__(base_url="https://threatfox-api.abuse.ch/api/v1", headers=headers, timeout=15.0)

    async def search_ioc(self, indicator: str) -> Optional[Dict[str, Any]]:
        if not self.auth_key:
            logger.warning("ThreatFox auth key not configured. Skipping.")
            return None

        response = await self._request(
            "POST", "",
            json_data={"query": "search_ioc", "search_term": indicator}
        )
        if response and response.status_code == 200:
            return response.json()
        return None
