from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .base_client import BaseAPIClient
from ...config import get_settings

logger = logging.getLogger(__name__)


class URLScanClient(BaseAPIClient):
    def __init__(self):
        settings = get_settings()
        self.api_key = settings.urlscan_api_key
        headers = {}
        if self.api_key:
            headers["API-Key"] = self.api_key
        super().__init__(base_url="https://urlscan.io/api/v1", headers=headers, timeout=15.0)

    async def search_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            logger.warning("URLScan API key not configured. Skipping.")
            return None

        response = await self._request(
            "GET", "search",
            params={"q": f"domain:{domain}", "size": 5}
        )
        if response and response.status_code == 200:
            return response.json()
        return None
