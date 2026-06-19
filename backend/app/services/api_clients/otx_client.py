from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from .base_client import BaseAPIClient
from ...config import get_settings

logger = logging.getLogger(__name__)

class OTXClient(BaseAPIClient):
    def __init__(self):
        settings = get_settings()
        self.api_key = settings.otx_api_key
        headers = {}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        super().__init__(base_url="https://otx.alienvault.com", headers=headers)

    async def get_ip_reputation(self, ip: str) -> Optional[Dict[str, Any]]:
        response = await self._request("GET", f"api/v1/indicators/IPv4/{ip}/general")
        if response and response.status_code == 200:
            return response.json()
        return None

    async def get_domain_reputation(self, domain: str) -> Optional[Dict[str, Any]]:
        response = await self._request("GET", f"api/v1/indicators/domain/{domain}/general")
        if response and response.status_code == 200:
            return response.json()
        return None

    async def get_subscribed_pulses(self, limit: int = 50, modified_since: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.api_key:
            logger.warning("OTX API key not configured. Subscribed pulses cannot be fetched.")
            return []
            
        params = {"limit": limit}
        if modified_since:
            params["modified_since"] = modified_since
            
        response = await self._request("GET", "api/v1/pulses/subscribed", params=params)
        if response and response.status_code == 200:
            data = response.json()
            return data.get("results", [])
        return []
