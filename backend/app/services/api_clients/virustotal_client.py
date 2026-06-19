from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .base_client import BaseAPIClient
from ...config import get_settings

logger = logging.getLogger(__name__)


class VirusTotalClient(BaseAPIClient):
    def __init__(self):
        settings = get_settings()
        self.api_key = settings.virustotal_api_key
        headers = {}
        if self.api_key:
            headers["x-apikey"] = self.api_key
        super().__init__(base_url="https://www.virustotal.com/api/v3", headers=headers, timeout=15.0)

    async def get_ip_report(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            logger.warning("VirusTotal API key not configured. Skipping.")
            return None

        response = await self._request("GET", f"ip_addresses/{ip}")
        if response and response.status_code == 200:
            return response.json()
        return None

    async def get_domain_report(self, domain: str) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            logger.warning("VirusTotal API key not configured. Skipping.")
            return None

        response = await self._request("GET", f"domains/{domain}")
        if response and response.status_code == 200:
            return response.json()
        return None

    async def get_url_report(self, url: str) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            logger.warning("VirusTotal API key not configured. Skipping.")
            return None

        import hashlib
        url_id = hashlib.sha256(url.encode()).hexdigest()
        response = await self._request("GET", f"urls/{url_id}")
        if response and response.status_code == 200:
            return response.json()
        return None
