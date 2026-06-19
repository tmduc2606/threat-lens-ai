from __future__ import annotations

import logging
import datetime
from typing import Any, Dict, Optional
from .base_client import BaseAPIClient
from ...config import get_settings

logger = logging.getLogger(__name__)

class NVDClient(BaseAPIClient):
    def __init__(self):
        settings = get_settings()
        self.api_key = settings.nvd_api_key
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        super().__init__(base_url="https://services.nvd.nist.gov/rest/json/cves/2.0", headers=headers)

    async def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        params = {"cveId": cve_id}
        response = await self._request("GET", "", params=params)
        if response and response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                return vulnerabilities[0].get("cve")
        return None

    async def get_recent_cves(self, limit: int = 50) -> Optional[Dict[str, Any]]:
        now = datetime.datetime.utcnow()
        yesterday = now - datetime.timedelta(days=1)
        params = {
            "lastModStartDate": yesterday.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": limit,
        }
        response = await self._request("GET", "", params=params)
        if response and response.status_code == 200:
            return response.json()
        return None
