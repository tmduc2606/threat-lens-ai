from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .base_client import BaseAPIClient

logger = logging.getLogger(__name__)


class EPSSClient(BaseAPIClient):
    def __init__(self):
        super().__init__(base_url="https://api.first.org/data/v1", timeout=10.0)

    async def get_cve_score(self, cve_id: str) -> Optional[Dict[str, Any]]:
        response = await self._request("GET", "epss", params={"cve": cve_id})
        if response and response.status_code == 200:
            data = response.json()
            results = data.get("data", [])
            if results:
                return results[0]
        return None
