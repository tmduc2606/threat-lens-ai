from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx

from .base_client import BaseAPIClient

logger = logging.getLogger(__name__)

RDAP_SERVERS = [
    "https://rdap.org",
    "https://rdap.arin.net/registry",
    "https://rdap.ripe.net",
    "https://rdap.apnic.net",
    "https://rdap.lacnic.net/rdap",
    "https://rdap.afrinic.net/rdap",
]


class RDAPClient(BaseAPIClient):
    def __init__(self):
        super().__init__(base_url=RDAP_SERVERS[0], timeout=10.0)

    async def _try_servers(self, path: str) -> Optional[Dict[str, Any]]:
        for server in RDAP_SERVERS:
            url = f"{server.rstrip('/')}/{path.lstrip('/')}"
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        return resp.json()
                    if resp.status_code not in (404,):
                        logger.debug(f"RDAP {server} returned {resp.status_code} for {path}")
            except Exception as e:
                logger.debug(f"RDAP {server} failed for {path}: {e}")
                continue
        logger.warning(f"All RDAP servers failed for {path}")
        return None

    async def get_domain_registrar(self, domain: str) -> Optional[Dict[str, Any]]:
        return await self._try_servers(f"domain/{domain}")

    async def get_ip_network(self, ip: str) -> Optional[Dict[str, Any]]:
        return await self._try_servers(f"ip/{ip}")
