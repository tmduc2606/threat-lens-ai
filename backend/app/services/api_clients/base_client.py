from __future__ import annotations

import httpx
import logging
import asyncio
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

class BaseAPIClient:
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 10.0, follow_redirects: bool = True):
        self.base_url = base_url
        self.headers = headers or {}
        self.timeout = timeout
        self.follow_redirects = follow_redirects

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        retries: int = 3,
        backoff_factor: float = 0.5,
    ) -> Optional[httpx.Response]:
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        
        async with httpx.AsyncClient(headers=self.headers, timeout=self.timeout, follow_redirects=self.follow_redirects) as client:
            for attempt in range(retries):
                try:
                    response = await client.request(
                        method,
                        url,
                        params=params,
                        json=json_data,
                    )
                    
                    # Check for rate limits (HTTP 429) or server errors (5xx)
                    if response.status_code == 429:
                        wait_time = backoff_factor * (2 ** attempt)
                        logger.warning(f"Rate limited (429) for {url}. Retrying in {wait_time}s...")
                        await asyncio.sleep(wait_time)
                        continue
                        
                    response.raise_for_status()
                    return response
                    
                except httpx.HTTPStatusError as e:
                    # Don't retry on 400, 401, 403, 404
                    if e.response.status_code in (400, 401, 403, 404):
                        logger.error(f"HTTP error {e.response.status_code} for {url}: {e.response.text}")
                        return e.response
                    
                    wait_time = backoff_factor * (2 ** attempt)
                    logger.warning(f"HTTP error {e.response.status_code} for {url}. Attempt {attempt + 1}/{retries}. Retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    
                except httpx.RequestError as e:
                    wait_time = backoff_factor * (2 ** attempt)
                    logger.warning(f"Request connection error {e} for {url}. Attempt {attempt + 1}/{retries}. Retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    
            logger.error(f"Max retries exceeded for {url}")
            return None
