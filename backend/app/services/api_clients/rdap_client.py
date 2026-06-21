from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple
from functools import lru_cache

import httpx

from .base_client import BaseAPIClient

logger = logging.getLogger(__name__)

# IANA RDAP Bootstrap Registry URL
IANA_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

# Regional RDAP servers for IP address queries (ordered by likelihood of success)
IP_RDAP_SERVERS = [
    "https://rdap.org",                # General referral/caching proxy
    "https://rdap.arin.net/registry",  # North America
    "https://rdap.ripe.net",           # Europe, Middle East, Central Asia
    "https://rdap.apnic.net",          # Asia-Pacific
    "https://rdap.lacnic.net/rdap",    # Latin America & Caribbean
    "https://rdap.afrinic.net/rdap",   # Africa
]

# Timeout for individual RDAP requests (seconds) — Hotfix 4: reduced from 10s
RDAP_TIMEOUT = 5.0
# Max retries per server — Hotfix 4: reduced from 3
RDAP_RETRIES = 2


@lru_cache(maxsize=1)
def _fetch_iana_bootstrap() -> Dict[str, List[str]]:
    """
    Fetch and cache the IANA RDAP bootstrap registry.
    Returns a dict mapping TLD (lowercase) -> list of RDAP server URLs.
    """
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(IANA_RDAP_BOOTSTRAP_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.warning(f"Failed to fetch IANA RDAP bootstrap: {e}. Using fallback servers.")
        return {}

    tld_to_servers: Dict[str, List[str]] = {}
    for entry in data.get("services", []):
        tlds = entry[0]
        servers = entry[1]
        if not servers:
            continue
        for tld in tlds:
            tld_lower = tld.lower()
            if tld_lower not in tld_to_servers:
                tld_to_servers[tld_lower] = servers

    logger.info(f"IANA RDAP bootstrap loaded: {len(tld_to_servers)} TLDs mapped.")
    return tld_to_servers


# Common multi-part TLDs (second-level domains under ccTLDs)
# Used by _extract_registered_domain for correct label counting
_MULTI_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk", "ltd.uk", "plc.uk",
    "co.jp", "or.jp", "ne.jp", "go.jp", "ac.jp", "ad.jp", "ed.jp", "gr.jp",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "asn.au", "id.au",
    "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz", "geek.nz",
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "res.in", "edu.in",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "co.za", "org.za", "net.za", "gov.za", "web.za",
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    "co.il", "org.il", "net.il", "gov.il", "ac.il",
    "com.ar", "net.ar", "org.ar", "gov.ar", "edu.ar",
    "co.th", "or.th", "go.th", "ac.th", "mi.th",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn", "ac.vn",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "co.id", "or.id", "go.id", "ac.id", "web.id",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "co.ke", "or.ke", "go.ke", "ac.ke", "ne.ke",
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
    "co.ug", "or.ug", "go.ug", "ac.ug",
    "co.tz", "or.tz", "go.tz", "ac.tz",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua",
    "com.ru", "net.ru", "org.ru", "gov.ru", "edu.ru",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
}


def _extract_registered_domain(domain: str) -> Tuple[str, str]:
    """
    Hotfix 2: Extract the registered domain and its TLD from a potentially
    subdomain-bearing input. Uses a simple heuristic with known multi-part TLDs.

    Returns (registered_domain, tld).
    Examples:
        "src.sandcastlesmagazine.com" -> ("sandcastlesmagazine.com", "com")
        "tuoitre.vn"                  -> ("tuoitre.vn", "vn")
        "news.bbc.co.uk"              -> ("bbc.co.uk", "co.uk")
    """
    parts = domain.lower().strip().rstrip(".").split(".")

    if len(parts) < 2:
        return domain, parts[-1] if parts else ""

    # Check for multi-part TLD (last 2 labels form a known compound TLD)
    if len(parts) >= 3:
        compound = f"{parts[-2]}.{parts[-1]}"
        if compound in _MULTI_PART_TLDS:
            registered = ".".join(parts[-3:])
            return registered, compound

    # Standard case: last 2 labels
    return ".".join(parts[-2:]), parts[-1]


def _get_rdap_servers_for_tld(tld: str) -> Optional[List[str]]:
    """
    Hotfix 1: Get the authoritative RDAP servers for a given TLD from IANA bootstrap.
    Returns None if the TLD has no known RDAP server (Hotfix 3).
    """
    bootstrap = _fetch_iana_bootstrap()
    servers = bootstrap.get(tld.lower())
    if servers:
        return servers
    return None


class RDAPClient(BaseAPIClient):
    def __init__(self):
        # Base URL is a placeholder; we resolve per-TLD dynamically
        super().__init__(base_url="https://rdap.org", timeout=RDAP_TIMEOUT)

    async def _query_server(self, server: str, path: str) -> Optional[Dict[str, Any]]:
        """Query a single RDAP server with retries. Hotfix 4: reduced timeout/retries."""
        url = f"{server.rstrip('/')}/{path.lstrip('/')}"
        for attempt in range(RDAP_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        return resp.json()
                    if resp.status_code == 404:
                        # Domain not found on this server — don't retry
                        logger.debug(f"RDAP {server}: 404 for {path}")
                        return None
                    logger.debug(f"RDAP {server}: status {resp.status_code} for {path}")
            except Exception as e:
                logger.debug(f"RDAP {server} attempt {attempt+1}/{RDAP_RETRIES} failed for {path}: {e}")
        return None

    async def _try_domain_servers(self, path: str, tld: str) -> Optional[Dict[str, Any]]:
        """
        Hotfix 1+3: Try authoritative RDAP servers for the given TLD from IANA bootstrap.
        If TLD has no RDAP server in bootstrap, skip gracefully (Hotfix 3).
        """
        # Look up authoritative servers from IANA bootstrap
        servers = _get_rdap_servers_for_tld(tld)

        if servers:
            for server in servers:
                result = await self._query_server(server, path)
                if result is not None:
                    return result
            # All authoritative servers returned 404 or errors
            logger.debug(f"All authoritative RDAP servers returned no data for {path}")
            return None

        # Hotfix 3: TLD not in bootstrap = no RDAP support
        bootstrap = _fetch_iana_bootstrap()
        if bootstrap and tld.lower() not in bootstrap:
            logger.debug(f"No RDAP server for .{tld} TLD (not in IANA bootstrap). Skipping.")
            return None

        # Bootstrap empty/unreachable — try rdap.org as last resort
        logger.debug(f"No bootstrap data for .{tld}, trying rdap.org fallback")
        return await self._query_server("https://rdap.org", path)

    async def _try_ip_servers(self, path: str) -> Optional[Dict[str, Any]]:
        """Try regional RDAP servers for IP address queries."""
        for server in IP_RDAP_SERVERS:
            result = await self._query_server(server, path)
            if result is not None:
                return result
        logger.warning(f"All RDAP servers failed for {path}")
        return None

    async def get_domain_registrar(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Hotfix 2: Extract registered domain from subdomains before querying RDAP.
        E.g., "src.sandcastlesmagazine.com" -> queries "sandcastlesmagazine.com".
        """
        registered_domain, tld = _extract_registered_domain(domain)
        if registered_domain != domain:
            logger.debug(f"RDAP: extracted registered domain {registered_domain} from {domain}")
        return await self._try_domain_servers(f"domain/{registered_domain}", tld)

    async def get_ip_network(self, ip: str) -> Optional[Dict[str, Any]]:
        return await self._try_ip_servers(f"ip/{ip}")
