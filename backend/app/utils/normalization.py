from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Iterable, List, Optional


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
UUID_LIKE_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

COUNTRY_TO_CONTINENT = {
    # Africa
    "AO": "AF", "BF": "AF", "BI": "AF", "BJ": "AF", "BW": "AF", "CD": "AF",
    "CF": "AF", "CG": "AF", "CI": "AF", "CM": "AF", "CV": "AF", "DJ": "AF",
    "DZ": "AF", "EG": "AF", "EH": "AF", "ER": "AF", "ET": "AF", "GA": "AF",
    "GH": "AF", "GM": "AF", "GN": "AF", "GQ": "AF", "GW": "AF", "KE": "AF",
    "KM": "AF", "LR": "AF", "LS": "AF", "LY": "AF", "MA": "AF", "MG": "AF",
    "ML": "AF", "MR": "AF", "MU": "AF", "MW": "AF", "MZ": "AF", "NA": "AF",
    "NE": "AF", "NG": "AF", "RW": "AF", "SC": "AF", "SD": "AF", "SH": "AF",
    "SL": "AF", "SN": "AF", "SO": "AF", "SS": "AF", "ST": "AF", "SZ": "AF",
    "TD": "AF", "TG": "AF", "TN": "AF", "TZ": "AF", "UG": "AF", "YT": "AF",
    "ZA": "AF", "ZM": "AF", "ZW": "AF",
    # Asia
    "AE": "AS", "AF": "AS", "AM": "AS", "AZ": "AS", "BD": "AS", "BH": "AS",
    "BN": "AS", "BT": "AS", "CC": "AS", "CN": "AS", "CX": "AS", "CY": "AS",
    "GE": "AS", "HK": "AS", "ID": "AS", "IL": "AS", "IN": "AS", "IO": "AS",
    "IQ": "AS", "IR": "AS", "JO": "AS", "JP": "AS", "KG": "AS", "KH": "AS",
    "KP": "AS", "KR": "AS", "KW": "AS", "KZ": "AS", "LA": "AS", "LB": "AS",
    "LK": "AS", "MM": "AS", "MN": "AS", "MO": "AS", "MV": "AS", "MY": "AS",
    "NP": "AS", "OM": "AS", "PH": "AS", "PK": "AS", "PS": "AS", "QA": "AS",
    "SA": "AS", "SG": "AS", "SY": "AS", "TH": "AS", "TJ": "AS", "TL": "AS",
    "TM": "AS", "TR": "AS", "TW": "AS", "UZ": "AS", "VN": "AS", "YE": "AS",
    # Europe
    "AD": "EU", "AL": "EU", "AT": "EU", "AX": "EU", "BA": "EU", "BE": "EU",
    "BG": "EU", "BY": "EU", "CH": "EU", "CZ": "EU", "DE": "EU", "DK": "EU",
    "EE": "EU", "ES": "EU", "FI": "EU", "FO": "EU", "FR": "EU", "GB": "EU",
    "GG": "EU", "GI": "EU", "GR": "EU", "HR": "EU", "HU": "EU", "IE": "EU",
    "IM": "EU", "IS": "EU", "IT": "EU", "JE": "EU", "LI": "EU", "LT": "EU",
    "LU": "EU", "LV": "EU", "MC": "EU", "MD": "EU", "ME": "EU", "MK": "EU",
    "MT": "EU", "NL": "EU", "NO": "EU", "PL": "EU", "PT": "EU", "RO": "EU",
    "RS": "EU", "RU": "EU", "SE": "EU", "SI": "EU", "SJ": "EU", "SK": "EU",
    "SM": "EU", "UA": "EU", "VA": "EU", "XK": "EU",
    # North America
    "AG": "NA", "AI": "NA", "AW": "NA", "BB": "NA", "BL": "NA", "BM": "NA",
    "BQ": "NA", "BS": "NA", "BZ": "NA", "CA": "NA", "CR": "NA", "CU": "NA",
    "CW": "NA", "DM": "NA", "DO": "NA", "GD": "NA", "GL": "NA", "GP": "NA",
    "GT": "NA", "HN": "NA", "HT": "NA", "JM": "NA", "KN": "NA", "KY": "NA",
    "LC": "NA", "MF": "NA", "MQ": "NA", "MS": "NA", "MX": "NA", "NI": "NA",
    "PA": "NA", "PM": "NA", "PR": "NA", "SV": "NA", "SX": "NA", "TC": "NA",
    "TT": "NA", "US": "NA", "VC": "NA", "VG": "NA", "VI": "NA",
    # Oceania
    "AS": "OC", "AU": "OC", "CK": "OC", "FJ": "OC", "FM": "OC", "GU": "OC",
    "KI": "OC", "MH": "OC", "MP": "OC", "NC": "OC", "NF": "OC", "NR": "OC",
    "NU": "OC", "NZ": "OC", "PF": "OC", "PG": "OC", "PN": "OC", "PW": "OC",
    "SB": "OC", "TK": "OC", "TO": "OC", "TV": "OC", "UM": "OC", "VU": "OC",
    "WF": "OC", "WS": "OC",
    # South America
    "AR": "SA", "BO": "SA", "BR": "SA", "CL": "SA", "CO": "SA", "EC": "SA",
    "FK": "SA", "GF": "SA", "GY": "SA", "PE": "SA", "PY": "SA", "SR": "SA",
    "UY": "SA", "VE": "SA",
}

COUNTRY_TO_REGIONAL_REGISTRY = {
    "AF": "AFRINIC", "AO": "AFRINIC", "BF": "AFRINIC", "BI": "AFRINIC",
    "BJ": "AFRINIC", "BW": "AFRINIC", "CD": "AFRINIC", "CF": "AFRINIC",
    "CG": "AFRINIC", "CI": "AFRINIC", "CM": "AFRINIC", "CV": "AFRINIC",
    "DJ": "AFRINIC", "DZ": "AFRINIC", "EG": "AFRINIC", "ER": "AFRINIC",
    "ET": "AFRINIC", "GA": "AFRINIC", "GH": "AFRINIC", "GM": "AFRINIC",
    "GN": "AFRINIC", "GQ": "AFRINIC", "GW": "AFRINIC", "KE": "AFRINIC",
    "KM": "AFRINIC", "LR": "AFRINIC", "LS": "AFRINIC", "LY": "AFRINIC",
    "MA": "AFRINIC", "MG": "AFRINIC", "ML": "AFRINIC", "MR": "AFRINIC",
    "MU": "AFRINIC", "MW": "AFRINIC", "MZ": "AFRINIC", "NA": "AFRINIC",
    "NE": "AFRINIC", "NG": "AFRINIC", "RW": "AFRINIC", "SC": "AFRINIC",
    "SD": "AFRINIC", "SL": "AFRINIC", "SN": "AFRINIC", "SO": "AFRINIC",
    "SS": "AFRINIC", "ST": "AFRINIC", "SZ": "AFRINIC", "TD": "AFRINIC",
    "TG": "AFRINIC", "TN": "AFRINIC", "TZ": "AFRINIC", "UG": "AFRINIC",
    "ZA": "AFRINIC", "ZM": "AFRINIC", "ZW": "AFRINIC",
    "AE": "RIPE NCC", "AM": "RIPE NCC", "AZ": "RIPE NCC", "BY": "RIPE NCC",
    "CY": "RIPE NCC", "GE": "RIPE NCC", "IL": "RIPE NCC", "IQ": "RIPE NCC",
    "IR": "RIPE NCC", "JO": "RIPE NCC", "KZ": "RIPE NCC", "LB": "RIPE NCC",
    "MT": "RIPE NCC", "OM": "RIPE NCC", "PS": "RIPE NCC", "QA": "RIPE NCC",
    "RU": "RIPE NCC", "SA": "RIPE NCC", "SY": "RIPE NCC", "TR": "RIPE NCC",
    "UA": "RIPE NCC", "YE": "RIPE NCC",
    "AD": "RIPE NCC", "AL": "RIPE NCC", "AT": "RIPE NCC", "BA": "RIPE NCC",
    "BE": "RIPE NCC", "BG": "RIPE NCC", "CH": "RIPE NCC", "CZ": "RIPE NCC",
    "DE": "RIPE NCC", "DK": "RIPE NCC", "EE": "RIPE NCC", "ES": "RIPE NCC",
    "FI": "RIPE NCC", "FR": "RIPE NCC", "GB": "RIPE NCC", "GR": "RIPE NCC",
    "HR": "RIPE NCC", "HU": "RIPE NCC", "IE": "RIPE NCC", "IS": "RIPE NCC",
    "IT": "RIPE NCC", "LI": "RIPE NCC", "LT": "RIPE NCC", "LU": "RIPE NCC",
    "LV": "RIPE NCC", "MC": "RIPE NCC", "MD": "RIPE NCC", "ME": "RIPE NCC",
    "MK": "RIPE NCC", "NL": "RIPE NCC", "NO": "RIPE NCC", "PL": "RIPE NCC",
    "PT": "RIPE NCC", "RO": "RIPE NCC", "RS": "RIPE NCC", "SE": "RIPE NCC",
    "SI": "RIPE NCC", "SK": "RIPE NCC", "SM": "RIPE NCC", "VA": "RIPE NCC",
    "AG": "ARIN", "AI": "ARIN", "AW": "ARIN", "BB": "ARIN", "BM": "ARIN",
    "BS": "ARIN", "BZ": "ARIN", "CA": "ARIN", "CR": "ARIN", "CU": "ARIN",
    "DM": "ARIN", "DO": "ARIN", "GD": "ARIN", "GT": "ARIN", "HN": "ARIN",
    "HT": "ARIN", "JM": "ARIN", "KN": "ARIN", "KY": "ARIN", "LC": "ARIN",
    "MX": "ARIN", "NI": "ARIN", "PA": "ARIN", "PR": "ARIN", "SV": "ARIN",
    "TC": "ARIN", "TT": "ARIN", "US": "ARIN", "VC": "ARIN", "VG": "ARIN",
    "VI": "ARIN",
    "AR": "LACNIC", "BO": "LACNIC", "BR": "LACNIC", "CL": "LACNIC",
    "CO": "LACNIC", "EC": "LACNIC", "GF": "LACNIC", "GY": "LACNIC",
    "PE": "LACNIC", "PY": "LACNIC", "SR": "LACNIC", "UY": "LACNIC",
    "VE": "LACNIC",
    "AU": "APNIC", "BD": "APNIC", "BN": "APNIC", "BT": "APNIC",
    "CC": "APNIC", "CN": "APNIC", "CX": "APNIC", "FJ": "APNIC",
    "HK": "APNIC", "ID": "APNIC", "IN": "APNIC", "JP": "APNIC",
    "KG": "APNIC", "KH": "APNIC", "KP": "APNIC", "KR": "APNIC",
    "LA": "APNIC", "LK": "APNIC", "MM": "APNIC", "MN": "APNIC",
    "MO": "APNIC", "MV": "APNIC", "MY": "APNIC", "NP": "APNIC",
    "NZ": "APNIC", "PG": "APNIC", "PH": "APNIC", "PK": "APNIC",
    "SB": "APNIC", "SG": "APNIC", "TH": "APNIC", "TL": "APNIC",
    "TO": "APNIC", "TV": "APNIC", "TW": "APNIC", "VU": "APNIC",
    "VN": "APNIC", "WS": "APNIC",
}


def country_to_continent(country_code: str) -> str:
    return COUNTRY_TO_CONTINENT.get(country_code.upper(), "Unknown")


def country_to_regional_registry(country_code: str) -> str:
    return COUNTRY_TO_REGIONAL_REGISTRY.get(country_code.upper(), "Unknown")


def snake_case(name: str) -> str:
    name = re.sub(r"[^0-9a-zA-Z]+", "_", name)
    name = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"_+", "_", name).strip("_").lower()


def clean_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def clean_text_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        text = str(value).strip()
        if not text:
            return []
        text = text.replace("|", ",")
        items = [part.strip() for part in text.split(",")]
    return [item for item in (clean_text(x) for x in items) if item]


def to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "t", "on"}


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except Exception:
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def parse_datetime(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    if hasattr(value, "year") and hasattr(value, "month") and hasattr(value, "day"):
        return datetime(value.year, value.month, value.day)
    text = str(value).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(text[:19], fmt)
        except Exception:
            pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        return None


def parse_date(value: Any):
    dt = parse_datetime(value)
    return dt.date() if dt else None


def classify_query(q: str) -> str:
    query = (q or "").strip()
    if not query:
        return "unknown"
    if CVE_PATTERN.match(query):
        return "cve"
    try:
        ipaddress.ip_address(query)
        return "ip"
    except Exception:
        pass
    if UUID_LIKE_PATTERN.match(query):
        return "otx"
    if "." in query and " " not in query and not query.upper().startswith("CVE-"):
        return "domain"
    return "unknown"


def normalize_severity(value: Any, score: float | None = None) -> str:
    text = clean_text(value)
    if text:
        lowered = text.lower()
        if lowered in {"critical", "high", "medium", "low", "informational", "info", "unknown"}:
            return lowered.capitalize()
    if score is None:
        return "Unknown"
    if score >= 8:
        return "High"
    if score >= 5:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def join_nonempty(items: Iterable[Any], separator: str = ", ") -> Optional[str]:
    values = [clean_text(item) for item in items]
    values = [value for value in values if value]
    return separator.join(values) if values else None


def _strip_www(domain: str) -> str:
    """Strip common www subdomain prefix."""
    parts = domain.split(".")
    if len(parts) > 2 and parts[0].lower() in ("www", "wwww", "wwwwww", "m", "mobile", "w"):
        return ".".join(parts[1:])
    return domain


def extract_domain_from_url(url: str) -> str:
    """Extract registrable domain from a URL, stripping protocol, path, and www subdomain."""
    from urllib.parse import urlparse
    url = (url or "").strip()
    if not url:
        return url
    # Remove protocol if present
    if url.startswith(("http://", "https://")):
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
    else:
        domain = url.split("/")[0]
    # Remove any remaining path
    domain = domain.split("/")[0]
    # Remove port if present
    domain = domain.split(":")[0]
    # Remove userinfo if present (user:pass@host)
    if "@" in domain:
        domain = domain.split("@")[-1]
    # Strip www prefix
    domain = _strip_www(domain)
    return domain.lower()