import json
import logging
from pathlib import Path

try:
    import httpx
except ImportError:
    httpx = None

_CONFIG_DIR = Path(__file__).resolve().parent / "lookups"
_REMOTE_TIMEOUT = 10.0

logger = logging.getLogger(__name__)


def _load(name: str) -> dict:
    path = _CONFIG_DIR / f"{name}.json"
    if not path.exists():
        return {}
    with open(path, "r") as f:
        return json.load(f)


def _ensure_dir():
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)


# --- Remote fallback sources ---
_REMOTE_FALLBACKS = {
    "high_risk_tlds": {
        "url": "https://raw.githubusercontent.com/opencoconut/coconuttlds/master/coconuttlds.json",
        "parse": lambda data: {"tlds": [t.strip(".").lower() for t in data if isinstance(t, str)]},
    },
    "high_risk_countries": {
        "url": "https://raw.githubusercontent.com/pietercolpaert/ntlm/master/data/country-codes.json",
        "parse": lambda data: {"codes": [e["alpha-2"].upper() for e in data if e.get("alpha-2") in ("CN","RU","IR","KP","SY","VE","UA")]},
    },
    "suspicious_keywords": {},
    "brand_keywords": {},
    "known_malicious_asns": {},
    "attack_keywords": {},
}


def _load_or_fallback(name: str, default_factory: callable) -> dict:
    """Load JSON file or fall back to remote source, then to a local default."""
    data = _load(name)
    if data:
        return data

    fallback = _REMOTE_FALLBACKS.get(name, {})
    url = fallback.get("url")
    if url and httpx:
        try:
            resp = httpx.get(url, timeout=_REMOTE_TIMEOUT)
            resp.raise_for_status()
            parsed = fallback["parse"](resp.json())
            _ensure_dir()
            out_path = _CONFIG_DIR / f"{name}.json"
            with open(out_path, "w") as f:
                json.dump(parsed, f, indent=2)
            logger.info(f"Lookup '{name}' fetched from remote: {url}")
            return parsed
        except Exception as e:
            logger.warning(f"Remote lookup '{name}' failed: {e}")

    return default_factory()


# --- Domain lookups ---
def get_suspicious_keywords() -> list[str]:
    return _load_or_fallback("suspicious_keywords", lambda: {}).get("keywords", [])

def get_high_risk_tlds() -> set[str]:
    return set(_load_or_fallback("high_risk_tlds", lambda: {"tlds": ["tk","ml","ga","cf","gq","xyz","top","club","work","click","download"]}).get("tlds", []))

def get_brand_keywords() -> list[str]:
    return _load_or_fallback("brand_keywords", lambda: {}).get("keywords", [])

# --- IP lookups ---
def get_high_risk_countries() -> set[str]:
    return set(_load_or_fallback("high_risk_countries", lambda: {"codes": ["CN","RU","IR","KP","SY","VE","UA"]}).get("codes", []))

def get_known_malicious_asns() -> set[str]:
    return set(_load_or_fallback("known_malicious_asns", lambda: {}).get("asns", []))

# --- OTX lookups ---
def get_attack_keywords() -> dict[str, str]:
    return _load("attack_keywords")

# --- Write helpers (for external update scripts) ---
def write_suspicious_keywords(keywords: list[str]):
    _ensure_dir()
    with open(_CONFIG_DIR / "suspicious_keywords.json", "w") as f:
        json.dump({"keywords": sorted(keywords)}, f, indent=2)

def write_high_risk_tlds(tlds: list[str]):
    _ensure_dir()
    with open(_CONFIG_DIR / "high_risk_tlds.json", "w") as f:
        json.dump({"tlds": sorted(tlds)}, f, indent=2)

def write_brand_keywords(keywords: list[str]):
    _ensure_dir()
    with open(_CONFIG_DIR / "brand_keywords.json", "w") as f:
        json.dump({"keywords": sorted(keywords)}, f, indent=2)

def write_high_risk_countries(codes: list[str]):
    _ensure_dir()
    with open(_CONFIG_DIR / "high_risk_countries.json", "w") as f:
        json.dump({"codes": sorted(codes)}, f, indent=2)

def write_known_malicious_asns(asns: list[str]):
    _ensure_dir()
    with open(_CONFIG_DIR / "known_malicious_asns.json", "w") as f:
        json.dump({"asns": sorted(asns)}, f, indent=2)

def write_attack_keywords(mapping: dict[str, str]):
    _ensure_dir()
    with open(_CONFIG_DIR / "attack_keywords.json", "w") as f:
        json.dump(dict(sorted(mapping.items())), f, indent=2)
