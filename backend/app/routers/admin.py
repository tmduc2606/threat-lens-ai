from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])

LOOKUPS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data_science" / "configs" / "lookups"

_REMOTE_FEEDS = {
    "high_risk_tlds": {
        "url": "https://raw.githubusercontent.com/opencoconut/coconuttlds/master/coconuttlds.json",
        "parse": lambda data: {"tlds": [t.strip(".").lower() for t in data if isinstance(t, str)]},
    },
    "high_risk_countries": {
        "url": "https://raw.githubusercontent.com/pietercolpaert/ntlm/master/data/country-codes.json",
        "parse": lambda data: {"codes": [e["alpha-2"].upper() for e in data if e.get("alpha-2") in ("CN","RU","IR","KP","SY","VE","UA")]},
    },
}


@router.post("/admin/lookups/sync")
async def sync_lookups(feed: str = Query(default="all", pattern="^(all|high_risk_tlds|high_risk_countries)$")):
    import httpx

    results = {}
    LOOKUPS_DIR.mkdir(parents=True, exist_ok=True)

    targets = list(_REMOTE_FEEDS.keys()) if feed == "all" else [feed]

    for name in targets:
        feed_config = _REMOTE_FEEDS.get(name)
        if feed_config is None:
            results[name] = {"status": "skipped", "reason": "no remote source configured"}
            continue

        url = feed_config["url"]
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                parsed = feed_config["parse"](resp.json())
                out_path = LOOKUPS_DIR / f"{name}.json"
                with open(out_path, "w") as f:
                    json.dump(parsed, f, indent=2)
                results[name] = {
                    "status": "updated",
                    "source": url,
                    "item_count": len(list(parsed.values())[0]) if parsed else 0,
                }
                logger.info(f"Lookup '{name}' synced from {url}")
        except Exception as e:
            results[name] = {"status": "failed", "error": str(e)}
            logger.warning(f"Lookup sync '{name}' failed: {e}")

    return {"status": "completed", "results": results}
