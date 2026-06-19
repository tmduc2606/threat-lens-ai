from __future__ import annotations

import datetime
import logging
import random
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models.cve import CVEVulnerability
from ..models.otx import OTXPulse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tips"])

FALLBACK_TIPS = [
    "Always enable MFA on accounts — it blocks 99.9% of automated credential attacks.",
    "Keep all software patched; 60% of breaches involve known unpatched vulnerabilities.",
    "Never reuse passwords across sites — a single breach can compromise all accounts.",
    "Public Wi-Fi is insecure — always use a VPN when connecting on untrusted networks.",
    "Back up your data regularly to an offline or separate location.",
    "Phishing is the top initial attack vector — never click links in unsolicited messages.",
    "Encrypt sensitive data at rest and in transit using industry-standard protocols.",
    "Implement zero-trust principles: verify every request as if it originates from an open network.",
]

_cache: Optional[dict] = None
_cache_ts: Optional[datetime.datetime] = None
_CACHE_TTL = datetime.timedelta(hours=24)


def _is_cache_valid() -> bool:
    global _cache, _cache_ts
    if _cache is None or _cache_ts is None:
        return False
    return datetime.datetime.utcnow() - _cache_ts < _CACHE_TTL


def _build_dynamic_tip(db: Session) -> str:
    now = datetime.datetime.utcnow()

    urgent_kev = (
        db.query(CVEVulnerability)
        .filter(
            CVEVulnerability.known_ransomware_campaign_use.ilike("%ransomware%"),
            CVEVulnerability.due_date.isnot(None),
            CVEVulnerability.due_date <= (now + datetime.timedelta(days=7)).date(),
        )
        .order_by(CVEVulnerability.due_date.asc())
        .first()
    )
    if urgent_kev and urgent_kev.short_description:
        return (
            f"URGENT: KEV alert — {urgent_kev.vulnerability_name or urgent_kev.cve_id}. "
            f"{urgent_kev.required_action or 'Apply vendor patch immediately.'} "
            f"Due by {urgent_kev.due_date}."
        )

    top_cve = (
        db.query(CVEVulnerability)
        .filter(CVEVulnerability.cvss_v3_score > 0)
        .order_by(desc(CVEVulnerability.cvss_v3_score))
        .first()
    )
    if top_cve and top_cve.short_description:
        vuln_name = top_cve.vulnerability_name or top_cve.cve_id
        desc_text = top_cve.short_description[:150]
        return (
            f"Critical CVE: {vuln_name} (CVSS {top_cve.cvss_v3_score}). "
            f"{desc_text}. Patch if applicable."
        )

    recent_pulse = (
        db.query(OTXPulse)
        .order_by(desc(OTXPulse.created_at))
        .first()
    )
    if recent_pulse and recent_pulse.description:
        return (
            f"OTX Pulse: {recent_pulse.title}. "
            f"{recent_pulse.description[:200]}"
        )

    return random.choice(FALLBACK_TIPS)


@router.get("/tip-of-the-day")
async def tip_of_the_day(db: Session = Depends(get_db)):
    global _cache, _cache_ts
    if _is_cache_valid():
        return {"tip": _cache["tip"]}

    try:
        tip = _build_dynamic_tip(db)
    except Exception as e:
        logger.warning(f"Failed to build dynamic tip: {e}")
        tip = random.choice(FALLBACK_TIPS)

    _cache = {"tip": tip}
    _cache_ts = datetime.datetime.utcnow()
    return {"tip": tip}
