from __future__ import annotations

from typing import List

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..models.cve import CVEVulnerability
from ..models.domain import MaliciousDomain
from ..models.index import IntelIndex
from ..models.ip import MaliciousIP
from ..models.otx import OTXPulse
from ..schemas.common import SearchResponse, SearchResult
from ..utils.normalization import classify_query, clean_text_list, safe_float
from ..utils.response_helpers import make_result
from ..utils.scoring import build_excerpt, score_cve, score_domain, score_ip, score_otx


def search_intelligence(db: Session, query: str, limit: int = 20) -> SearchResponse:
    query = (query or "").strip()
    if not query:
        return SearchResponse(query=query, count=0, results=[])

    qtype = classify_query(query)
    results: List[SearchResult] = []

    if qtype == "cve":
        results.extend(search_cve(db, query))
    elif qtype == "ip":
        results.extend(search_ip(db, query))
    elif qtype == "domain":
        results.extend(search_domain(db, query))
    elif qtype == "otx":
        results.extend(search_otx(db, query))
    else:
        results.extend(search_cve(db, query))
        results.extend(search_domain(db, query))
        results.extend(search_ip(db, query))
        results.extend(search_otx(db, query))

    def _sort_key(r):
        ts = r.updated_at or r.created_at
        if ts is None:
            return (r.score, "")
        if hasattr(ts, "isoformat"):
            return (r.score, ts.isoformat())
        return (r.score, str(ts))

    results = sorted(results, key=_sort_key, reverse=True)[:limit]

    return SearchResponse(query=query, count=len(results), results=results)


def search_cve(db: Session, query: str) -> List[SearchResult]:
    rows = (
        db.query(CVEVulnerability)
        .filter(
            or_(
                CVEVulnerability.cve_id.ilike(f"%{query}%"),
                CVEVulnerability.vendor_project.ilike(f"%{query}%"),
                CVEVulnerability.product.ilike(f"%{query}%"),
                CVEVulnerability.vulnerability_name.ilike(f"%{query}%"),
                CVEVulnerability.short_description.ilike(f"%{query}%"),
                CVEVulnerability.required_action.ilike(f"%{query}%"),
                CVEVulnerability.cwes.ilike(f"%{query}%"),
            )
        )
        .limit(10)
        .all()
    )

    items: List[SearchResult] = []
    for row in rows:
        score, severity, tags, summary = score_cve(row)
        if row.known_ransomware_campaign_use:
            tags.append("Ransomware")
        if row.due_date:
            tags.append("Due Date")
        items.append(
            make_result(
                source_type="CVE",
                source_key=row.cve_id,
                title=row.vulnerability_name or row.cve_id,
                summary=build_excerpt(summary, row.short_description, row.required_action),
                severity=severity,
                score=score,
                tags=tags,
                created_at=row.date_added,
                updated_at=row.due_date or row.date_added,
            )
        )
    return items


def search_domain(db: Session, query: str) -> List[SearchResult]:
    rows = (
        db.query(MaliciousDomain)
        .filter(
            or_(
                MaliciousDomain.domain.ilike(f"%{query}%"),
                MaliciousDomain.registrar.ilike(f"%{query}%"),
                MaliciousDomain.categories.ilike(f"%{query}%"),
                MaliciousDomain.whois_summary.ilike(f"%{query}%"),
                MaliciousDomain.data_source.ilike(f"%{query}%"),
            )
        )
        .limit(10)
        .all()
    )
    items: List[SearchResult] = []
    for row in rows:
        score, severity, tags, summary = score_domain(row)
        items.append(
            make_result(
                source_type="DOMAIN",
                source_key=row.domain,
                title=row.domain,
                summary=build_excerpt(summary, row.categories, row.registrar),
                severity=severity,
                score=score,
                tags=tags,
                created_at=row.creation_date,
                updated_at=row.last_analysis_date or row.last_update_date,
            )
        )
    return items


def search_ip(db: Session, query: str) -> List[SearchResult]:
    rows = (
        db.query(MaliciousIP)
        .filter(
            or_(
                MaliciousIP.ip.ilike(f"%{query}%"),
                MaliciousIP.country.ilike(f"%{query}%"),
                MaliciousIP.owner.ilike(f"%{query}%"),
                MaliciousIP.asn.ilike(f"%{query}%"),
                MaliciousIP.threat_label.ilike(f"%{query}%"),
                MaliciousIP.threat_category.ilike(f"%{query}%"),
                MaliciousIP.whois_summary.ilike(f"%{query}%"),
            )
        )
        .limit(10)
        .all()
    )
    items: List[SearchResult] = []
    for row in rows:
        score, severity, tags, summary = score_ip(row)
        items.append(
            make_result(
                source_type="IP",
                source_key=row.ip,
                title=row.ip,
                summary=build_excerpt(summary, row.threat_label, row.threat_category, row.owner),
                severity=severity,
                score=score,
                tags=tags,
                created_at=row.last_analysis_date,
                updated_at=row.last_analysis_date,
            )
        )
    return items


def search_otx(db: Session, query: str) -> List[SearchResult]:
    rows = (
        db.query(OTXPulse)
        .filter(
            or_(
                OTXPulse.pulse_id.ilike(f"%{query}%"),
                OTXPulse.title.ilike(f"%{query}%"),
                OTXPulse.description.ilike(f"%{query}%"),
                OTXPulse.author.ilike(f"%{query}%"),
                OTXPulse.tags.ilike(f"%{query}%"),
                OTXPulse.malware_families.ilike(f"%{query}%"),
                OTXPulse.attack_ids.ilike(f"%{query}%"),
                OTXPulse.industries.ilike(f"%{query}%"),
                OTXPulse.countries.ilike(f"%{query}%"),
            )
        )
        .limit(10)
        .all()
    )
    items: List[SearchResult] = []
    for row in rows:
        score, severity, tags, summary = score_otx(row)
        items.append(
            make_result(
                source_type="OTX",
                source_key=row.pulse_id,
                title=row.title,
                summary=build_excerpt(summary, row.description, row.author),
                severity=severity,
                score=score,
                tags=tags,
                created_at=row.created_at,
                updated_at=row.modified_at or row.created_at,
            )
        )
    return items


def recent_index(db: Session, limit: int = 20) -> List[SearchResult]:
    rows = (
        db.query(IntelIndex)
        .order_by(
            IntelIndex.updated_at.desc().nullslast(),
            IntelIndex.created_at.desc().nullslast(),
            IntelIndex.id.desc(),
        )
        .limit(limit)
        .all()
    )

    results: List[SearchResult] = []
    for row in rows:
        results.append(
            make_result(
                source_type=row.source_type,
                source_key=row.source_key,
                title=row.title or row.source_key,
                summary=row.summary,
                severity=row.severity or "Unknown",
                score=safe_float(row.score, 0.0),
                tags=clean_text_list(row.tags),
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
        )
    return results