from __future__ import annotations

from typing import Any, Dict

from sqlalchemy.orm import Session

from ..models.cve import CVEVulnerability
from ..models.domain import MaliciousDomain
from ..models.ip import MaliciousIP
from ..models.otx import OTXPulse
from ..schemas.common import DetailResponse
from ..utils.normalization import clean_text_list, safe_float
from ..utils.response_helpers import make_detail, make_result
from ..utils.scoring import build_excerpt, score_cve, score_domain, score_ip, score_otx
from .modeling_service import enrich_cve, enrich_domain, enrich_ip, enrich_otx, shap_explain_domain, shap_explain_ip


def _normalize_type(source_type: str) -> str:
    return (source_type or "").strip().upper()


def get_intel_detail(db: Session, source_type: str, value: str) -> DetailResponse | None:
    source_type = _normalize_type(source_type)
    value = (value or "").strip()

    if source_type == "CVE":
        row = db.get(CVEVulnerability, value)
        if not row:
            return None
        score, severity, tags, summary = score_cve(row)
        result = make_result(
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
        metadata = {
            "vendor_project": row.vendor_project,
            "product": row.product,
            "cwes": clean_text_list(row.cwes),
            "known_ransomware_campaign_use": row.known_ransomware_campaign_use,
        }
        evidence = {
            "short_description": row.short_description,
            "required_action": row.required_action,
        }
        timeline = {"date_added": row.date_added, "due_date": row.due_date}
        raw = _row_to_dict(row)
        return make_detail(result, metadata, evidence, timeline, raw, enrich_cve(row))

    if source_type == "DOMAIN":
        row = db.get(MaliciousDomain, value)
        if not row:
            return None
        score, severity, tags, summary = score_domain(row)
        result = make_result(
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
        metadata = {
            "tld": row.tld,
            "registrar": row.registrar,
            "reputation": safe_float(row.reputation, 0.0),
            "data_source": row.data_source,
            "threat_severity": row.threat_severity,
        }
        evidence = {
            "malicious_votes": row.malicious_votes,
            "suspicious_votes": row.suspicious_votes,
            "harmless_votes": row.harmless_votes,
            "undetected_votes": row.undetected_votes,
            "total_engines": row.total_engines,
            "categories": clean_text_list(row.categories),
            "whois_summary": row.whois_summary,
        }
        timeline = {
            "creation_date": row.creation_date,
            "last_update_date": row.last_update_date,
            "last_analysis_date": row.last_analysis_date,
        }
        raw = _row_to_dict(row)
        domain_features = {c.name: getattr(row, c.name) for c in MaliciousDomain.__table__.columns}
        shap_vals = shap_explain_domain(domain_features)
        return make_detail(result, metadata, evidence, timeline, raw, enrich_domain(row), shap_values=shap_vals)

    if source_type == "IP":
        row = db.get(MaliciousIP, value)
        if not row:
            return None
        score, severity, tags, summary = score_ip(row)
        result = make_result(
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
        metadata = {
            "country": row.country,
            "continent": row.continent,
            "asn": row.asn,
            "owner": row.owner,
            "network": row.network,
            "regional_registry": row.regional_registry,
            "tor_node": row.tor_node,
            "threat_label": row.threat_label,
            "threat_category": row.threat_category,
            "threat_severity": row.threat_severity,
        }
        evidence = {
            "malicious_votes": row.malicious_votes,
            "suspicious_votes": row.suspicious_votes,
            "harmless_votes": row.harmless_votes,
            "undetected_votes": row.undetected_votes,
            "total_reports": row.total_reports,
            "reputation_score": safe_float(row.reputation_score, 0.0),
            "times_submitted": row.times_submitted,
            "whois_summary": row.whois_summary,
        }
        timeline = {"last_analysis_date": row.last_analysis_date}
        raw = _row_to_dict(row)
        ip_features = {c.name: getattr(row, c.name) for c in MaliciousIP.__table__.columns}
        shap_vals = shap_explain_ip(ip_features, model_name="xgb")
        return make_detail(result, metadata, evidence, timeline, raw, enrich_ip(row), shap_values=shap_vals)

    if source_type == "OTX":
        row = db.get(OTXPulse, value)
        if not row:
            return None
        score, severity, tags, summary = score_otx(row)
        result = make_result(
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
        metadata = {
            "author": row.author,
            "tlp": row.tlp,
            "indicators_count": row.indicators_count,
            "subscribers": row.subscribers,
        }
        evidence = {
            "description": row.description,
            "tags": clean_text_list(row.tags),
            "malware_families": clean_text_list(row.malware_families),
            "attack_ids": clean_text_list(row.attack_ids),
            "industries": clean_text_list(row.industries),
            "countries": clean_text_list(row.countries),
        }
        timeline = {"created_at": row.created_at, "modified_at": row.modified_at}
        raw = _row_to_dict(row)
        return make_detail(result, metadata, evidence, timeline, raw, enrich_otx(row))

    return None


def _row_to_dict(row: Any) -> Dict[str, Any]:
    if hasattr(row, "__table__"):
        return {column.name: getattr(row, column.name) for column in row.__table__.columns}
    return dict(row)