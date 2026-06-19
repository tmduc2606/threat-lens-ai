from __future__ import annotations

import sys
from pathlib import Path

# Add parent directory to path so we can import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from sqlalchemy.orm import Session

from app.database import SessionLocal, engine
from app.models.base import Base
from app.models.cve import CVEVulnerability
from app.models.domain import MaliciousDomain
from app.models.index import IntelIndex
from app.models.ip import MaliciousIP
from app.models.otx import OTXPulse
from app.utils.normalization import clean_text, parse_date, parse_datetime, safe_float, safe_int, to_bool
from app.utils.scoring import score_cve, score_domain, score_ip, score_otx
from app.utils.response_helpers import make_result

Base.metadata.create_all(bind=engine)
db: Session = SessionLocal()


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")
    return df


def upsert_index(source_type: str, source_key: str, title: str, summary: str, severity: str, score: float, tags: list[str], created_at=None, updated_at=None):
    existing = (
        db.query(IntelIndex)
        .filter(IntelIndex.source_type == source_type, IntelIndex.source_key == source_key)
        .one_or_none()
    )
    if existing:
        existing.title = title
        existing.summary = summary
        existing.severity = severity
        existing.score = score
        existing.tags = ", ".join(tags)
        existing.created_at = created_at
        existing.updated_at = updated_at
    else:
        db.add(
            IntelIndex(
                source_type=source_type,
                source_key=source_key,
                title=title,
                summary=summary,
                severity=severity,
                score=score,
                tags=", ".join(tags),
                created_at=created_at,
                updated_at=updated_at,
            )
        )


# Domains
domains_df = normalize_columns(pd.read_csv("data/3_malicious_domains.csv"))
for _, row in domains_df.iterrows():
    domain_name = clean_text(row.get("domain"))

    # Recompute has_numbers and has_hyphen from the full domain name
    # rather than trusting CSV values, ensuring correctness.
    has_numbers = any(c.isdigit() for c in domain_name) if domain_name else False
    has_hyphen = "-" in domain_name if domain_name else False

    # Calculate realistic popularity_rank when CSV has "Unknown"/0/missing
    raw_rank = row.get("popularity_rank")
    csv_rank = safe_int(raw_rank) if raw_rank and str(raw_rank).strip().lower() not in {"", "unknown", "none", "n/a"} else None
    if csv_rank is None or csv_rank == 0:
        mal_votes = safe_int(row.get("malicious_votes"))
        reputation = safe_float(row.get("reputation"))
        total_eng = safe_int(row.get("total_engines"))
        if mal_votes > 0:
            csv_rank = min(9999999, 100000 * mal_votes)
        elif reputation != 0:
            csv_rank = max(10000, int(abs(reputation) * 5000))
        else:
            csv_rank = max(500000, total_eng * 10000) if total_eng > 0 else None

    domain = MaliciousDomain(
        domain=domain_name,
        tld=clean_text(row.get("tld")),
        domain_length=safe_int(row.get("domain_length")),
        has_numbers=has_numbers,
        has_hyphen=has_hyphen,
        registrar=clean_text(row.get("registrar")),
        creation_date=parse_date(row.get("creation_date") or row.get("creation_date")),
        last_update_date=parse_date(row.get("last_update_date")),
        reputation=safe_float(row.get("reputation")),
        malicious_votes=safe_int(row.get("malicious_votes")),
        suspicious_votes=safe_int(row.get("suspicious_votes")),
        harmless_votes=safe_int(row.get("harmless_votes")),
        undetected_votes=safe_int(row.get("undetected_votes")),
        total_engines=safe_int(row.get("total_engines")),
        threat_severity=clean_text(row.get("threat_severity")),
        categories=clean_text(row.get("categories")),
        popularity_rank=csv_rank,
        last_analysis_date=parse_date(row.get("last_analysis_date")),
        whois_summary=clean_text(row.get("whois_summary")),
        data_source=clean_text(row.get("data_source")) or "csv_import",
    )
    db.merge(domain)
    score, severity, tags, summary = score_domain(domain)
    upsert_index("DOMAIN", domain.domain, domain.domain, summary, severity, score, tags, domain.creation_date, domain.last_analysis_date)
db.commit()

# IPs
ips_df = normalize_columns(pd.read_csv("data/4_malicious_ips.csv"))
for _, row in ips_df.iterrows():
    ip = MaliciousIP(
        ip=clean_text(row.get("ip")),
        country=clean_text(row.get("country")),
        continent=clean_text(row.get("continent")),
        asn=clean_text(row.get("asn")),
        owner=clean_text(row.get("owner")),
        network=clean_text(row.get("network")),
        malicious_votes=safe_int(row.get("malicious_votes")),
        suspicious_votes=safe_int(row.get("suspicious_votes")),
        harmless_votes=safe_int(row.get("harmless_votes")),
        undetected_votes=safe_int(row.get("undetected_votes")),
        total_reports=safe_int(row.get("total_reports")),
        reputation_score=safe_float(row.get("reputation_score")),
        threat_label=clean_text(row.get("threat_label")),
        threat_category=clean_text(row.get("threat_category")),
        regional_registry=clean_text(row.get("regional_registry")),
        whois_summary=clean_text(row.get("whois_summary")),
        tor_node=to_bool(row.get("tor_node")),
        times_submitted=safe_int(row.get("times_submitted")),
        last_analysis_date=parse_date(row.get("last_analysis_date")),
        threat_severity=clean_text(row.get("threat_severity")),
    )
    db.merge(ip)
    score, severity, tags, summary = score_ip(ip)
    upsert_index("IP", ip.ip, ip.ip, summary, severity, score, tags, ip.last_analysis_date, ip.last_analysis_date)
db.commit()

# CVEs
cves_df = normalize_columns(pd.read_csv("data/2_cve_vulnerabilities.csv"))
for _, row in cves_df.iterrows():
    cve = CVEVulnerability(
        cve_id=clean_text(row.get("cveid") or row.get("cve_id")),
        vendor_project=clean_text(row.get("vendor_project") or row.get("vendorproject")),
        product=clean_text(row.get("product")),
        vulnerability_name=clean_text(row.get("vulnerability_name") or row.get("vulnerabilityname")),
        date_added=parse_date(row.get("date_added") or row.get("dateadded")),
        short_description=clean_text(row.get("short_description") or row.get("shortdescription")),
        required_action=clean_text(row.get("required_action") or row.get("requiredaction")),
        due_date=parse_date(row.get("due_date") or row.get("duedate")),
        known_ransomware_campaign_use=clean_text(row.get("known_ransomware_campaign_use") or row.get("knownransomwarecampaignuse")),
        cwes=clean_text(row.get("cwes")),
    )
    db.merge(cve)
    score, severity, tags, summary = score_cve(cve)
    upsert_index("CVE", cve.cve_id, cve.vulnerability_name or cve.cve_id, summary, severity, score, tags, cve.date_added, cve.due_date or cve.date_added)
db.commit()

# OTX
otx_df = normalize_columns(pd.read_csv("data/1_otx_threat_intel.csv"))
otx_df = otx_df.drop_duplicates(subset=["pulse_id"])
for _, row in otx_df.iterrows():
    pulse = OTXPulse(
        pulse_id=clean_text(row.get("pulse_id")),
        title=clean_text(row.get("title")),
        description=clean_text(row.get("description")),
        author=clean_text(row.get("author")),
        created_at=parse_datetime(row.get("created")),
        modified_at=parse_datetime(row.get("modified")),
        tlp=clean_text(row.get("tlp")),
        tags=clean_text(row.get("tags")),
        malware_families=clean_text(row.get("malware_families")),
        attack_ids=clean_text(row.get("attack_ids")),
        industries=clean_text(row.get("industries")),
        countries=clean_text(row.get("countries")),
        indicators_count=safe_int(row.get("indicators_count")),
        subscribers=safe_int(row.get("subscribers")),
    )
    db.merge(pulse)
    score, severity, tags, summary = score_otx(pulse)
    upsert_index("OTX", pulse.pulse_id, pulse.title, summary, severity, score, tags, pulse.created_at, pulse.modified_at or pulse.created_at)
db.commit()

db.close()
print("All CSV data imported successfully")