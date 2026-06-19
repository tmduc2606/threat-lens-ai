"""
Export database tables to CSV files for ML retraining.

This script exports data from threatlensai.db to CSV files in the data/ directory:
- 1_otx_threat_intel.csv
- 2_cve_vulnerabilities.csv
- 3_malicious_domains.csv
- 4_malicious_ips.csv
"""

import csv
import sys
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.models.otx import OTXPulse
from app.models.cve import CVEVulnerability
from app.models.domain import MaliciousDomain
from app.models.ip import MaliciousIP
from app.config import get_settings

# Normalization mappings for ML-consistent exports
THREAT_CATEGORY_MAP = {
    "unrated": "unrated",
    "malware": "malware",
    "malicious": "malware",
    "clean": "clean",
    "anonymizer": "malware",
    "malicious_activity": "malware",
    "suspicious_activity": "unrated",
    "suspicious_hosting": "unrated",
    "scanning": "malware",
    "local": "clean",
}

THREAT_LABEL_MAP = {
    "unrated": "unrated",
    "malware": "malware",
    "clean": "clean",
    "malicious": "malicious",
    "suspicious": "suspicious",
}


def _normalize(val: str, mapping: dict, default: str = "clean") -> str:
    if not val:
        return default
    return mapping.get(val.lower().strip(), default)

def export_otx_pulses(db: Session, output_path: Path):
    """Export OTX pulses to CSV."""
    query = select(OTXPulse)
    pulses = db.execute(query).scalars().all()
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Pulse_ID', 'Title', 'Description', 'Author', 'Created', 'Modified',
            'TLP', 'Tags', 'Malware_Families', 'Attack_IDs', 'Industries',
            'Countries', 'Indicators_Count', 'Subscribers'
        ])
        
        for pulse in pulses:
            writer.writerow([
                pulse.pulse_id,
                pulse.title,
                pulse.description,
                pulse.author,
                pulse.created_at.isoformat() if pulse.created_at else '',
                pulse.modified_at.isoformat() if pulse.modified_at else '',
                pulse.tlp,
                pulse.tags,
                pulse.malware_families,
                pulse.attack_ids,
                pulse.industries,
                pulse.countries,
                pulse.indicators_count,
                pulse.subscribers
            ])
    
    print(f"Exported {len(pulses)} OTX pulses to {output_path}")

def export_cve_vulnerabilities(db: Session, output_path: Path):
    """Export CVE vulnerabilities to CSV."""
    query = select(CVEVulnerability)
    cves = db.execute(query).scalars().all()
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'cveID', 'vendorProject', 'product', 'vulnerabilityName',
            'dateAdded', 'shortDescription', 'requiredAction', 'dueDate',
            'knownRansomwareCampaignUse', 'cwes', 'cvss_v3_score', 'cvss_v3_vector'
        ])
        
        for cve in cves:
            writer.writerow([
                cve.cve_id,
                cve.vendor_project,
                cve.product,
                cve.vulnerability_name,
                cve.date_added.isoformat() if cve.date_added else '',
                cve.short_description,
                cve.required_action,
                cve.due_date.isoformat() if cve.due_date else '',
                cve.known_ransomware_campaign_use,
                cve.cwes,
                cve.cvss_v3_score,
                cve.cvss_v3_vector
            ])
    
    print(f"Exported {len(cves)} CVE vulnerabilities to {output_path}")

def export_malicious_domains(db: Session, output_path: Path):
    """Export malicious domains to CSV."""
    query = select(MaliciousDomain)
    domains = db.execute(query).scalars().all()
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Domain', 'TLD', 'Domain_Length', 'Has_Numbers', 'Has_Hyphen',
            'Registrar', 'Creation_Date', 'Last_Update_Date', 'Reputation',
            'Malicious_Votes', 'Suspicious_Votes', 'Harmless_Votes',
            'Undetected_Votes', 'Total_Engines', 'Threat_Severity',
            'Categories', 'Popularity_Rank', 'Last_Analysis_Date',
            'WHOIS_Summary', 'Data_Source', 'Enrichment_Breakdown'
        ])
        
        for domain in domains:
            writer.writerow([
                domain.domain,
                domain.tld,
                domain.domain_length,
                'Yes' if domain.has_numbers else 'No',
                'Yes' if domain.has_hyphen else 'No',
                domain.registrar,
                domain.creation_date.isoformat() if domain.creation_date else '',
                domain.last_update_date.isoformat() if domain.last_update_date else '',
                domain.reputation,
                domain.malicious_votes,
                domain.suspicious_votes,
                domain.harmless_votes,
                domain.undetected_votes,
                domain.total_engines,
                domain.threat_severity,
                domain.categories,
                domain.popularity_rank,
                domain.last_analysis_date.isoformat() if domain.last_analysis_date else '',
                domain.whois_summary,
                domain.data_source,
                domain.enrichment_breakdown
            ])
    
    print(f"Exported {len(domains)} malicious domains to {output_path}")

def export_malicious_ips(db: Session, output_path: Path):
    """Export malicious IPs to CSV."""
    query = select(MaliciousIP)
    ips = db.execute(query).scalars().all()
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'IP', 'Country', 'Continent', 'ASN', 'Owner', 'Network',
            'Malicious_Votes', 'Suspicious_Votes', 'Harmless_Votes',
            'Undetected_Votes', 'Total_Reports', 'Reputation_Score',
            'Threat_Label', 'Threat_Category', 'Regional_Registry',
            'WHOIS_Summary', 'Tor_Node', 'Times_Submitted',
            'Last_Analysis_Date', 'Threat_Severity', 'Data_Source',
            'Enrichment_Breakdown'
        ])
        
        for ip in ips:
            writer.writerow([
                ip.ip,
                ip.country,
                ip.continent,
                ip.asn,
                ip.owner,
                ip.network,
                ip.malicious_votes,
                ip.suspicious_votes,
                ip.harmless_votes,
                ip.undetected_votes,
                ip.total_reports,
                ip.reputation_score,
                _normalize(ip.threat_label, THREAT_LABEL_MAP),
                _normalize(ip.threat_category, THREAT_CATEGORY_MAP),
                ip.regional_registry,
                ip.whois_summary,
                'Yes' if ip.tor_node else 'No',
                ip.times_submitted,
                ip.last_analysis_date.isoformat() if ip.last_analysis_date else '',
                ip.threat_severity,
                ip.data_source,
                ip.enrichment_breakdown
            ])
    
    print(f"Exported {len(ips)} malicious IPs to {output_path}")

def main():
    """Main export function."""
    settings = get_settings()
    
    # Create database engine
    engine = create_engine(settings.database_url)
    
    # Create data directory if it doesn't exist
    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    
    print(f"Connecting to database: {settings.database_url}")
    
    with Session(engine) as db:
        print("Starting database export...\n")
        
        # Export OTX pulses
        export_otx_pulses(db, data_dir / "1_otx_threat_intel.csv")
        
        # Export CVE vulnerabilities
        export_cve_vulnerabilities(db, data_dir / "2_cve_vulnerabilities.csv")
        
        # Export malicious domains
        export_malicious_domains(db, data_dir / "3_malicious_domains.csv")
        
        # Export malicious IPs
        export_malicious_ips(db, data_dir / "4_malicious_ips.csv")
        
        print("\nDatabase export completed successfully!")

if __name__ == "__main__":
    main()
