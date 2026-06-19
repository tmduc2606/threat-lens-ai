from __future__ import annotations

import logging
import datetime
import httpx
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models.cve import CVEVulnerability
from ..models.otx import OTXPulse
from ..services.api_clients import NVDClient, OTXClient

logger = logging.getLogger(__name__)

nvd_client = NVDClient()
otx_client = OTXClient()

async def sync_cisa_kev(db: Session) -> int:
    """Fetch CISA KEV catalog and upsert into database."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    logger.info("Starting CISA KEV catalog synchronization...")
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV catalog: {e}")
            return 0
            
    vulnerabilities = data.get("vulnerabilities", [])
    logger.info(f"Fetched {len(vulnerabilities)} vulnerabilities from CISA KEV feed.")
    
    upserted_count = 0
    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID")
        if not cve_id:
            continue
            
        # Try converting dates
        try:
            date_added_str = vuln.get("dateAdded")
            date_added = datetime.datetime.strptime(date_added_str, "%Y-%m-%d").date() if date_added_str else datetime.date.today()
        except Exception:
            date_added = datetime.date.today()
            
        try:
            due_date_str = vuln.get("dueDate")
            due_date = datetime.datetime.strptime(due_date_str, "%Y-%m-%d").date() if due_date_str else datetime.date.today()
        except Exception:
            due_date = datetime.date.today()
            
        cve_row = db.get(CVEVulnerability, cve_id)
        if not cve_row:
            cve_row = CVEVulnerability(cve_id=cve_id)
            db.add(cve_row)
            
        cve_row.vendor_project = vuln.get("vendorProject")
        cve_row.product = vuln.get("product")
        cve_row.vulnerability_name = vuln.get("vulnerabilityName")
        cve_row.date_added = date_added
        cve_row.short_description = vuln.get("shortDescription")
        cve_row.required_action = vuln.get("requiredAction")
        cve_row.due_date = due_date
        cve_row.known_ransomware_campaign_use = vuln.get("knownRansomwareCampaignUse") or "Unknown"
        
        # If it doesn't have a CWE yet
        if not cve_row.cwes:
            cve_row.cwes = "Unknown"
            
        upserted_count += 1
        
    try:
        db.commit()
        logger.info(f"Successfully synchronized {upserted_count} CISA KEV vulnerabilities.")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to commit CISA KEV updates: {e}")
        return 0
        
    return upserted_count


async def sync_nvd_recent(db: Session) -> int:
    """Fetch last 24h modified CVEs from NVD API and upsert into database."""
    logger.info("Starting NVD modified CVE synchronization...")
    try:
        data = await nvd_client.get_recent_cves(limit=50)
    except Exception as e:
        logger.error(f"Failed to query recent CVEs from NVD API: {e}")
        return 0
        
    if not data:
        logger.warning("No data returned from NVD API.")
        return 0
        
    vulnerabilities = data.get("vulnerabilities", [])
    logger.info(f"Fetched {len(vulnerabilities)} recently modified CVEs from NVD API.")
    
    upserted_count = 0
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
            
        descriptions = cve.get("descriptions", [])
        short_desc = "No description available."
        for desc in descriptions:
            if desc.get("lang") == "en":
                short_desc = desc.get("value")
                break
                
        metrics = cve.get("metrics", {})
        cvss_v3_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        cvss_score = 0.0
        cvss_vector = ""
        if cvss_v3_list:
            cvss_data = cvss_v3_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
            
        weaknesses = cve.get("weaknesses", [])
        cwe_list = []
        for w in weaknesses:
            desc_list = w.get("description", [])
            for d in desc_list:
                if d.get("lang") == "en":
                    cwe_list.append(d.get("value"))
        cwe_str = ", ".join(cwe_list) if cwe_list else "Unknown"
        
        cve_row = db.get(CVEVulnerability, cve_id)
        if not cve_row:
            cve_row = CVEVulnerability(cve_id=cve_id)
            db.add(cve_row)
            
        cve_row.short_description = short_desc
        cve_row.cvss_v3_score = float(cvss_score)
        cve_row.cvss_v3_vector = cvss_vector
        cve_row.cwes = cwe_str
        cve_row.enriched_at = datetime.datetime.utcnow()
        
        if not cve_row.date_added:
            cve_row.date_added = datetime.date.today()
        if not cve_row.due_date:
            cve_row.due_date = datetime.date.today() + datetime.timedelta(days=14)
            
        upserted_count += 1
        
    try:
        db.commit()
        logger.info(f"Successfully synchronized {upserted_count} CVEs from NVD API.")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to commit NVD API sync updates: {e}")
        return 0
        
    return upserted_count


async def sync_otx_pulses(db: Session) -> int:
    """Fetch OTX subscribed pulses and upsert them into otx_pulses."""
    logger.info("Starting OTX subscribed pulses synchronization...")
    try:
        pulses = await otx_client.get_subscribed_pulses(limit=50)
    except Exception as e:
        logger.error(f"Failed to fetch OTX subscribed pulses: {e}")
        return 0
        
    logger.info(f"Fetched {len(pulses)} subscribed pulses from OTX.")
    
    upserted_count = 0
    for p in pulses:
        pulse_id = p.get("id")
        if not pulse_id:
            continue
            
        pulse_row = db.get(OTXPulse, pulse_id)
        if not pulse_row:
            pulse_row = OTXPulse(pulse_id=pulse_id)
            db.add(pulse_row)
            
        try:
            created_str = p.get("created")
            created_at = datetime.datetime.fromisoformat(created_str.replace("Z", "+00:00")) if created_str else datetime.datetime.utcnow()
        except Exception:
            created_at = datetime.datetime.utcnow()
            
        try:
            modified_str = p.get("modified")
            modified_at = datetime.datetime.fromisoformat(modified_str.replace("Z", "+00:00")) if modified_str else datetime.datetime.utcnow()
        except Exception:
            modified_at = datetime.datetime.utcnow()
            
        pulse_row.title = p.get("name") or "Unnamed Pulse"
        pulse_row.description = p.get("description")
        pulse_row.author = p.get("author_name") or "AlienVault"
        pulse_row.created_at = created_at
        pulse_row.modified_at = modified_at
        pulse_row.tlp = p.get("tlp") or "white"
        pulse_row.tags = ", ".join(p.get("tags", []))
        
        # OTX indicators count
        indicators = p.get("indicators", [])
        pulse_row.indicators_count = len(indicators)
        pulse_row.subscribers = int(p.get("subscriber_count", 0))
        
        upserted_count += 1
        
    try:
        db.commit()
        logger.info(f"Successfully synchronized {upserted_count} OTX pulses.")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to commit OTX pulse sync: {e}")
        return 0
        
    return upserted_count
