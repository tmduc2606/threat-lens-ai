from __future__ import annotations

import logging
import datetime
import json
import math
import time
import asyncio
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..config import get_settings
from ..models.ip import MaliciousIP
from ..models.domain import MaliciousDomain
from ..models.cve import CVEVulnerability
from ..models.api_cache import APICache
from ..models.enrichment_log import EnrichmentLog
from .api_clients import (
    AbuseIPDBClient,
    OTXClient,
    NVDClient,
    RDAPClient,
    WhoisJSONClient,
    VirusTotalClient,
    URLScanClient,
    ThreatFoxClient,
    URLhausClient,
    MalwareBazaarClient,
    EPSSClient,
)
from ..utils.normalization import country_to_continent, country_to_regional_registry, extract_domain_from_url

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


def normalize_threat_category(value: str) -> str:
    return THREAT_CATEGORY_MAP.get(value.lower() if value else "", "unrated")


def normalize_threat_label(value: str) -> str:
    return THREAT_LABEL_MAP.get(value.lower() if value else "", "suspicious")


logger = logging.getLogger(__name__)

abuseipdb_client = AbuseIPDBClient()
otx_client = OTXClient()
nvd_client = NVDClient()
rdap_client = RDAPClient()
whoisjson_client = WhoisJSONClient()
virustotal_client = VirusTotalClient()
urlscan_client = URLScanClient()
threatfox_client = ThreatFoxClient()
urlhaus_client = URLhausClient()
malwarebazaar_client = MalwareBazaarClient()
epss_client = EPSSClient()


async def get_cached_response(db: Session, cache_key: str) -> Optional[Dict[str, Any]]:
    now = datetime.datetime.utcnow()
    cached = db.get(APICache, cache_key)
    if cached and cached.expires_at > now:
        try:
            return json.loads(cached.response_json)
        except Exception as e:
            logger.error(f"Error parsing cached JSON for {cache_key}: {e}")
    return None


def set_cached_response(db: Session, cache_key: str, source: str, response_data: Dict[str, Any], ttl_seconds: int, dry_run: bool = False):
    if dry_run:
        return
    now = datetime.datetime.utcnow()
    expires_at = now + datetime.timedelta(seconds=ttl_seconds)
    cached = db.get(APICache, cache_key)
    if cached:
        cached.response_json = json.dumps(response_data)
        cached.queried_at = now
        cached.expires_at = expires_at
    else:
        cached = APICache(
            cache_key=cache_key,
            source=source,
            response_json=json.dumps(response_data),
            queried_at=now,
            expires_at=expires_at
        )
        db.add(cached)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to cache response for {cache_key}: {e}")


def log_enrichment(db: Session, indicator_type: str, indicator_value: str, api_source: str, success: bool, latency_ms: int, error_message: Optional[str] = None, dry_run: bool = False):
    if dry_run:
        return
    log_entry = EnrichmentLog(
        indicator_type=indicator_type,
        indicator_value=indicator_value,
        api_source=api_source,
        success=success,
        error_message=error_message,
        latency_ms=latency_ms
    )
    db.add(log_entry)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to save enrichment log: {e}")


class EnrichmentPipeline:
    def __init__(self):
        self.settings = get_settings()

    def _build_ip_source_items(self, ip: str, parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
        items = []
        abuse = parsed.get("abuseipdb") or {}
        otx = parsed.get("otx") or {}
        vt = parsed.get("virustotal") or {}
        tf = parsed.get("threatfox") or {}
        rdap_data = parsed.get("rdap") or {}

        abuse_score = abuse.get("abuseConfidenceScore", 0)
        if isinstance(abuse_score, (int, float)) and abuse_score > 0:
            score = min(10.0, abuse_score / 10.0)
            verdict = "MALICIOUS" if abuse_score >= 50 else "SUSPICIOUS"
            items.append({
                "source_type": "IP", "source_key": ip, "engine": "AbuseIPDB",
                "verdict": verdict, "confidence": "HIGH" if abuse_score >= 80 else "MEDIUM",
                "score": score, "note": f"AbuseIPDB confidence score: {abuse_score}",
                "summary": f"AbuseIPDB confidence score: {abuse_score}",
            })

        otx_pulses = otx.get("pulse_info", {}).get("pulses", []) if isinstance(otx.get("pulse_info"), dict) else []
        if otx_pulses:
            pulse_count = len(otx_pulses)
            score = min(10.0, math.sqrt(pulse_count))
            items.append({
                "source_type": "IP", "source_key": ip, "engine": "OTX",
                "verdict": "MALICIOUS" if pulse_count >= 5 else "SUSPICIOUS",
                "confidence": "HIGH" if pulse_count >= 10 else "MEDIUM",
                "score": score,
                "note": f"OTX: {pulse_count} associated pulses",
                "summary": f"OTX: {pulse_count} associated pulses",
            })

        vt_stats = {}
        if vt and isinstance(vt, dict):
            vt_attrs = vt.get("data", {}).get("attributes", {}) if isinstance(vt.get("data"), dict) else {}
            vt_stats = vt_attrs.get("last_analysis_stats", {}) if isinstance(vt_attrs, dict) else {}
        vt_malicious = vt_stats.get("malicious", 0) if vt_stats else 0
        if vt_malicious > 0:
            score = min(10.0, vt_malicious)
            items.append({
                "source_type": "IP", "source_key": ip, "engine": "VirusTotal",
                "verdict": "MALICIOUS" if vt_malicious >= 3 else "SUSPICIOUS",
                "confidence": "HIGH" if vt_malicious >= 5 else "MEDIUM",
                "score": score,
                "note": f"VirusTotal: {vt_malicious} malicious engines",
                "summary": f"VirusTotal: {vt_malicious} malicious engines",
            })

        if tf and isinstance(tf, dict) and tf.get("query_status") == "ok":
            items.append({
                "source_type": "IP", "source_key": ip, "engine": "ThreatFox",
                "verdict": "MALICIOUS", "confidence": "MEDIUM",
                "score": 6.0,
                "note": "ThreatFox: IOC found in threat database",
                "summary": "ThreatFox: IOC found in threat database",
            })

        if rdap_data and isinstance(rdap_data, dict) and rdap_data.get("name"):
            items.append({
                "source_type": "IP", "source_key": ip, "engine": "RDAP",
                "verdict": "INFORMATIONAL", "confidence": "LOW", "score": 0.0,
                "note": f"RDAP network: {rdap_data.get('name')}",
                "summary": f"RDAP network: {rdap_data.get('name')}",
            })

        return items

    def _build_domain_source_items(self, domain: str, parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
        items = []
        otx = parsed.get("otx") or {}
        vt = parsed.get("virustotal") or {}
        us = parsed.get("urlscan") or {}
        tf = parsed.get("threatfox") or {}
        rdap_data = parsed.get("rdap") or {}
        wj = parsed.get("whoisjson") or {}

        pulse_info = otx.get("pulse_info", {})
        pulses = pulse_info.get("pulses", []) if isinstance(pulse_info, dict) else []
        pulse_count = len(pulses)
        if pulse_count > 0:
            score = min(10.0, math.sqrt(pulse_count))
            items.append({
                "source_type": "DOMAIN", "source_key": domain, "engine": "OTX",
                "verdict": "MALICIOUS" if pulse_count >= 5 else "SUSPICIOUS",
                "confidence": "HIGH" if pulse_count >= 10 else "MEDIUM",
                "score": score,
                "note": f"OTX: {pulse_count} associated pulses",
                "summary": f"OTX: {pulse_count} associated pulses",
            })

        vt_stats = {}
        if vt and isinstance(vt, dict):
            vt_attrs = vt.get("data", {}).get("attributes", {}) if isinstance(vt.get("data"), dict) else {}
            vt_stats = vt_attrs.get("last_analysis_stats", {}) if isinstance(vt_attrs, dict) else {}
        vt_malicious = vt_stats.get("malicious", 0) if vt_stats else 0
        if vt_malicious > 0:
            score = min(10.0, vt_malicious)
            items.append({
                "source_type": "DOMAIN", "source_key": domain, "engine": "VirusTotal",
                "verdict": "MALICIOUS" if vt_malicious >= 3 else "SUSPICIOUS",
                "confidence": "HIGH" if vt_malicious >= 5 else "MEDIUM",
                "score": score,
                "note": f"VirusTotal: {vt_malicious} malicious engines",
                "summary": f"VirusTotal: {vt_malicious} malicious engines",
            })

        if us and isinstance(us, dict):
            us_results = us.get("results", [])
            if us_results:
                rank = us_results[0].get("page", {}).get("rank", 0) or 0
                malicious_us = any(r.get("verdict") == "malicious" for r in us_results if isinstance(r, dict))
                if malicious_us or rank > 0:
                    items.append({
                        "source_type": "DOMAIN", "source_key": domain, "engine": "URLScan",
                        "verdict": "MALICIOUS" if malicious_us else "INFORMATIONAL",
                        "confidence": "MEDIUM", "score": 6.0 if malicious_us else 0.0,
                        "note": f"URLScan: rank={rank}" if rank else "URLScan: domain found",
                        "summary": f"URLScan: rank={rank}" if rank else "URLScan: domain found",
                    })

        if tf and isinstance(tf, dict) and tf.get("query_status") == "ok":
            items.append({
                "source_type": "DOMAIN", "source_key": domain, "engine": "ThreatFox",
                "verdict": "MALICIOUS", "confidence": "MEDIUM", "score": 6.0,
                "note": "ThreatFox: IOC found in threat database",
                "summary": "ThreatFox: IOC found in threat database",
            })

        if rdap_data and isinstance(rdap_data, dict):
            # Extract any useful info from RDAP, not just registrar
            rdap_name = rdap_data.get("name", "")
            rdap_entities = rdap_data.get("entities", []) or []
            registrar_name = ""
            for ent in rdap_entities if isinstance(rdap_entities, list) else []:
                if isinstance(ent, dict):
                    roles = ent.get("roles", [])
                    if "registrar" in [r.lower() for r in roles if isinstance(r, str)]:
                        if "vcardArray" in ent:
                            vcards = ent["vcardArray"]
                            if isinstance(vcards, list) and len(vcards) > 1:
                                for vcard_item in vcards[1] if isinstance(vcards[1], list) else []:
                                    if isinstance(vcard_item, list) and len(vcard_item) > 2 and vcard_item[0] == "fn":
                                        registrar_name = vcard_item[3]
                                        break
                        if not registrar_name and ent.get("handle"):
                            registrar_name = str(ent["handle"])
                        break
            # Build note from whatever RDAP data we have
            rdap_notes = []
            if registrar_name:
                rdap_notes.append(f"registrar: {registrar_name}")
            if rdap_name:
                rdap_notes.append(f"network: {rdap_name}")
            if rdap_notes:
                note = "RDAP: " + ", ".join(rdap_notes)
                items.append({
                    "source_type": "DOMAIN", "source_key": domain, "engine": "RDAP",
                    "verdict": "INFORMATIONAL", "confidence": "LOW", "score": 0.0,
                    "note": note,
                    "summary": note,
                })

        if wj and isinstance(wj, dict):
            wj_data = wj.get("data", wj) if isinstance(wj, dict) else wj
            registrar_name = wj_data.get("registrar_name") or wj_data.get("Registrar") or ""
            if registrar_name:
                items.append({
                    "source_type": "DOMAIN", "source_key": domain, "engine": "WhoisJSON",
                    "verdict": "INFORMATIONAL", "confidence": "LOW", "score": 0.0,
                    "note": f"WhoisJSON registrar: {registrar_name}",
                    "summary": f"WhoisJSON registrar: {registrar_name}",
                })
        return items

    def _build_cve_source_items(self, cve_id: str, parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
        items = []
        nvd_data = parsed.get("nvd") or {}
        epss_data = parsed.get("epss") or {}

        cvss_score = 0.0
        if nvd_data:
            metrics = nvd_data.get("metrics", {})
            cvss_v3_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
            if cvss_v3_list:
                cvss_data = cvss_v3_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)

        if cvss_score > 0:
            score = min(10.0, cvss_score)
            verdict = "CRITICAL" if cvss_score >= 9.0 else "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW"
            items.append({
                "source_type": "CVE", "source_key": cve_id, "engine": "NVD",
                "verdict": verdict, "confidence": "HIGH",
                "score": score, "note": f"NVD CVSS v3 score: {cvss_score}",
                "summary": f"NVD CVSS v3 score: {cvss_score}",
            })

        if epss_data and isinstance(epss_data, dict):
            epss_score = epss_data.get("epss", epss_data.get("score", 0))
            if isinstance(epss_score, (int, float)) and epss_score > 0:
                score = min(10.0, epss_score * 100)
                items.append({
                    "source_type": "CVE", "source_key": cve_id, "engine": "EPSS",
                    "verdict": "MEDIUM" if epss_score >= 0.5 else "LOW",
                    "confidence": "MEDIUM" if epss_score >= 0.3 else "LOW",
                    "score": score,
                    "note": f"EPSS exploit probability: {epss_score:.4f}",
                    "summary": f"EPSS exploit probability: {epss_score:.4f}",
                })

        return items

    async def enrich_ip(self, db: Session, ip: str, dry_run: bool = False) -> Tuple[MaliciousIP, List[Dict[str, Any]]]:
        cache_key = f"ip:{ip}"

        if not dry_run:
            cached_data = await get_cached_response(db, cache_key)
            if cached_data:
                logger.info(f"Cache hit for IP enrichment: {ip}")
                ip_row = db.get(MaliciousIP, ip)
                source_items = self._build_ip_source_items(ip, cached_data)
                if ip_row:
                    if not dry_run:
                        ip_row.enrichment_breakdown = json.dumps(source_items)
                        try:
                            db.commit()
                        except Exception:
                            db.rollback()
                    return ip_row, source_items
                else:
                    return self._save_ip_to_db(db, ip, cached_data, provenance="db_cache", dry_run=dry_run, source_items=source_items), source_items

        start_time = time.time()
        logger.info(f"Querying live APIs for IP enrichment: {ip}")

        tasks = [
            abuseipdb_client.check_ip(ip),
            otx_client.get_ip_reputation(ip),
            virustotal_client.get_ip_report(ip),
            threatfox_client.search_ioc(ip),
            rdap_client.get_ip_network(ip),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        latency_ms = int((time.time() - start_time) * 1000)

        source_names = ["AbuseIPDB", "OTX", "VirusTotal", "ThreatFox", "RDAP"]
        parsed = {}
        for name, res in zip(source_names, results):
            if isinstance(res, Exception):
                logger.error(f"{name} request exception: {res}")
                log_enrichment(db, "IP", ip, name, False, latency_ms, str(res), dry_run=dry_run)
                parsed[name.lower()] = None
            else:
                log_enrichment(db, "IP", ip, name, res is not None, latency_ms, dry_run=dry_run)
                parsed[name.lower()] = res

        source_items = self._build_ip_source_items(ip, parsed)

        nmap_items = []
        if self.settings.enable_nmap_scan:
            try:
                from .nmap_service import run_nmap_scan
                from .nmap_scoring import score_nmap
                nmap_result = await run_nmap_scan(db, ip)
                if nmap_result is not None:
                    from ..models.cve import CVEVulnerability
                    cve_matches = []
                    cpe_raw = nmap_result.cpe_entries
                    if isinstance(cpe_raw, str):
                        cpes = json.loads(cpe_raw) if cpe_raw else []
                    else:
                        cpes = cpe_raw or []
                    for cpe in cpes:
                        cve_rows = (
                            db.query(CVEVulnerability)
                            .filter(CVEVulnerability.cwes.ilike(f"%{cpe}%"))
                            .limit(5)
                            .all()
                        )
                        for row in cve_rows:
                            cve_matches.append({
                                "cve_id": row.cve_id,
                                "cvss": row.cvss_v3_score or 0,
                                "description": (row.short_description or "")[:100],
                            })

                    ml_result = score_nmap(nmap_result, cve_matches)
                    verdict_map = {
                        "malicious": "MALICIOUS", "suspicious": "SUSPICIOUS", "benign": "CLEAN",
                    }
                    ports = json.loads(nmap_result.open_ports) if isinstance(nmap_result.open_ports, str) else (nmap_result.open_ports or [])
                    os_text = nmap_result.os_guess or "Unknown"
                    detail_parts = [f"{len(ports)} open ports", f"OS: {os_text}"]
                    if cve_matches:
                        detail_parts.append(f"{len(cve_matches)} CVE matches")
                    detail_parts.append(f"ML: {ml_result['label']} ({ml_result['confidence']:.2f})")
                    note = " | ".join(detail_parts)
                    nmap_items.append({
                        "source_type": "IP", "source_key": ip, "engine": "NMAP",
                        "verdict": verdict_map.get(ml_result["label"], "SUSPICIOUS"),
                        "confidence": "HIGH" if ml_result["confidence"] >= 0.7 else "MEDIUM",
                        "score": ml_result["score"],
                        "note": note,
                        "summary": note,
                        "ml_model": ml_result["model"],
                        "ml_confidence": ml_result["confidence"],
                        "cve_matches": cve_matches[:5] if cve_matches else [],
                    })
            except Exception as e:
                logger.warning(f"Nmap scan failed for {ip}: {e}")

        if all(v is None for v in parsed.values()):
            logger.warning(f"No API responses for IP {ip}. Falling back to heuristics.")
            from .scan_service import _heuristically_analyze_unseen_ip
            heuristic_features = _heuristically_analyze_unseen_ip(ip)
            db_row = self._save_ip_to_db(db, ip, heuristic_features, provenance="heuristic_fallback", dry_run=dry_run, source_items=nmap_items or [])
            return db_row, nmap_items

        source_items.extend(nmap_items)
        set_cached_response(db, cache_key, "IP_ENRICHMENT", parsed, self.settings.cache_ttl_ip, dry_run=dry_run)
        db_row = self._save_ip_to_db(db, ip, parsed, provenance="live_api", dry_run=dry_run, source_items=source_items)
        return db_row, source_items

    def _save_ip_to_db(self, db: Session, ip: str, raw_data: Dict[str, Any], provenance: str, dry_run: bool = False, source_items: Optional[List[Dict[str, Any]]] = None) -> MaliciousIP:
        ip_row = db.get(MaliciousIP, ip)

        if provenance == "heuristic_fallback":
            features = raw_data
            if "threat_label" in features:
                features["threat_label"] = normalize_threat_label(features["threat_label"])
            if "threat_category" in features:
                features["threat_category"] = normalize_threat_category(features["threat_category"])
        else:
            abuse = raw_data.get("abuseipdb") or {}
            otx = raw_data.get("otx") or {}
            vt = raw_data.get("virustotal") or {}
            rdap_data = raw_data.get("rdap") or {}
            malicious_votes = abuse.get("abuseConfidenceScore", 0)
            total_reports = abuse.get("totalReports", 0)

            vt_stats = {}
            if vt and isinstance(vt, dict):
                vt_data = vt.get("data", {})
                vt_attrs = vt_data.get("attributes", {})
                if vt_attrs:
                    vt_last_stats = vt_attrs.get("last_analysis_stats", {})
                    vt_stats = vt_last_stats if isinstance(vt_last_stats, dict) else {}
                    if vt_stats.get("malicious", 0) > 0:
                        malicious_votes = max(malicious_votes, vt_stats["malicious"] * 15)
                    total_reports = total_reports or vt_stats.get("total", 0)

            suspicious_votes = 0
            harmless_votes = 1
            if malicious_votes > 50:
                suspicious_votes = 2
            elif malicious_votes == 0:
                harmless_votes = 5

            reputation_score = float(harmless_votes - (malicious_votes / 10.0))

            threat_label = "clean"
            if malicious_votes > 40 or total_reports > 10:
                threat_label = "malicious"
            elif malicious_votes > 10 or total_reports > 0:
                threat_label = "suspicious"

            threat_category = "clean"
            if abuse.get("isTor"):
                threat_category = "anonymizer"
            elif threat_label == "malicious":
                threat_category = "malicious_activity"
            elif threat_label == "suspicious":
                threat_category = "suspicious_activity"

            threat_label = normalize_threat_label(threat_label)
            threat_category = normalize_threat_category(threat_category)

            severity = "Low"
            if malicious_votes >= 75:
                severity = "Critical"
            elif malicious_votes >= 50:
                severity = "High"
            elif malicious_votes >= 20:
                severity = "Medium"

            country_code = abuse.get("countryCode") or ""
            if not country_code and otx:
                country_code = otx.get("country_code") or otx.get("country") or ""
            country = country_code.upper() if country_code else "Unknown"

            continent = country_to_continent(country)
            registry = country_to_regional_registry(country)

            asn_str = "Unknown"
            asn_raw = abuse.get("asn")
            if asn_raw is not None and str(asn_raw).strip() and str(asn_raw).strip().lower() != "none":
                asn_str = str(asn_raw).strip().lstrip("AS").lstrip("as")
            elif otx:
                otx_asn = otx.get("asn") or ""
                if otx_asn and otx_asn.lower() != "none":
                    asn_str = str(otx_asn).lstrip("AS").lstrip("as")

            owner = abuse.get("isp") or ""
            if not owner and otx:
                owner = otx.get("org") or otx.get("asn_org") or ""
            if not owner:
                owner = "Unknown ISP"

            network = abuse.get("ipAddress") or ip
            if otx:
                otx_network = otx.get("cidr") or otx.get("network") or ""
                if otx_network:
                    network = otx_network
                else:
                    network = f"{ip}/32"
            elif rdap_data and isinstance(rdap_data, dict):
                for cidr_entry in rdap_data.get("cidr0_cidrs", []) or rdap_data.get("cidr", []):
                    if isinstance(cidr_entry, dict):
                        cidr_str = f"{cidr_entry.get('v4prefix', cidr_entry.get('v6prefix', ''))}/{cidr_entry.get('length', 32)}"
                        if cidr_str:
                            network = cidr_str
                            break
            else:
                network = f"{ip}/32"

            whois_lines = []
            if abuse.get("isp"):
                whois_lines.append(f"ISP: {abuse.get('isp')}")
            if abuse.get("domain"):
                whois_lines.append(f"Domain: {abuse.get('domain')}")
            if otx:
                otx_desc = otx.get("description") or ""
                if otx_desc:
                    whois_lines.append(otx_desc[:200])
            if rdap_data and isinstance(rdap_data, dict):
                rdap_name = rdap_data.get("name") or ""
                if rdap_name:
                    whois_lines.append(f"Network: {rdap_name}")
                rdap_entities = rdap_data.get("entities", [])
                for ent in rdap_entities if isinstance(rdap_entities, list) else []:
                    if isinstance(ent, dict):
                        ent_name = None
                        if "vcardArray" in ent:
                            vcards = ent["vcardArray"]
                            if isinstance(vcards, list) and len(vcards) > 1:
                                for vcard_item in vcards[1] if isinstance(vcards[1], list) else []:
                                    if isinstance(vcard_item, list) and len(vcard_item) > 2 and vcard_item[0] == "fn":
                                        ent_name = vcard_item[3]
                                        break
                        if not ent_name:
                            ent_name = ent.get("handle", "")
                        if ent_name:
                            role = ent.get("roles", [None])[0] if isinstance(ent.get("roles"), list) else ""
                            whois_lines.append(f"{role}: {ent_name}".strip())
            whois_summary = "\n".join(whois_lines) if whois_lines else "Unknown"

            features = {
                "country": country,
                "continent": continent,
                "asn": asn_str,
                "owner": owner,
                "network": network,
                "malicious_votes": int(malicious_votes),
                "suspicious_votes": suspicious_votes,
                "harmless_votes": harmless_votes,
                "undetected_votes": 0,
                "total_reports": int(total_reports),
                "reputation_score": reputation_score,
                "threat_label": threat_label,
                "threat_category": threat_category,
                "regional_registry": registry,
                "whois_summary": whois_summary,
                "tor_node": bool(abuse.get("isTor", False)),
                "times_submitted": int(abuse.get("totalReports", 0)) + 1,
                "threat_severity": severity
            }

        if not ip_row:
            ip_row = MaliciousIP(ip=ip)
            db.add(ip_row)

        for key, val in features.items():
            setattr(ip_row, key, val)

        ip_row.data_source = provenance
        ip_row.enriched_at = datetime.datetime.utcnow()
        ip_row.last_analysis_date = datetime.date.today()

        if not dry_run:
            try:
                db.commit()
                db.refresh(ip_row)
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to persist IP row in database: {e}")

        if source_items is not None and not dry_run:
            try:
                ip_row.enrichment_breakdown = json.dumps(source_items)
                db.commit()
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to persist IP enrichment breakdown: {e}")

        return ip_row

    async def enrich_domain(self, db: Session, domain: str, dry_run: bool = False) -> Tuple[MaliciousDomain, List[Dict[str, Any]]]:
        original_domain = domain
        domain = extract_domain_from_url(domain)

        cache_key = f"domain:{domain}"

        if not dry_run:
            cached_data = await get_cached_response(db, cache_key)
            if cached_data:
                logger.info(f"Cache hit for domain enrichment: {domain}")
                domain_row = db.get(MaliciousDomain, domain)
                source_items = self._build_domain_source_items(domain, cached_data)
                if domain_row:
                    if not dry_run:
                        domain_row.enrichment_breakdown = json.dumps(source_items)
                        try:
                            db.commit()
                        except Exception:
                            db.rollback()
                    return domain_row, source_items
                else:
                    return self._save_domain_to_db(db, domain, cached_data, provenance="db_cache", dry_run=dry_run, source_items=source_items), source_items

        start_time = time.time()
        logger.info(f"Querying live APIs for domain enrichment: {domain}")

        tasks = [
            otx_client.get_domain_reputation(domain),
            virustotal_client.get_domain_report(domain),
            urlscan_client.search_domain(domain),
            threatfox_client.search_ioc(domain),
            rdap_client.get_domain_registrar(domain),
            whoisjson_client.get_domain_whois(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        latency_ms = int((time.time() - start_time) * 1000)

        source_names = ["OTX", "VirusTotal", "URLScan", "ThreatFox", "RDAP", "WhoisJSON"]
        parsed = {}
        for name, res in zip(source_names, results):
            if isinstance(res, Exception):
                logger.error(f"{name} request exception: {res}")
                log_enrichment(db, "DOMAIN", domain, name, False, latency_ms, str(res), dry_run=dry_run)
                parsed[name.lower()] = None
            else:
                log_enrichment(db, "DOMAIN", domain, name, res is not None, latency_ms, dry_run=dry_run)
                parsed[name.lower()] = res

        if all(v is None for v in parsed.values()):
            logger.warning(f"No API response for domain {domain}. Falling back to lexical heuristics.")
            from .scan_service import _heuristically_analyze_unseen_domain
            heuristic_features = _heuristically_analyze_unseen_domain(domain)
            db_row = self._save_domain_to_db(db, domain, heuristic_features, provenance="heuristic_fallback", dry_run=dry_run, source_items=[])
            return db_row, []

        source_items = self._build_domain_source_items(domain, parsed)
        set_cached_response(db, cache_key, "DOMAIN_ENRICHMENT", parsed, self.settings.cache_ttl_domain, dry_run=dry_run)
        db_row = self._save_domain_to_db(db, domain, parsed, provenance="live_api", dry_run=dry_run, source_items=source_items)
        return db_row, source_items

    def _save_domain_to_db(self, db: Session, domain: str, raw_data: Dict[str, Any], provenance: str, dry_run: bool = False, source_items: Optional[List[Dict[str, Any]]] = None) -> MaliciousDomain:
        domain_row = db.get(MaliciousDomain, domain)

        if provenance == "heuristic_fallback":
            features = raw_data
        else:
            otx = raw_data.get("otx") or {}
            vt = raw_data.get("virustotal") or {}
            us = raw_data.get("urlscan") or {}
            tf = raw_data.get("threatfox") or {}
            rdap_data = raw_data.get("rdap") or {}
            wj = raw_data.get("whoisjson") or {}

            pulse_info = otx.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            pulse_count = len(pulses)

            vt_stats = {}
            if vt and isinstance(vt, dict):
                vt_data = vt.get("data", {})
                vt_attrs = vt_data.get("attributes", {})
                if vt_attrs:
                    vt_last_stats = vt_attrs.get("last_analysis_stats", {})
                    vt_stats = vt_last_stats if isinstance(vt_last_stats, dict) else {}

            vt_malicious = vt_stats.get("malicious", 0) if vt_stats else 0
            import math
            malicious_votes = int(math.sqrt(pulse_count)) + vt_malicious

            suspicious_votes = 1 if pulse_count > 0 or vt_malicious > 0 else 0
            harmless_votes = 2 if (pulse_count == 0 and vt_malicious == 0) else 0
            reputation = float(harmless_votes - malicious_votes * 1.5)

            severity = "Low"
            if vt_malicious >= 5:
                severity = "Critical"
            elif vt_malicious >= 3:
                severity = "High"
            elif malicious_votes >= 10:
                severity = "High"
            elif vt_malicious >= 1:
                severity = "Medium"
            elif malicious_votes >= 5:
                severity = "Medium"

            parts = domain.split(".")
            tld = parts[-1].lower() if len(parts) > 1 else ""

            categories = "{}"
            category_tags = []
            if pulse_count > 0:
                for p in pulses:
                    category_tags.extend(p.get("tags", []))
                category_tags = list(dict.fromkeys(category_tags))
                if category_tags:
                    categories = "{" + ", ".join(f"'{t}': '{t}'" for t in category_tags[:5]) + "}"
                else:
                    categories = "{'suspicious_domain': 'suspicious_domain'}"

            registrar = "Unknown"
            if rdap_data and isinstance(rdap_data, dict):
                rdap_entities = rdap_data.get("entities", [])
                for ent in rdap_entities if isinstance(rdap_entities, list) else []:
                    if isinstance(ent, dict):
                        roles = ent.get("roles", [])
                        if isinstance(roles, list) and "registrar" in [r.lower() for r in roles if isinstance(r, str)]:
                            # Strategy 1: vcardArray fn field (most common)
                            if "vcardArray" in ent:
                                vcards = ent["vcardArray"]
                                if isinstance(vcards, list) and len(vcards) > 1:
                                    for vcard_item in vcards[1] if isinstance(vcards[1], list) else []:
                                        if isinstance(vcard_item, list) and len(vcard_item) > 2 and vcard_item[0] == "fn":
                                            registrar = vcard_item[3]
                                            break
                            # Strategy 2: handle field (fallback for some TLDs)
                            if registrar == "Unknown" and ent.get("handle"):
                                registrar = str(ent["handle"])
                            # Strategy 3: vcardArray org field
                            if registrar == "Unknown" and "vcardArray" in ent:
                                vcards = ent["vcardArray"]
                                if isinstance(vcards, list) and len(vcards) > 1:
                                    for vcard_item in vcards[1] if isinstance(vcards[1], list) else []:
                                        if isinstance(vcard_item, list) and len(vcard_item) > 2 and vcard_item[0] == "org":
                                            registrar = vcard_item[3] if len(vcard_item) > 3 else str(vcard_item)
                                            break
                            if registrar != "Unknown":
                                break
                # Strategy 4: top-level name field (some RDAP servers put registrar here)
                if registrar == "Unknown" and rdap_data.get("name"):
                    registrar = str(rdap_data["name"])
            if registrar == "Unknown" and wj and isinstance(wj, dict):
                wj_data = wj.get("data", wj)
                registrar = wj_data.get("registrar_name") or wj_data.get("Registrar") or wj_data.get("registrar") or "Unknown"
            if registrar == "Unknown":
                whois_data = otx.get("whois", "")
                if isinstance(whois_data, dict):
                    registrar = whois_data.get("registrar_name") or whois_data.get("Registrar") or whois_data.get("registrar") or "Unknown"
                elif isinstance(whois_data, str):
                    pass

            whois_data_raw = otx.get("whois", "")
            whois_summary = f"Pulses associated: {pulse_count}."
            creation_date = datetime.date.today()

            whois_dict = {}
            if isinstance(whois_data_raw, dict):
                whois_dict = whois_data_raw
            elif wj and isinstance(wj, dict):
                wj_data = wj.get("data", wj)
                if isinstance(wj_data, dict):
                    whois_dict = wj_data

            if whois_dict:
                whois_lines = []
                for key, label in [
                    ("AdminOrganization", "Administrative organization"),
                    ("AdminCity", "Administrative city"),
                    ("AdminCountry", "Administrative country"),
                    ("AdminState", "Administrative state"),
                    ("AdminEmail", "Administrative email"),
                    ("TechOrganization", "Technical organization"),
                    ("TechCity", "Technical city"),
                    ("TechCountry", "Technical country"),
                    ("TechState", "Technical state"),
                    ("Name", "Name"),
                    ("Organization", "Organization"),
                ]:
                    val = whois_dict.get(key) or whois_dict.get(key.lower())
                    if val:
                        whois_lines.append(f"{label}: {val}")
                for key in ("CreationDate", "creation_date", "created", "created_date"):
                    val = whois_dict.get(key)
                    if val:
                        whois_lines.append(f"Creation Date: {val}")
                        break
                for key in ("DNSSEC", "dnssec"):
                    val = whois_dict.get(key)
                    if val:
                        whois_lines.append(f"DNSSEC: {val}")
                        break
                for key in ("DomainStatus", "domain_status", "status"):
                    val = whois_dict.get(key)
                    if val:
                        whois_lines.append(f"Domain Status: {val}")
                        break
                if whois_lines:
                    whois_summary = "\n".join(whois_lines)
                try:
                    for key in ("CreationDate", "creation_date", "created", "created_date"):
                        cd = whois_dict.get(key, "")
                        if cd:
                            creation_date = datetime.datetime.strptime(str(cd)[:10], "%Y-%m-%d").date()
                            break
                except Exception:
                    pass
            elif isinstance(whois_data_raw, str) and whois_data_raw.strip():
                whois_summary = whois_data_raw.strip()

            popularity_rank = 0
            if us and isinstance(us, dict):
                us_results = us.get("results", [])
                if us_results and len(us_results) > 0:
                    first_result = us_results[0]
                    popularity_rank = first_result.get("page", {}).get("rank", 0) or first_result.get("rank", 0) or 0
            alexa_data = otx.get("alexa")
            if not popularity_rank:
                if isinstance(alexa_data, dict):
                    popularity_rank = alexa_data.get("rank", 0)
                elif isinstance(alexa_data, str) and alexa_data.strip():
                    try:
                        popularity_rank = int(alexa_data.strip())
                    except Exception:
                        popularity_rank = 0
            if not popularity_rank:
                if malicious_votes == 0:
                    popularity_rank = max(10000, int(reputation * 5000)) if reputation > 0 else 0
                else:
                    popularity_rank = min(9999999, 100000 * malicious_votes)

            features = {
                "tld": tld,
                "domain_length": len(domain),
                "has_numbers": any(c.isdigit() for c in domain),
                "has_hyphen": "-" in domain,
                "registrar": registrar,
                "creation_date": creation_date,
                "last_update_date": datetime.date.today(),
                "reputation": reputation,
                "malicious_votes": malicious_votes,
                "suspicious_votes": suspicious_votes,
                "harmless_votes": harmless_votes,
                "undetected_votes": 0,
                "total_engines": malicious_votes + suspicious_votes + harmless_votes,
                "threat_severity": severity,
                "categories": categories,
                "popularity_rank": popularity_rank,
                "whois_summary": whois_summary
            }

        if not domain_row:
            domain_row = MaliciousDomain(domain=domain)
            db.add(domain_row)

        for key, val in features.items():
            if key == "has_numbers" or key == "has_hyphen":
                setattr(domain_row, key, bool(val))
            else:
                setattr(domain_row, key, val)

        domain_row.data_source = provenance
        domain_row.enriched_at = datetime.datetime.utcnow()
        domain_row.last_analysis_date = datetime.date.today()

        if not dry_run:
            try:
                db.commit()
                db.refresh(domain_row)
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to persist Domain row in database: {e}")

        if source_items is not None and not dry_run:
            try:
                domain_row.enrichment_breakdown = json.dumps(source_items)
                db.commit()
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to persist Domain enrichment breakdown: {e}")

        return domain_row

    async def enrich_cve(self, db: Session, cve_id: str, dry_run: bool = False) -> Tuple[CVEVulnerability, List[Dict[str, Any]]]:
        cache_key = f"cve:{cve_id}"

        if not dry_run:
            cached_data = await get_cached_response(db, cache_key)
            if cached_data:
                logger.info(f"Cache hit for CVE enrichment: {cve_id}")
                cve_row = db.get(CVEVulnerability, cve_id)
                source_items = self._build_cve_source_items(cve_id, cached_data)
                if cve_row:
                    if not dry_run:
                        cve_row.enrichment_breakdown = json.dumps(source_items)
                        try:
                            db.commit()
                        except Exception:
                            db.rollback()
                    return cve_row, source_items
                else:
                    return self._save_cve_to_db(db, cve_id, cached_data, provenance="db_cache", dry_run=dry_run, source_items=source_items), source_items

        start_time = time.time()
        logger.info(f"Querying live APIs for CVE enrichment: {cve_id}")

        tasks = [
            nvd_client.get_cve(cve_id),
            epss_client.get_cve_score(cve_id),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        latency_ms = int((time.time() - start_time) * 1000)

        source_names = ["NVD", "EPSS"]
        parsed = {}
        for name, res in zip(source_names, results):
            if isinstance(res, Exception):
                logger.error(f"{name} request exception: {res}")
                log_enrichment(db, "CVE", cve_id, name, False, latency_ms, str(res), dry_run=dry_run)
                parsed[name.lower()] = None
            else:
                log_enrichment(db, "CVE", cve_id, name, res is not None, latency_ms, dry_run=dry_run)
                parsed[name.lower()] = res

        cve_res = parsed.get("nvd") or {}
        epss_res = parsed.get("epss") or {}

        if not cve_res:
            logger.warning(f"No API response for CVE {cve_id}. Falling back to default CVE container.")
            fallback_features = {
                "cve_id": cve_id,
                "vulnerability_name": cve_id,
                "vendor_project": "Unknown",
                "product": "Unknown",
                "short_description": "No CVE description available.",
                "required_action": "No specific actions required.",
                "known_ransomware_campaign_use": "Unknown",
                "cwes": "Unknown",
                "cvss_v3_score": 0.0,
                "cvss_v3_vector": ""
            }
            db_row = self._save_cve_to_db(db, cve_id, fallback_features, provenance="fallback", dry_run=dry_run, source_items=[])
            return db_row, []

        combined_response = {"nvd": cve_res, "epss": epss_res}
        source_items = self._build_cve_source_items(cve_id, combined_response)
        set_cached_response(db, cache_key, "CVE_ENRICHMENT", combined_response, self.settings.cache_ttl_cve, dry_run=dry_run)
        db_row = self._save_cve_to_db(db, cve_id, combined_response, provenance="nvd", dry_run=dry_run, source_items=source_items)
        return db_row, source_items

    def _save_cve_to_db(self, db: Session, cve_id: str, raw_data: Dict[str, Any], provenance: str, dry_run: bool = False, source_items: Optional[List[Dict[str, Any]]] = None) -> CVEVulnerability:
        cve_row = db.get(CVEVulnerability, cve_id)

        if provenance == "fallback":
            features = raw_data
        else:
            nvd_data = raw_data.get("nvd", raw_data)
            epss_data = raw_data.get("epss")

            descriptions = nvd_data.get("descriptions", [])
            short_desc = "No description available."
            for desc in descriptions:
                if desc.get("lang") == "en":
                    short_desc = desc.get("value")
                    break

            cvss_score = 0.0
            cvss_vector = ""
            metrics = nvd_data.get("metrics", {})
            cvss_v3_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
            if cvss_v3_list:
                cvss_data = cvss_v3_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")

            weaknesses = nvd_data.get("weaknesses", [])
            cwe_list = []
            for w in weaknesses:
                desc_list = w.get("description", [])
                for d in desc_list:
                    if d.get("lang") == "en":
                        cwe_list.append(d.get("value"))
            cwe_str = ", ".join(cwe_list) if cwe_list else "Unknown"

            configurations = nvd_data.get("configurations", [])
            vendor = "Unknown"
            product = "Unknown"

            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_matches = node.get("cpeMatch", [])
                    for match in cpe_matches:
                        cpe_uri = match.get("criteria", "")
                        parts = cpe_uri.split(":")
                        if len(parts) > 4:
                            v = parts[3].replace("_", " ").title().strip()
                            p = parts[4].replace("_", " ").title().strip()
                            if v and v != "*":
                                vendor = v
                            if p and p != "*":
                                product = p
                            break
                    if vendor != "Unknown" and product != "Unknown":
                        break
                if vendor != "Unknown" and product != "Unknown":
                    break

            if vendor == "Unknown" or product == "Unknown":
                vendor = nvd_data.get("vendor", vendor)
                product = nvd_data.get("product", product)

            epss_score = None
            epss_percentile = None
            if epss_data and isinstance(epss_data, dict):
                epss_score = epss_data.get("epss", epss_data.get("score"))
                epss_percentile = epss_data.get("percentile")

            features = {
                "cve_id": cve_id,
                "vulnerability_name": f"{cve_id}: {product} {vendor} Vulnerability" if product != "Unknown" else cve_id,
                "vendor_project": vendor,
                "product": product,
                "short_description": short_desc,
                "required_action": "Apply security patches provided by vendor.",
                "known_ransomware_campaign_use": "Unknown",
                "cwes": cwe_str,
                "cvss_v3_score": float(cvss_score),
                "cvss_v3_vector": cvss_vector,
            }

        if not cve_row:
            cve_row = CVEVulnerability(cve_id=cve_id)
            db.add(cve_row)

        for key, val in features.items():
            setattr(cve_row, key, val)

        cve_row.enriched_at = datetime.datetime.utcnow()
        if not cve_row.date_added:
            published = nvd_data.get("published", "") if provenance != "fallback" else ""
            if published:
                try:
                    cve_row.date_added = datetime.datetime.fromisoformat(published.replace("Z", "+00:00")).date()
                except Exception:
                    cve_row.date_added = datetime.date.today()
            else:
                cve_row.date_added = datetime.date.today()
        if not cve_row.due_date:
            if cve_row.date_added:
                cve_row.due_date = cve_row.date_added + datetime.timedelta(days=14)
            else:
                cve_row.due_date = datetime.date.today() + datetime.timedelta(days=14)

        if not dry_run:
            try:
                db.commit()
                db.refresh(cve_row)
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to persist CVE row in database: {e}")

        if source_items is not None and not dry_run:
            try:
                cve_row.enrichment_breakdown = json.dumps(source_items)
                db.commit()
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to persist CVE enrichment breakdown: {e}")

        return cve_row


enrichment_pipeline = EnrichmentPipeline()
