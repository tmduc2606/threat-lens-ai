from __future__ import annotations

import json
import logging
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from ..config import get_settings
from ..models.nmap_results import NmapResult
from .ml_adapter import load_joblib_artifact, model_exists

logger = logging.getLogger(__name__)

SERVICE_RISK_MAP = {
    "telnet": 0.9, "ftp": 0.8, "ms-sql-s": 0.8, "ms-sql": 0.8,
    "smb": 0.85, "microsoft-ds": 0.85, "netbios-ssn": 0.75,
    "rdp": 0.7, "vnc": 0.75, "rexec": 0.8, "rlogin": 0.8,
    "mysql": 0.6, "postgresql": 0.6, "oracle-tns": 0.7,
    "mongod": 0.65, "redis": 0.7, "memcached": 0.6,
    "ssh": 0.3, "smtp": 0.4, "pop3": 0.4, "imap": 0.4,
    "http": 0.2, "https": 0.15, "http-proxy": 0.3,
    "dns": 0.2, "dhcp": 0.2, "ntp": 0.3, "snmp": 0.5,
    "ldap": 0.4, "kerberos": 0.3, "kpasswd": 0.3,
    "socks": 0.5, "squid": 0.4,
}

SENSITIVE_PORTS = {22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017, 11211, 8080, 8443}


def _port_risk(port: int, service_name: str) -> float:
    base = SERVICE_RISK_MAP.get(service_name.lower().strip(), 0.3)
    if port in SENSITIVE_PORTS:
        base = max(base, 0.5)
    if port < 1024 and service_name in ("unknown", ""):
        base = max(base, 0.4)
    return base


def _os_risk(os_guess: str) -> Tuple[float, str]:
    if not os_guess or os_guess == "Unknown":
        return 0.3, "Unknown OS"
    lower = os_guess.lower()
    if any(x in lower for x in ("windows 7", "windows 8", "windows xp", "windows vista", "windows 2000", "windows nt")):
        return 0.8, "End-of-life OS detected"
    if any(x in lower for x in ("windows 10", "windows server 2008", "windows server 2012")):
        return 0.5, "Aging OS version"
    if any(x in lower for x in ("windows 11", "windows server 2016", "windows server 2019", "windows server 2022")):
        return 0.2, "Modern OS"
    if any(x in lower for x in ("ubuntu 1[4-9]", "centos [6-7]", "debian [7-8]", "linux 2.[0-6]")):
        return 0.6, "Potentially outdated Linux kernel"
    if any(x in lower for x in ("ubuntu", "centos", "debian", "fedora", "rhel", "linux")):
        return 0.2, "Modern Linux"
    if "cisco" in lower or "router" in lower or "switch" in lower or "embedded" in lower:
        return 0.5, "Network device / embedded OS"
    if "mac" in lower or "apple" in lower:
        return 0.2, "Apple OS"
    return 0.3, "Unknown OS fingerprint"


def _extract_feature_vector(nmap_result: NmapResult) -> np.ndarray:
    ports_raw = nmap_result.open_ports
    if isinstance(ports_raw, str):
        ports = json.loads(ports_raw) if ports_raw else []
    else:
        ports = ports_raw or []

    cpe_raw = nmap_result.cpe_entries
    if isinstance(cpe_raw, str):
        cpes = json.loads(cpe_raw) if cpe_raw else []
    else:
        cpes = cpe_raw or []

    port_count = len(ports)
    high_risk = sum(1 for p in ports if _port_risk(p.get("port", 0), p.get("service", "")) >= 0.7)
    med_risk = sum(1 for p in ports if 0.4 <= _port_risk(p.get("port", 0), p.get("service", "")) < 0.7)
    low_risk = sum(1 for p in ports if _port_risk(p.get("port", 0), p.get("service", "")) < 0.4)

    os_score, _ = _os_risk(nmap_result.os_guess or "")
    cpe_count = len(cpes)
    unique_services = len(set(p.get("service", "") for p in ports if p.get("service")))
    distinct_product_count = len(set(p.get("product", "") for p in ports if p.get("product")))

    return np.array([
        port_count / 100.0,
        high_risk / 10.0,
        med_risk / 10.0,
        low_risk / 10.0,
        os_score,
        min(cpe_count / 20.0, 1.0),
        unique_services / 20.0,
        distinct_product_count / 10.0,
        1.0 if port_count == 0 else 0.0,
    ], dtype=np.float32)


def _rule_based_scoring(nmap_result: NmapResult, cve_matches: List[Dict[str, Any]]) -> Dict[str, Any]:
    ports_raw = nmap_result.open_ports
    if isinstance(ports_raw, str):
        ports = json.loads(ports_raw) if ports_raw else []
    else:
        ports = ports_raw or []

    port_count = len(ports)
    if port_count == 0:
        return {"label": "benign", "confidence": 0.7, "score": 0.0, "model": "nmap_rules",
                "details": "No open ports detected"}

    total_risk = 0.0
    high_risk_services = []
    for p in ports:
        risk = _port_risk(p.get("port", 0), p.get("service", ""))
        if risk >= 0.7:
            high_risk_services.append(p.get("service", f"port-{p.get('port')}"))
        total_risk += risk

    avg_port_risk = total_risk / port_count
    os_score, os_note = _os_risk(nmap_result.os_guess or "")
    port_density_bonus = min(port_count / 50.0, 1.0) * 0.2
    cve_bonus = 0.0
    cve_detail = ""
    if cve_matches:
        max_cvss = max((c.get("cvss", 0) or 0) for c in cve_matches)
        cve_bonus = min(len(cve_matches) / 10.0, 1.0) * 0.3 + min(max_cvss / 10.0, 1.0) * 0.2
        cve_detail = f"{len(cve_matches)} CVE matches (max CVSS: {max_cvss})"

    combined = avg_port_risk * 0.4 + os_score * 0.2 + port_density_bonus + cve_bonus
    score = min(10.0, combined * 10.0)

    if score >= 7.0:
        label = "malicious"
        confidence = min(0.95, 0.5 + combined * 0.5)
    elif score >= 4.0:
        label = "suspicious"
        confidence = min(0.85, 0.3 + combined * 0.5)
    elif score >= 1.0:
        label = "suspicious"
        confidence = 0.3 + combined * 0.3
    else:
        label = "benign"
        confidence = 0.7 - combined * 0.5

    details = f"{port_count} open ports"
    if high_risk_services:
        details += f", high-risk: {', '.join(high_risk_services[:3])}"
    if os_note != "Unknown OS":
        details += f", {os_note}"
    if cve_detail:
        details += f", {cve_detail}"

    return {
        "label": label,
        "confidence": round(max(0.0, min(1.0, confidence)), 4),
        "score": round(score, 2),
        "model": "nmap_rules",
        "details": details,
    }


@lru_cache(maxsize=1)
def _load_nmap_model():
    for name in ["nmap_xgb_model.joblib", "nmap_logreg_model.joblib"]:
        m = load_joblib_artifact(name)
        if m is not None:
            return m, name
    return None, None


def nmap_model_exists() -> bool:
    model, _ = _load_nmap_model()
    return model is not None


def score_nmap(nmap_result: NmapResult, cve_matches: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    if cve_matches is None:
        cve_matches = []
    model, model_name = _load_nmap_model()
    if model is not None:
        try:
            features = _extract_feature_vector(nmap_result).reshape(1, -1)
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(features)[0]
                pred = model.predict(features)[0]
                confidence = max(proba)
                label = "malicious" if pred == 1 else "benign"
                score = round(float(confidence) * 10.0, 2)
                return {
                    "label": label,
                    "confidence": round(float(confidence), 4),
                    "score": score,
                    "model": model_name,
                    "probabilities": [round(float(p), 4) for p in proba],
                    "details": f"ML model {model_name}: {label} (confidence: {confidence:.2f})",
                }
        except Exception as e:
            logger.warning(f"Nmap ML model prediction failed: {e}. Falling back to rules.")
    return _rule_based_scoring(nmap_result, cve_matches)
