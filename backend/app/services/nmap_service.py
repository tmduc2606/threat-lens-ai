from __future__ import annotations

import logging
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
import json
import datetime
import ipaddress
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models.nmap_results import NmapResult

logger = logging.getLogger(__name__)


NMAP_PATH: Optional[str] = None
NMAP_COMMON_PORTS = "22,80,443,3389,8080,8443,445,139,135,1433,3306,5432,6379,27017,21,25,110,993,995,389,636,88,464,53,161,162,514,80,443,8080,8443,9090,3000,5000,8000,9000,9200"


def _find_nmap() -> Optional[str]:
    paths = [
        shutil.which("nmap"),
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
    ]
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return None


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            return True
        logger.info(f"IP {ip} is not private/loopback. Skipping Nmap scan.")
        return False
    except ValueError:
        return False


def _parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "hostname": "",
        "open_ports": [],
        "os_guess": "",
        "cpe_entries": [],
    }

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        logger.error(f"Failed to parse Nmap XML: {e}")
        return result

    host = root.find(".//host")
    if host is None:
        return result

    hostname_elem = host.find(".//hostname")
    if hostname_elem is not None:
        result["hostname"] = hostname_elem.get("name", "")

    for port_elem in host.findall(".//port"):
        port_id = port_elem.get("portid")
        protocol = port_elem.get("protocol", "tcp")
        state_elem = port_elem.find("state")
        state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
        service_elem = port_elem.find("service")
        service_name = service_elem.get("name", "") if service_elem is not None else ""
        product = service_elem.get("product", "") if service_elem is not None else ""
        version = service_elem.get("version", "") if service_elem is not None else ""

        cpe_elements = port_elem.findall(".//cpe") if service_elem is not None else []
        for cpe_elem in cpe_elements:
            cpe_str = cpe_elem.text or ""
            if cpe_str and cpe_str not in result["cpe_entries"]:
                result["cpe_entries"].append(cpe_str)

        if state == "open":
            result["open_ports"].append({
                "port": int(port_id) if port_id else 0,
                "protocol": protocol,
                "service": service_name,
                "product": product,
                "version": version,
            })

    os_elem = host.find(".//os/osmatch")
    if os_elem is not None:
        result["os_guess"] = os_elem.get("name", "")

    os_cpe = host.findall(".//os/osmatch/osclass/cpe")
    for cpe_elem in os_cpe:
        cpe_str = cpe_elem.text or ""
        if cpe_str and cpe_str not in result["cpe_entries"]:
            result["cpe_entries"].append(cpe_str)

    return result


async def run_nmap_scan(db: Session, ip: str) -> Optional[NmapResult]:
    global NMAP_PATH
    settings = get_settings()
    if not settings.enable_nmap_scan:
        logger.info("Nmap scanning is disabled (ENABLE_NMAP_SCAN=false). Skipping.")
        return None

    if not _is_private_ip(ip):
        return None

    if NMAP_PATH is None:
        NMAP_PATH = _find_nmap()

    if NMAP_PATH is None:
        logger.error("Nmap executable not found. Ensure nmap is installed and in PATH.")
        return None

    logger.info(f"Running Nmap scan on private IP: {ip} using {NMAP_PATH}")
    try:
        import math
        is_local = ipaddress.ip_address(ip).is_loopback
        nprocs = max(2, min(8, os.cpu_count() or 4))

        if is_local:
            port_range = NMAP_COMMON_PORTS
        else:
            port_range = "1-10000"

        completed = subprocess.run(
            [
                NMAP_PATH,
                "-sT",
                "-sV",
                "--osscan-guess",
                "-O",
                "--version-intensity", "5",
                "--min-rate", "100",
                "--max-retries", "2",
                "--host-timeout", "300s",
                "-p", port_range,
                "-oX", "-",
                "--privileged",
                ip,
            ],
            capture_output=True,
            text=True,
            timeout=600,
            env={**os.environ, "NPARALLEL": str(nprocs)},
        )

        if completed.returncode != 0:
            logger.error(f"Nmap scan failed for {ip}: {completed.stderr[:200]}")
            return None

        xml_text = completed.stdout
        parsed = _parse_nmap_xml(xml_text)

        nmap_row = NmapResult(
            ip=ip,
            scan_date=datetime.datetime.utcnow(),
            hostname=parsed["hostname"],
            open_ports=json.dumps(parsed["open_ports"]),
            os_guess=parsed["os_guess"],
            cpe_entries=json.dumps(parsed["cpe_entries"]),
            raw_xml=xml_text[:5000],
            is_local_ip=True,
        )

        db.add(nmap_row)
        db.commit()
        db.refresh(nmap_row)
        logger.info(f"Nmap scan completed for {ip}: {len(parsed['open_ports'])} open ports found.")
        return nmap_row

    except FileNotFoundError:
        logger.error("Nmap executable not found. Ensure nmap is installed and in PATH.")
        return None
    except subprocess.TimeoutExpired:
        logger.error(f"Nmap scan timed out for {ip}.")
        return None
    except Exception as e:
        logger.error(f"Nmap scan exception for {ip}: {e}")
        return None
