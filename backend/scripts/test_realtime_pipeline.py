from __future__ import annotations

import json
import urllib.request
import urllib.parse
import sys
import time

BASE_URL = "http://localhost:8000"

def make_request(path: str, method: str = "GET", payload: dict | None = None) -> dict | str:
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as res:
            content_type = res.headers.get("Content-Type", "")
            body = res.read().decode("utf-8")
            if "text/csv" in content_type:
                return body
            return json.loads(body)
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code} on {method} {path}")
        try:
            return {"error": e.code, "detail": json.loads(e.read().decode("utf-8"))}
        except Exception:
            return {"error": e.code, "reason": e.reason}
    except Exception as e:
        return {"error": str(e)}

def run_pipeline_tests():
    print("==================================================")
    print("Testing Real-Time Threat Intelligence Pipeline")
    print("==================================================")

    # 1. Test Threat Feed Sync manual trigger
    print("\n[1] Triggering Threat Feed Sync (CISA KEV / NVD / OTX)...")
    sync_res = make_request("/model/sync?feed=cisa", method="POST")
    print("Sync Result:", json.dumps(sync_res, indent=2))
    
    # 2. Test Scan for Unseen IP (triggers live API client reputation fetch)
    test_ip = "8.8.8.8"
    print(f"\n[2] Scanning Unseen IP (should trigger live reputation enrichment): {test_ip}")
    start_t = time.time()
    scan_ip_res = make_request(f"/scan?q={test_ip}")
    duration = time.time() - start_t
    print(f"IP Scan completed in {duration:.2f}s")
    print(f"Verdict: {scan_ip_res.get('verdict')}")
    print(f"Confidence: {scan_ip_res.get('confidence')}")
    print(f"Score: {scan_ip_res.get('score')}")
    print(f"Evidence: {scan_ip_res.get('evidence')}")
    print(f"Data source / Provenance in DB: {scan_ip_res.get('source_type')}")
    
    # 3. Test Scan for Unseen Domain (triggers live API client reputation fetch)
    test_domain = "malicious-test-domain.com"
    print(f"\n[3] Scanning Unseen Domain: {test_domain}")
    start_t = time.time()
    scan_domain_res = make_request(f"/scan?q={test_domain}")
    duration = time.time() - start_t
    print(f"Domain Scan completed in {duration:.2f}s")
    print(f"Verdict: {scan_domain_res.get('verdict')}")
    print(f"Confidence: {scan_domain_res.get('confidence')}")
    print(f"Score: {scan_domain_res.get('score')}")
    print(f"Evidence: {scan_domain_res.get('evidence')}")

    # 4. Test Scan for Unseen CVE (triggers NVD live enrichment)
    test_cve = "CVE-2023-38831"
    print(f"\n[4] Scanning Unseen CVE: {test_cve}")
    start_t = time.time()
    scan_cve_res = make_request(f"/scan?q={test_cve}")
    duration = time.time() - start_t
    print(f"CVE Scan completed in {duration:.2f}s")
    print(f"Verdict: {scan_cve_res.get('verdict')}")
    print(f"Confidence: {scan_cve_res.get('confidence')}")
    print(f"Score: {scan_cve_res.get('score')}")
    print(f"Evidence: {scan_cve_res.get('evidence')}")

    # 5. Test Exporting Training Data (Stage 2)
    print("\n[5] Testing Exporting Training Data (only_enriched=True)...")
    for indicator in ("ip", "domain", "cve"):
        export_res = make_request(f"/model/export/{indicator}?only_enriched=true")
        if isinstance(export_res, dict) and "error" in export_res:
            print(f"Export {indicator} failed: {export_res}")
        else:
            # It returns CSV content
            print(f"Successfully triggered CSV export for '{indicator}'.")
            
    print("\n[6] Testing Exporting ALL Training Data (only_enriched=False)...")
    export_all = make_request("/model/export/ip?only_enriched=false")
    if isinstance(export_all, dict) and "error" in export_all:
        print("Export ALL failed:", export_all)
    else:
        print("Successfully triggered ALL IP records export.")

    print("\nAll pipeline tests finished.")

if __name__ == "__main__":
    run_pipeline_tests()
