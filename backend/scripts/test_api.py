import json
import urllib.request
import urllib.parse

BASE_URL = "http://localhost:8000"

def make_request(path, method="GET", payload=None):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as res:
            response_data = res.read().decode("utf-8")
            return json.loads(response_data)
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code} on {method} {path}")
        try:
            err_data = e.read().decode("utf-8")
            return {"error": e.code, "detail": json.loads(err_data)}
        except Exception:
            return {"error": e.code, "reason": e.reason}
    except Exception as e:
        return {"error": str(e)}

def run_tests():
    print("=== Testing ThreatLensAI backend APIs ===")
    
    # 1. Test Root
    print("\n1. GET /")
    root_res = make_request("/")
    print(json.dumps(root_res, indent=2))
    
    # 2. Test Model Status
    print("\n2. GET /model/status")
    status_res = make_request("/model/status")
    print(json.dumps(status_res, indent=2))
    
    # 3. Test CVE Predict Endpoint
    print("\n3. POST /model/predict/cve")
    cve_payload = {"payload": {"text": "A remote code execution vulnerability exists in screenconnect."}}
    cve_res = make_request("/model/predict/cve", method="POST", payload=cve_payload)
    print(json.dumps(cve_res, indent=2))
    
    # 4. Test Domain Predict Endpoint
    print("\n4. POST /model/predict/domain")
    domain_payload = {
        "payload": {
            "domain_length": 16,
            "reputation": 2.0,
            "total_engines": 91,
            "malicious_votes": 3,
            "suspicious_votes": 1,
            "harmless_votes": 50,
            "undetected_votes": 37,
            "has_numbers": False,
            "has_hyphen": False,
            "tld": "ch",
            "registrar": "Unknown",
            "categories": "abuse",
            "popularity_rank": 0,
            "data_source": "VirusTotal"
        }
    }
    domain_res = make_request("/model/predict/domain", method="POST", payload=domain_payload)
    print(json.dumps(domain_res, indent=2))
    
    # 5. Test IP Predict Endpoint (xgb)
    print("\n5. POST /model/predict/ip?model_name=xgb")
    ip_payload = {
        "payload": {
            "ip": "176.10.99.200",
            "malicious_votes": 3,
            "suspicious_votes": 0,
            "harmless_votes": 55,
            "undetected_votes": 33,
            "total_reports": 91,
            "reputation_score": -26.0,
            "times_submitted": 0,
            "country": "CH",
            "continent": "EU",
            "asn": "51395",
            "owner": "Datasource AG",
            "network": "176.10.96.0/19",
            "threat_label": "clean",
            "threat_category": "clean",
            "regional_registry": "RIPE NCC",
            "tor_node": False
        }
    }
    ip_res = make_request("/model/predict/ip?model_name=xgb", method="POST", payload=ip_payload)
    print(json.dumps(ip_res, indent=2))
    
    # 6. Test IP Predict Endpoint (logreg)
    print("\n6. POST /model/predict/ip?model_name=logreg")
    ip_res_lr = make_request("/model/predict/ip?model_name=logreg", method="POST", payload=ip_payload)
    print(json.dumps(ip_res_lr, indent=2))
    
    # 7. Test OTX Predict Endpoint
    print("\n7. POST /model/predict/otx")
    otx_payload = {
        "payload": {
            "text": "Multi-Stage Malware Execution Chain Analysis featuring defense evasion and lateral movement"
        }
    }
    otx_res = make_request("/model/predict/otx", method="POST", payload=otx_payload)
    print(json.dumps(otx_res, indent=2))
    
    # 8. Test Scan Endpoint with exact CVE query
    print("\n8. GET /scan?q=CVE-2024-1708")
    scan_cve = make_request(f"/scan?q={urllib.parse.quote('CVE-2024-1708')}")
    # Print a summary of the response rather than the massive full body
    print(f"Verdict: {scan_cve.get('verdict')}")
    print(f"Confidence: {scan_cve.get('confidence')}")
    print(f"Score: {scan_cve.get('score')}")
    print(f"Evidence: {scan_cve.get('evidence')}")
    print(f"Model status response in scan: {scan_cve.get('model_status')}")
    
    # 9. Test Scan Endpoint with exact Domain query
    print("\n9. GET /scan?q=urlhaus.abuse.ch")
    scan_domain = make_request(f"/scan?q={urllib.parse.quote('urlhaus.abuse.ch')}")
    print(f"Verdict: {scan_domain.get('verdict')}")
    print(f"Confidence: {scan_domain.get('confidence')}")
    print(f"Score: {scan_domain.get('score')}")
    print(f"Evidence: {scan_domain.get('evidence')}")
    
    # 10. Test Scan Endpoint with exact IP query
    print("\n10. GET /scan?q=176.10.99.200")
    scan_ip = make_request(f"/scan?q={urllib.parse.quote('176.10.99.200')}")
    print(f"Verdict: {scan_ip.get('verdict')}")
    print(f"Confidence: {scan_ip.get('confidence')}")
    print(f"Score: {scan_ip.get('score')}")
    print(f"Evidence: {scan_ip.get('evidence')}")
    
    # 11. Test Scan Endpoint with exact OTX pulse query
    print("\n11. GET /scan?q=69f1e236e4e192f639298d53")
    scan_otx = make_request(f"/scan?q={urllib.parse.quote('69f1e236e4e192f639298d53')}")
    print(f"Verdict: {scan_otx.get('verdict')}")
    print(f"Confidence: {scan_otx.get('confidence')}")
    print(f"Score: {scan_otx.get('score')}")
    print(f"Evidence: {scan_otx.get('evidence')}")

    # 12. Test Search Endpoint with query 'ScreenConnect'
    print("\n12. GET /search?q=ScreenConnect")
    search_res = make_request(f"/search?q={urllib.parse.quote('ScreenConnect')}")
    print(f"Count: {search_res.get('count')}")
    if search_res.get('results'):
        print(f"First result: Source Type={search_res['results'][0].get('source_type')}, Title={search_res['results'][0].get('title')}, Score={search_res['results'][0].get('score')}")

if __name__ == "__main__":
    run_tests()
