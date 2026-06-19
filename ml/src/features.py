from __future__ import annotations

import math
import re
from typing import Any, Dict

import pandas as pd


# ---------------------------------------------------------------------------
# IP Features
# ---------------------------------------------------------------------------

def build_ip_features(features: Dict[str, Any]) -> pd.DataFrame:
    """Build DataFrame with all engineered features the IP model expects."""
    mv = float(features.get("malicious_votes", 0))
    sv = float(features.get("suspicious_votes", 0))
    hv = float(features.get("harmless_votes", 0))
    uv = float(features.get("undetected_votes", 0))
    tr = float(features.get("total_reports", 0))
    rep = float(features.get("reputation_score", 0.0))
    ts = float(features.get("times_submitted", 0))
    tor = features.get("tor_node", False)
    country = str(features.get("country", ""))
    continent = str(features.get("continent", ""))
    asn_str = str(features.get("asn", ""))
    network = str(features.get("network", ""))
    threat_label = str(features.get("threat_label", ""))
    threat_category = str(features.get("threat_category", ""))
    registry = str(features.get("regional_registry", ""))

    total = max(tr, 1)
    malicious_ratio = mv / total
    suspicious_ratio = sv / total
    log_malicious = math.log1p(mv)
    log_suspicious = math.log1p(sv)
    log_harmless = math.log1p(hv)
    log_undetected = math.log1p(uv)
    tor_flag = 1 if tor else 0
    zero_votes = 1 if (mv + sv + hv + uv) == 0 else 0
    negative_reputation = 1 if rep < 0 else 0
    unknown_continent = 1 if continent.lower() in ("", "unknown", "none") else 0
    high_risk_country = 1 if country.upper() in ("CN", "RU", "IR", "KP", "SY", "VE", "UA") else 0
    asn_risk_flag = 1 if asn_str and str(asn_str).lstrip("AS").lstrip("as").isdigit() and int(str(asn_str).lstrip("AS").lstrip("as")) > 200000 else 0
    reputation_score_scaled = max(-5.0, min(5.0, rep / 2.0))
    ip_first_octet = 0
    if network and "/" in network:
        try:
            ip_first_octet = int(network.split("/")[0].split(".")[0])
        except (ValueError, IndexError):
            ip_first_octet = 0

    import datetime
    lad = features.get("last_analysis_date")
    if lad is None:
        lad_year, lad_month, lad_day = 0, 0, 0
    elif isinstance(lad, (datetime.datetime, datetime.date)):
        lad_year = lad.year
        lad_month = lad.month
        lad_day = lad.day
    elif isinstance(lad, str):
        try:
            dt = datetime.datetime.fromisoformat(lad)
            lad_year, lad_month, lad_day = dt.year, dt.month, dt.day
        except (ValueError, TypeError):
            lad_year, lad_month, lad_day = 0, 0, 0
    else:
        lad_year, lad_month, lad_day = 0, 0, 0

    column_map = {
        "Malicious_Votes": mv,
        "Suspicious_Votes": sv,
        "Harmless_Votes": hv,
        "Undetected_Votes": uv,
        "Total_Reports": tr,
        "Reputation_Score": rep,
        "Times_Submitted": ts,
        "Country": country,
        "Continent": continent,
        "ASN": asn_str,
        "Owner": str(features.get("owner", "")),
        "Network": network,
        "Threat_Label": threat_label,
        "Threat_Category": threat_category,
        "Regional_Registry": registry,
        "TOR_Node": str(tor),
        "malicious_ratio": malicious_ratio,
        "suspicious_ratio": suspicious_ratio,
        "log_malicious": log_malicious,
        "log_suspicious": log_suspicious,
        "log_harmless": log_harmless,
        "log_undetected": log_undetected,
        "tor_flag": tor_flag,
        "zero_votes": zero_votes,
        "negative_reputation": negative_reputation,
        "unknown_continent": unknown_continent,
        "high_risk_country": high_risk_country,
        "asn_risk_flag": asn_risk_flag,
        "reputation_score_scaled": reputation_score_scaled,
        "ip_first_octet": ip_first_octet,
        "Last_Analysis_Date_year": lad_year,
        "Last_Analysis_Date_month": lad_month,
        "Last_Analysis_Date_day": lad_day,
    }
    return pd.DataFrame([column_map])


# ---------------------------------------------------------------------------
# Domain Features
# ---------------------------------------------------------------------------

_DOMAIN_EXPECTED_FEATURES = [
    "Domain", "TLD", "Domain_Length", "Has_Numbers", "Has_Hyphen",
    "Registrar", "Creation_Date", "Last_Update_Date", "Reputation",
    "Malicious_Votes", "Suspicious_Votes", "Harmless_Votes",
    "Undetected_Votes", "Total_Engines", "Threat_Severity", "Categories",
    "Popularity_Rank", "Last_Analysis_Date", "WHOIS_Summary", "Data_Source",
    "Creation_Date_year", "Creation_Date_month", "Creation_Date_day",
    "domain_string", "domain_age_days", "log_domain_age", "is_new_domain",
    "entropy", "digit_ratio", "vowel_ratio", "special_ratio",
    "subdomain_count", "token_count", "max_token_length",
    "consecutive_consonants", "consecutive_digits",
    "suspicious_keyword_count", "contains_brand_keyword",
    "contains_login_keyword", "contains_crypto_keyword",
    "contains_bank_keyword", "is_randomized_domain", "malicious_ratio",
    "suspicious_ratio", "log_malicious", "log_suspicious", "tld_risk_score",
    "has_creation_date", "has_registrar", "has_nameservers", "whois_field_count",
]


def build_domain_features(features: Dict[str, Any]) -> pd.DataFrame:
    """Build DataFrame with all engineered features the domain model expects."""
    ml = int(features.get("malicious_votes", 0))
    sl = int(features.get("suspicious_votes", 0))
    hl = int(features.get("harmless_votes", 0))
    ul = int(features.get("undetected_votes", 0))
    te = int(features.get("total_engines", 0) or max(ml, sl, hl, ul))
    domain = str(features.get("domain", ""))
    tld = str(features.get("tld", ""))
    categories = str(features.get("categories", ""))

    total = max(te, 1)
    malicious_ratio = ml / total
    suspicious_ratio = sl / total
    log_malicious = math.log1p(ml)
    log_suspicious = math.log1p(sl)
    entropy = 0.0
    if domain:
        prob = [domain.count(c) / len(domain) for c in set(domain)]
        entropy = -sum(p * math.log2(p) for p in prob)
    digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)
    vowel_ratio = sum(c.lower() in "aeiou" for c in domain) / max(len(domain), 1)
    special_ratio = sum(not c.isalnum() for c in domain) / max(len(domain), 1)
    subdomain_count = domain.count(".")
    token_count = len(domain.replace(".", "-").split("-")) if domain else 0
    max_token_length = max((len(t) for t in domain.replace(".", "-").split("-")), default=0)
    consecutive_consonants = 0
    consecutive_digits = 0
    if domain:
        cons = re.findall(r"[bcdfghjklmnpqrstvwxyz]{2,}", domain.lower())
        consecutive_consonants = max((len(c) for c in cons), default=0)
        digs = re.findall(r"\d{2,}", domain)
        consecutive_digits = max((len(d) for d in digs), default=0)
    suspicious_keywords = ["login", "secure", "account", "verify", "bank", "update", "confirm", "password", "free", "win"]
    suspicious_keyword_count = sum(1 for kw in suspicious_keywords if kw in domain.lower())
    tld_risk_score = 1.0 if tld.lower() in ("tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click", "download") else 0.0
    contains_brand_keyword = 1 if any(b in domain.lower() for b in ["google", "facebook", "amazon", "apple", "microsoft", "paypal", "netflix"]) else 0
    contains_login_keyword = 1 if "login" in domain.lower() else 0
    contains_crypto_keyword = 1 if any(c in domain.lower() for c in ["bitcoin", "crypto", "wallet", "eth", "blockchain"]) else 0
    contains_bank_keyword = 1 if any(b in domain.lower() for b in ["bank", "chase", "wells", "citibank", "hsbc"]) else 0
    is_randomized_domain = 1 if (len(domain) > 20 and entropy > 4.0) or digit_ratio > 0.5 else 0
    is_new_domain = 1 if int(features.get("domain_age_days", 0)) < 30 else 0
    domain_age_days = int(features.get("domain_age_days", 0))
    log_domain_age = math.log1p(max(domain_age_days, 0))

    column_map = {
        "Domain": domain,
        "TLD": tld,
        "Domain_Length": int(features.get("domain_length", len(domain))),
        "Has_Numbers": str(features.get("has_numbers", False)),
        "Has_Hyphen": str(features.get("has_hyphen", False)),
        "Registrar": str(features.get("registrar", "")),
        "Creation_Date": str(features.get("creation_date", "")),
        "Last_Update_Date": str(features.get("last_update_date", "")),
        "Reputation": float(features.get("reputation", 0.0)),
        "Malicious_Votes": ml,
        "Suspicious_Votes": sl,
        "Harmless_Votes": hl,
        "Undetected_Votes": ul,
        "Total_Engines": te,
        "Threat_Severity": str(features.get("threat_severity", "")),
        "Categories": categories,
        "Popularity_Rank": int(features.get("popularity_rank", 0)),
        "Last_Analysis_Date": str(features.get("last_analysis_date", "")),
        "WHOIS_Summary": str(features.get("whois_summary", "")),
        "Data_Source": str(features.get("data_source", "")),
        "Creation_Date_year": int(features.get("creation_date_year", 0)),
        "Creation_Date_month": int(features.get("creation_date_month", 0)),
        "Creation_Date_day": int(features.get("creation_date_day", 0)),
        "domain_string": domain,
        "domain_age_days": domain_age_days,
        "log_domain_age": log_domain_age,
        "is_new_domain": is_new_domain,
        "entropy": entropy,
        "digit_ratio": digit_ratio,
        "vowel_ratio": vowel_ratio,
        "special_ratio": special_ratio,
        "subdomain_count": subdomain_count,
        "token_count": token_count,
        "max_token_length": max_token_length,
        "consecutive_consonants": consecutive_consonants,
        "consecutive_digits": consecutive_digits,
        "suspicious_keyword_count": suspicious_keyword_count,
        "contains_brand_keyword": contains_brand_keyword,
        "contains_login_keyword": contains_login_keyword,
        "contains_crypto_keyword": contains_crypto_keyword,
        "contains_bank_keyword": contains_bank_keyword,
        "is_randomized_domain": is_randomized_domain,
        "malicious_ratio": malicious_ratio,
        "suspicious_ratio": suspicious_ratio,
        "log_malicious": log_malicious,
        "log_suspicious": log_suspicious,
        "tld_risk_score": tld_risk_score,
        "has_creation_date": 1 if features.get("creation_date") else 0,
        "has_registrar": 1 if str(features.get("registrar", "")) not in ("", "Unknown") else 0,
        "has_nameservers": 1 if bool(features.get("nameservers")) else 0,
        "whois_field_count": int(features.get("whois_field_count", 0)),
    }
    df = pd.DataFrame([column_map])
    return df[_DOMAIN_EXPECTED_FEATURES]


# ---------------------------------------------------------------------------
# CVE Features
# ---------------------------------------------------------------------------

def build_cve_features(text: str) -> str:
    """Clean and normalize CVE text for TF-IDF vectorization."""
    text = (text or "").strip().lower()
    text = re.sub(r"[^\w\s\-.,:/]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text
