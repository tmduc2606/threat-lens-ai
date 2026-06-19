from __future__ import annotations

import math
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

from .normalization import clean_text, clean_text_list, normalize_severity, safe_float, safe_int, to_bool


RISK_BANDS = [
    ("CRITICAL", 8.5, 10.0),
    ("HIGH", 6.5, 8.5),
    ("MEDIUM", 4.0, 6.5),
    ("LOW", 1.5, 4.0),
    ("IGNORE", 0.0, 1.5),
]

SOURCE_CREDIBILITY: Dict[str, float] = {
    "ABUSEIPDB": 0.9,
    "VIRUSTOTAL": 0.85,
    "NVD": 0.95,
    "OTX": 0.75,
    "RDAP": 0.7,
    "WHOISJSON": 0.7,
    "EPSS": 0.85,
    "URLSCAN": 0.8,
    "THREATFOX": 0.8,
    "URLHAUS": 0.8,
    "MALWAREBAZAAR": 0.85,
    "ML_PREDICTION": 0.9,
    "DEFAULT": 0.5,
}

VERDICT_WEIGHTS: Dict[str, Optional[float]] = {
    "MALICIOUS": 1.0,
    "SUSPICIOUS": 0.5,
    "CLEAN": 0.0,
    "UNKNOWN": None,
}


def risk_band_from_score(score: float) -> str:
    for band, lo, hi in RISK_BANDS:
        if lo <= score <= hi:
            return band
    return "IGNORE"


def confidence_from_probability(prob: float) -> str:
    if prob >= 0.85:
        return "HIGH"
    elif prob >= 0.65:
        return "MEDIUM"
    elif prob >= 0.40:
        return "LOW"
    return "IGNORE"


def _cap(score: float) -> float:
    return max(0.0, min(10.0, round(score, 2)))


def weighted_consensus(source_breakdown: List[Dict[str, Any]]) -> Tuple[float, float]:
    """
    Weighted vote: each source contributes (verdict_score * credibility).
    Returns (consensus_score_0_to_10, agreement_ratio).
    """
    total_weight = 0.0
    weighted_sum = 0.0
    source_count = 0

    for item in source_breakdown:
        st = str(item.get("source_type", "")).upper()
        verdict = str(item.get("verdict", "UNKNOWN")).upper()
        weight = VERDICT_WEIGHTS.get(verdict)
        if weight is None:
            continue
        credibility = SOURCE_CREDIBILITY.get(st, SOURCE_CREDIBILITY["DEFAULT"])
        total_weight += credibility
        weighted_sum += weight * credibility
        source_count += 1

    if total_weight == 0 or source_count == 0:
        return 0.0, 0.0

    consensus = weighted_sum / total_weight * 10.0
    agreement_ratio = source_count / max(len(source_breakdown), 1)
    return _cap(consensus), agreement_ratio


def temporal_decay(last_enriched: Optional[datetime], half_life_days: int = 30) -> float:
    """Returns a decay factor [0.5, 1.0] based on how stale the data is."""
    if last_enriched is None:
        return 0.7
    if isinstance(last_enriched, str):
        try:
            last_enriched = datetime.fromisoformat(last_enriched)
        except (ValueError, TypeError):
            return 0.7
    days = (datetime.utcnow() - last_enriched).days
    return max(0.5, math.exp(-0.693 * days / half_life_days))


def calibrate_confidence(
    ml_probability: Optional[float],
    n_sources: int,
    agreement_ratio: float,
    is_ensemble: bool = False,
) -> Tuple[Optional[float], Optional[Dict[str, float]]]:
    """
    Returns (calibrated_confidence_pct, confidence_interval_dict).
    Uses Platt-style heuristic: CI widens with few sources/low agreement, narrows with high agreement.
    """
    if ml_probability is None:
        return None, None

    # Platt-style sigmoid scaling
    calibrated = 1.0 / (1.0 + math.exp(-6.0 * (ml_probability - 0.5)))

    # Adjust based on source agreement
    if agreement_ratio > 0:
        calibrated = calibrated * (0.7 + 0.3 * agreement_ratio)

    # Ensemble bonus: multiple models agreeing boost confidence
    if is_ensemble:
        calibrated = min(1.0, calibrated * 1.1)

    cal_pct = round(calibrated * 100, 1)

    # CI width: fewer sources + low agreement = wider interval
    ci_half = 15.0 - min(12.0, n_sources * 2.0) - agreement_ratio * 5.0
    ci_half = max(3.0, min(15.0, ci_half))

    ci = {
        "low": round(max(0.0, cal_pct - ci_half), 1),
        "high": round(min(100.0, cal_pct + ci_half), 1),
    }
    return cal_pct, ci


def compute_composite_score(
    ml_prediction: Optional[Dict[str, Any]],
    source_breakdown: List[Dict[str, Any]],
    heuristic_score: float,
    last_enriched: Optional[datetime] = None,
    is_ensemble: bool = False,
) -> Tuple[float, str, Optional[float], Optional[Dict[str, float]], Dict[str, Any]]:
    """
    Weighted multi-signal scoring.

    Returns (score, risk_band, calibrated_confidence, confidence_interval, breakdown_dict).

    Signal weights:
      - ML model probability: 0.30
      - API consensus ratio:   0.25
      - Heuristic lexical:     0.15
      - Temporal recency:      0.10
      - Severity weight:       0.10
      - Source credibility:    0.10
    """
    # 1. ML model component (0.30)
    ml_prob = None
    if ml_prediction:
        ml_prob = ml_prediction.get("confidence") or ml_prediction.get("calibrated_probability")
    ml_component = (ml_prob or 0.0) * 10.0 * 0.30

    # 2. API consensus component (0.25)
    api_consensus, agreement_ratio = weighted_consensus(source_breakdown)
    consensus_component = api_consensus * 0.25

    # 3. Heuristic component (0.15)
    heuristic_component = _cap(heuristic_score) * 0.15

    # 4. Temporal recency (0.10)
    decay = temporal_decay(last_enriched)
    temporal_component = decay * 1.0 * 0.10

    # 5. Severity weight (0.10)
    severity_score = 0.0
    for item in source_breakdown:
        s = float(item.get("score", 0) or 0)
        if s >= 8.5:
            severity_score += 1.0
        elif s >= 6.5:
            severity_score += 0.7
        elif s >= 4.0:
            severity_score += 0.4
    severity_component = min(1.0, severity_score / max(len(source_breakdown), 1)) * 10.0 * 0.10

    # 6. Source credibility (0.10)
    cred_score = 0.0
    for item in source_breakdown:
        st = str(item.get("source_type", "")).upper()
        cred_score += SOURCE_CREDIBILITY.get(st, SOURCE_CREDIBILITY["DEFAULT"])
    cred_component = (cred_score / max(len(source_breakdown), 1)) * 10.0 * 0.10

    # Normalize: sum of weights = 1.0
    score = ml_component + consensus_component + heuristic_component + temporal_component + severity_component + cred_component
    score = _cap(score)

    # Apply ensemble disagreement penalty if multiple models present
    if is_ensemble and ml_prediction:
        xgb_prob = ml_prediction.get("xgb_probability")
        logreg_prob = ml_prediction.get("logreg_probability")
        if xgb_prob is not None and logreg_prob is not None:
            ensemble_agreement = 1.0 - abs(xgb_prob - logreg_prob)
            score = score * (0.85 + 0.15 * ensemble_agreement)
            score = _cap(score)

    risk_band = risk_band_from_score(score)

    n_sources = len(source_breakdown) + (1 if ml_prediction else 0)
    cal_conf, ci = calibrate_confidence(ml_prob, n_sources, agreement_ratio, is_ensemble)

    breakdown = {
        "ml_component": round(ml_component, 2),
        "consensus_component": round(consensus_component, 2),
        "heuristic_component": round(heuristic_component, 2),
        "temporal_component": round(temporal_component, 2),
        "severity_component": round(severity_component, 2),
        "credibility_component": round(cred_component, 2),
    }

    return score, risk_band, cal_conf, ci, breakdown


def _get(record: Any, key: str, default=None):
    if isinstance(record, dict):
        return record.get(key, default)
    return getattr(record, key, default)


def score_cve(record: Any) -> Tuple[float, str, List[str], str]:
    desc = clean_text(_get(record, "short_description"))
    kev = clean_text(_get(record, "known_ransomware_campaign_use"))
    due_date = _get(record, "due_date")
    vuln_name = clean_text(_get(record, "vulnerability_name"))
    cvss = safe_float(_get(record, "cvss_v3_score"), 0.0)

    text = " ".join(filter(None, [vuln_name, desc, kev])).lower()
    tags: List[str] = []

    text_bonus = 0.0
    if any(word in text for word in ["remote code execution", "rce", "privilege escalation", "sql injection", "ssrf", "auth bypass"]):
        text_bonus += 1.5
        tags.append("Exploit-Prone")
    if kev and kev.strip().lower() in {"yes", "true", "1"}:
        text_bonus += 2.0
        tags.append("KEV")
        tags.append("Exploited")
    if kev and "ransomware" in kev.lower():
        text_bonus += 1.5
        tags.append("Ransomware")
    if due_date:
        if isinstance(due_date, (date, datetime)):
            d = due_date.date() if isinstance(due_date, datetime) else due_date
            delta = d - date.today()
            if delta.days <= 7:
                text_bonus += 1.0
                tags.append("Urgent")
            elif delta.days <= 30:
                text_bonus += 0.5
                tags.append("Patch Soon")
    if desc and len(desc) > 120:
        text_bonus += 0.25

    if cvss > 0:
        score = cvss * 0.7 + min(cvss + text_bonus, 10.0) * 0.3
    else:
        score = 4.0 + text_bonus

    score = _cap(score)
    severity = normalize_severity(None, score)
    if score >= 8.5:
        severity = "Critical"
    return score, severity, list(dict.fromkeys(tags)), _summarize(text or vuln_name or desc or "CVE record")


def score_domain(record: Any) -> Tuple[float, str, List[str], str]:
    malicious = safe_int(_get(record, "malicious_votes"))
    suspicious = safe_int(_get(record, "suspicious_votes"))
    reputation = safe_float(_get(record, "reputation"), 0.0)
    severity = clean_text(_get(record, "threat_severity"))
    has_numbers = to_bool(_get(record, "has_numbers"))
    has_hyphen = to_bool(_get(record, "has_hyphen"))
    categories = clean_text_list(_get(record, "categories"))
    last_analysis = _get(record, "last_analysis_date")
    total = safe_int(_get(record, "total_engines"))

    score = 1.5
    score += min(4.0, malicious * 0.15)
    score += min(2.0, suspicious * 0.08)
    score += max(0.0, min(3.0, (5.0 - max(reputation, -10.0)) * 0.3))
    if total and malicious / max(total, 1) > 0.3:
        score += 1.0
    if has_numbers:
        score += 0.4
    if has_hyphen:
        score += 0.3
    if categories:
        score += min(0.6, len(categories) * 0.15)
    if last_analysis:
        score += 0.2

    tags = []
    if malicious >= 10:
        tags.append("Malicious")
    if suspicious >= 5:
        tags.append("Suspicious")
    if has_numbers:
        tags.append("Digits")
    if has_hyphen:
        tags.append("Hyphen")
    if categories:
        tags.extend(categories[:3])

    score = _cap(score)
    resolved_severity = normalize_severity(severity, score)
    if score >= 8:
        resolved_severity = "High"
    elif score >= 5.5 and resolved_severity == "Unknown":
        resolved_severity = "Medium"
    return score, resolved_severity, list(dict.fromkeys(tags)), _summarize(clean_text(_get(record, "whois_summary")) or "Domain intelligence record")


def score_ip(record: Any) -> Tuple[float, str, List[str], str]:
    malicious = safe_int(_get(record, "malicious_votes"))
    suspicious = safe_int(_get(record, "suspicious_votes"))
    total = safe_int(_get(record, "total_reports"))
    reputation = safe_float(_get(record, "reputation_score"), 0.0)
    tor_node = to_bool(_get(record, "tor_node"))
    category = clean_text(_get(record, "threat_category"))
    label = clean_text(_get(record, "threat_label"))

    score = 1.0
    score += min(4.5, malicious * 0.12)
    score += min(1.5, suspicious * 0.05)
    score += max(0.0, min(3.0, 5.0 - max(reputation, -10.0)))
    if total and malicious / max(total, 1) > 0.25:
        score += 0.75
    if tor_node:
        score += 1.25
    if category:
        score += 0.5
    if label and any(x in label.lower() for x in ["botnet", "scanner", "brute", "exfil", "c2"]):
        score += 0.75

    tags = []
    if tor_node:
        tags.append("TOR")
    if category:
        tags.append(category)
    if label:
        tags.append(label)
    if malicious >= 15:
        tags.append("High-Vote")

    score = _cap(score)
    severity = normalize_severity(None, score)
    if score >= 8.5:
        severity = "High"
    elif score >= 5.5 and severity == "Unknown":
        severity = "Medium"
    return score, severity, list(dict.fromkeys(tags)), _summarize(clean_text(_get(record, "whois_summary")) or "IP intelligence record")


def score_otx(record: Any) -> Tuple[float, str, List[str], str]:
    indicators = safe_int(_get(record, "indicators_count"))
    subscribers = safe_int(_get(record, "subscribers"))
    malware_families = clean_text_list(_get(record, "malware_families"))
    attack_ids = clean_text_list(_get(record, "attack_ids"))
    tags_text = clean_text_list(_get(record, "tags"))
    description = clean_text(_get(record, "description"))
    title = clean_text(_get(record, "title"))

    score = 1.5
    score += min(3.0, indicators * 0.08)
    score += min(2.0, subscribers * 0.02)
    if malware_families:
        score += 1.0
    if attack_ids:
        score += 0.75
    if tags_text:
        score += min(1.0, len(tags_text) * 0.15)
    if description and len(description) > 120:
        score += 0.5

    tags = []
    tags.extend(tags_text[:4])
    tags.extend([f"ATT&CK:{x}" for x in attack_ids[:2]])
    tags.extend(malware_families[:3])

    score = _cap(score)
    severity = normalize_severity(None, score)
    if score >= 8:
        severity = "High"
    elif score >= 5 and severity == "Unknown":
        severity = "Medium"
    return score, severity, list(dict.fromkeys(tags)), _summarize(description or title or "OTX pulse")


def build_excerpt(*parts: Any, limit: int = 220) -> str:
    text = " ".join([str(part).strip() for part in parts if part not in (None, "")]).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _summarize(text: str) -> str:
    text = " ".join(text.split())
    if len(text) <= 180:
        return text
    return text[:177].rstrip() + "..."