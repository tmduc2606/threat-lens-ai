from __future__ import annotations

import io
import json
import time
import uuid
import logging
import datetime
import asyncio
from functools import lru_cache
from typing import Any, Dict, List, Optional
import pandas as pd

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.training_metadata import TrainingMetadata
from ..config import get_settings

logger = logging.getLogger(__name__)
from ..models.cve import CVEVulnerability
from ..models.domain import MaliciousDomain
from ..models.ip import MaliciousIP
from ..models.otx import OTXPulse
from ..schemas.common import DashboardResponse, SearchResult
from ..services.modeling_service import (
    enrich_cve,
    enrich_domain,
    enrich_ip,
    enrich_otx,
    get_model_status,
    predict_cve,
    predict_domain,
    predict_ip,
    predict_otx_attackids,
)
from ..utils.response_helpers import make_result
from ..utils.scoring import score_cve, score_domain, score_ip, score_otx
from ..utils.normalization import extract_domain_from_url

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

router = APIRouter(prefix="/model", tags=["modeling"])


class PredictRequest(BaseModel):
    payload: Dict[str, Any]


class PredictResponse(BaseModel):
    model: str
    label: Optional[str] = None
    confidence: Optional[float] = None
    probabilities: Optional[List[float]] = None
    classes: Optional[List[str]] = None
    ml_model_available: bool = False


@router.get("/dashboard", response_model=DashboardResponse)
def model_dashboard(db: Session = Depends(get_db), limit: int = Query(default=20, ge=1, le=100)):
    recent_items: List[SearchResult] = []

    cve_rows = db.query(CVEVulnerability).order_by(CVEVulnerability.date_added.desc().nullslast()).limit(limit).all()
    domain_rows = db.query(MaliciousDomain).order_by(MaliciousDomain.last_analysis_date.desc().nullslast()).limit(limit).all()
    ip_rows = db.query(MaliciousIP).order_by(MaliciousIP.last_analysis_date.desc().nullslast()).limit(limit).all()
    otx_rows = db.query(OTXPulse).order_by(OTXPulse.created_at.desc().nullslast()).limit(limit).all()

    for row in cve_rows:
        score, severity, tags, summary = score_cve(row)
        recent_items.append(
            make_result(
                source_type="CVE",
                source_key=row.cve_id,
                title=row.vulnerability_name or row.cve_id,
                summary=summary,
                severity=severity,
                score=score,
                tags=tags,
                created_at=row.date_added,
                updated_at=row.date_added,
            )
        )

    for row in domain_rows:
        score, severity, tags, summary = score_domain(row)
        recent_items.append(
            make_result(
                source_type="DOMAIN",
                source_key=row.domain,
                title=row.domain,
                summary=summary,
                severity=severity,
                score=score,
                tags=tags,
                created_at=row.creation_date,
                updated_at=row.last_analysis_date,
            )
        )

    for row in ip_rows:
        score, severity, tags, summary = score_ip(row)
        recent_items.append(
            make_result(
                source_type="IP",
                source_key=row.ip,
                title=row.ip,
                summary=summary,
                severity=severity,
                score=score,
                tags=tags,
                created_at=row.last_analysis_date,
                updated_at=row.last_analysis_date,
            )
        )

    for row in otx_rows:
        score, severity, tags, summary = score_otx(row)
        recent_items.append(
            make_result(
                source_type="OTX",
                source_key=row.pulse_id,
                title=row.title,
                summary=summary,
                severity=severity,
                score=score,
                tags=tags,
                created_at=row.created_at,
                updated_at=row.modified_at or row.created_at,
            )
        )

    recent_items = sorted(
        recent_items,
        key=lambda r: (r.score, r.updated_at or r.created_at or ""),
        reverse=True,
    )[:limit]

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in recent_items:
        s = (item.severity or "").lower()
        if s in summary:
            summary[s] += 1

    return DashboardResponse(summary=summary, recent=recent_items)


@router.get("/status")
def model_status():
    return {"models": get_model_status()}


@router.get("/stats")
def model_stats(db: Session = Depends(get_db)):
    ip_count = db.query(MaliciousIP).count()
    ip_enriched = db.query(MaliciousIP).filter(MaliciousIP.data_source != "csv_import").count()
    domain_count = db.query(MaliciousDomain).count()
    domain_enriched = db.query(MaliciousDomain).filter(MaliciousDomain.data_source != "csv_import").count()
    cve_count = db.query(CVEVulnerability).count()
    cve_enriched = db.query(CVEVulnerability).filter(CVEVulnerability.enriched_at.isnot(None)).count()
    otx_count = db.query(OTXPulse).count()

    return {
        "total_records": {
            "ip": ip_count,
            "domain": domain_count,
            "cve": cve_count,
            "otx": otx_count,
        },
        "api_enriched": {
            "ip": ip_enriched,
            "domain": domain_enriched,
            "cve": cve_enriched,
        },
        "model_status": get_model_status(),
    }


@router.post("/predict/cve")
def predict_cve_endpoint(request: PredictRequest):
    payload = request.payload
    text = payload.get("text") or " ".join(
        str(payload.get(k, "")) for k in ("vulnerability_name", "short_description", "required_action")
    )
    result = predict_cve(text)
    if result is None:
        return {"model": "cve_tfidf_logreg", "label": None, "confidence": None, "ml_model_available": False}
    return {**result, "ml_model_available": True}


@router.post("/predict/domain")
def predict_domain_endpoint(request: PredictRequest):
    result = predict_domain(request.payload)
    if result is None:
        return {"model": "domain_model", "label": None, "confidence": None, "ml_model_available": False}
    return {**result, "ml_model_available": True}


@router.post("/predict/ip")
def predict_ip_endpoint(
    request: PredictRequest,
    model_name: str = Query(default="xgb", pattern="^(xgb|logreg)$"),
):
    result = predict_ip(request.payload, model_name=model_name)
    if result is None:
        return {"model": f"ip_{model_name}", "label": None, "confidence": None, "ml_model_available": False}
    return {**result, "ml_model_available": True}


@router.post("/predict/otx")
def predict_otx_endpoint(request: PredictRequest):
    payload = request.payload
    text = payload.get("text") or " ".join(str(payload.get(k, "")) for k in ("title", "description", "tags"))
    attackids = predict_otx_attackids(text)

    return {
        "ml_model_available": {
            "attackids": attackids is not None,
        },
        "attackids": attackids or {"model": "otx_attackids", "label": None, "confidence": None},
    }


@router.get("/enrich/cve/{cve_id}")
def enrich_cve_endpoint(cve_id: str, db: Session = Depends(get_db)):
    row = db.get(CVEVulnerability, cve_id)
    if not row:
        raise HTTPException(status_code=404, detail="CVE not found")
    return {"cve_id": cve_id, "ml_prediction": enrich_cve(row)}


@router.get("/enrich/domain/{domain}")
def enrich_domain_endpoint(domain: str, db: Session = Depends(get_db)):
    row = db.get(MaliciousDomain, domain)
    if not row:
        raise HTTPException(status_code=404, detail="Domain not found")
    return {"domain": domain, "ml_prediction": enrich_domain(row)}


@router.get("/enrich/ip/{ip}")
def enrich_ip_endpoint(ip: str, db: Session = Depends(get_db)):
    row = db.get(MaliciousIP, ip)
    if not row:
        raise HTTPException(status_code=404, detail="IP not found")
    return {"ip": ip, "ml_prediction": enrich_ip(row)}


@router.get("/enrich/otx/{pulse_id}")
def enrich_otx_endpoint(pulse_id: str, db: Session = Depends(get_db)):
    row = db.get(OTXPulse, pulse_id)
    if not row:
        raise HTTPException(status_code=404, detail="OTX pulse not found")
    return {"pulse_id": pulse_id, "ml_prediction": enrich_otx(row)}


@router.get("/export/{indicator_type}")
def export_training_data(
    indicator_type: str,
    format: str = "csv",
    only_enriched: bool = Query(default=True),
    db: Session = Depends(get_db)
):
    """
    Export enriched data from DB in training-ready format.
    
    indicator_type: "ip", "domain", "cve"
    format: "csv"
    only_enriched: if True, only exports records enriched via live APIs (data_source != 'csv_import')
    """
    indicator_type = indicator_type.lower().strip()
    if indicator_type not in ("ip", "domain", "cve"):
        raise HTTPException(status_code=400, detail="Invalid indicator type. Must be 'ip', 'domain', or 'cve'.")
        
    if indicator_type == "ip":
        query_obj = db.query(MaliciousIP)
        if only_enriched:
            query_obj = query_obj.filter(MaliciousIP.data_source != "csv_import")
        records = query_obj.all()
        
        data_list = []
        for r in records:
            data_list.append({
                "Malicious_Votes": r.malicious_votes,
                "Suspicious_Votes": r.suspicious_votes,
                "Harmless_Votes": r.harmless_votes,
                "Undetected_Votes": r.undetected_votes,
                "Total_Reports": r.total_reports,
                "Reputation_Score": r.reputation_score,
                "Times_Submitted": r.times_submitted,
                "Country": r.country,
                "Continent": r.continent,
                "ASN": r.asn,
                "Owner": r.owner,
                "Network": r.network,
                "Threat_Label": _normalize(r.threat_label, THREAT_LABEL_MAP),
                "Threat_Category": _normalize(r.threat_category, THREAT_CATEGORY_MAP),
                "Regional_Registry": r.regional_registry,
                "TOR_Node": str(r.tor_node)
            })
        df = pd.DataFrame(data_list)
        
    elif indicator_type == "domain":
        query_obj = db.query(MaliciousDomain)
        if only_enriched:
            query_obj = query_obj.filter(MaliciousDomain.data_source != "csv_import")
        records = query_obj.all()
        
        data_list = []
        for r in records:
            data_list.append({
                "Domain_Length": r.domain_length,
                "Reputation": r.reputation,
                "Malicious_Votes": r.malicious_votes,
                "Suspicious_Votes": r.suspicious_votes,
                "Harmless_Votes": r.harmless_votes,
                "Undetected_Votes": r.undetected_votes,
                "Total_Engines": r.total_engines,
                "Has_Numbers": "Yes" if r.has_numbers else "No",
                "Has_Hyphen": "Yes" if r.has_hyphen else "No",
                "TLD": r.tld,
                "Registrar": r.registrar,
                "Categories": r.categories,
                "Popularity_Rank": str(r.popularity_rank),
                "Data_Source": r.data_source
            })
        df = pd.DataFrame(data_list)
        
    elif indicator_type == "cve":
        query_obj = db.query(CVEVulnerability)
        if only_enriched:
            query_obj = query_obj.filter(CVEVulnerability.enriched_at.isnot(None))
        records = query_obj.all()
        
        data_list = []
        for r in records:
            data_list.append({
                "CVE_ID": r.cve_id,
                "Vulnerability_Name": r.vulnerability_name,
                "Vendor_Project": r.vendor_project,
                "Product": r.product,
                "Short_Description": r.short_description,
                "Required_Action": r.required_action,
                "Known_Ransomware_Campaign_Use": r.known_ransomware_campaign_use,
                "CWEs": r.cwes,
                "CVSS_v3_Score": r.cvss_v3_score,
                "CVSS_v3_Vector": r.cvss_v3_vector
            })
        df = pd.DataFrame(data_list)

    if df.empty:
        if indicator_type == "ip":
            df = pd.DataFrame(columns=["Malicious_Votes", "Suspicious_Votes", "Harmless_Votes", "Undetected_Votes", "Total_Reports", "Reputation_Score", "Times_Submitted", "Country", "Continent", "ASN", "Owner", "Network", "Threat_Label", "Threat_Category", "Regional_Registry", "TOR_Node"])
        elif indicator_type == "domain":
            df = pd.DataFrame(columns=["Domain_Length", "Reputation", "Malicious_Votes", "Suspicious_Votes", "Harmless_Votes", "Undetected_Votes", "Total_Engines", "Has_Numbers", "Has_Hyphen", "TLD", "Registrar", "Categories", "Popularity_Rank", "Data_Source"])
        elif indicator_type == "cve":
            df = pd.DataFrame(columns=["CVE_ID", "Vulnerability_Name", "Vendor_Project", "Product", "Short_Description", "Required_Action", "Known_Ransomware_Campaign_Use", "CWEs", "CVSS_v3_Score", "CVSS_v3_Vector"])

    # Log metadata growth
    try:
        total_recs = db.query(
            MaliciousIP if indicator_type == "ip" else (MaliciousDomain if indicator_type == "domain" else CVEVulnerability)
        ).count()
        
        if indicator_type == "ip":
            enriched_count = db.query(MaliciousIP).filter(MaliciousIP.data_source != "csv_import").count()
        elif indicator_type == "domain":
            enriched_count = db.query(MaliciousDomain).filter(MaliciousDomain.data_source != "csv_import").count()
        else:
            enriched_count = db.query(CVEVulnerability).filter(CVEVulnerability.enriched_at.isnot(None)).count()
            
        metadata_entry = TrainingMetadata(
            indicator_type=indicator_type,
            total_records=total_recs,
            api_enriched_records=enriched_count,
            model_version="pending_retrain",
            notes=f"Exported {len(df)} rows. only_enriched={only_enriched}"
        )
        db.add(metadata_entry)
        db.commit()
    except Exception as e:
        db.rollback()
        # Non-fatal error, log it
        print(f"Failed to log export metadata: {e}")

    # Generate CSV Stream
    stream = io.StringIO()
    df.to_csv(stream, index=False)
    response = StreamingResponse(iter([stream.getvalue()]), media_type="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename=export_{indicator_type}_{int(time.time())}.csv"
    return response


@router.post("/sync")
async def trigger_background_sync(
    feed: str = Query(default="all", pattern="^(all|cisa|nvd|otx)$"),
    db: Session = Depends(get_db)
):
    """
    Manually trigger threat intel feed synchronization.
    
    feed: "all", "cisa", "nvd", or "otx"
    """
    from ..services.background_sync import sync_cisa_kev, sync_nvd_recent, sync_otx_pulses
    
    results = {}
    
    if feed in ("all", "cisa"):
        logger.info("Triggered CISA KEV manual synchronization")
        cisa_count = await sync_cisa_kev(db)
        results["cisa_kev"] = {"status": "success", "synced_records": cisa_count}
        
    if feed in ("all", "nvd"):
        logger.info("Triggered NVD recent manual synchronization")
        nvd_count = await sync_nvd_recent(db)
        results["nvd_recent"] = {"status": "success", "synced_records": nvd_count}
        
    if feed in ("all", "otx"):
        logger.info("Triggered OTX pulses manual synchronization")
        otx_count = await sync_otx_pulses(db)
        results["otx_subscribed_pulses"] = {"status": "success", "synced_records": otx_count}
        
    return {
        "status": "completed",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "results": results
    }


# ---------------------------------------------------------------------------
# Retrain Job Manager
# ---------------------------------------------------------------------------

class RetrainJob:
    def __init__(self, job_id: str, model_type: str):
        self.job_id = job_id
        self.model_type = model_type
        self.status: str = "pending"
        self.progress: float = 0.0
        self.message: str = "Queued"
        self.created_at: str = datetime.datetime.utcnow().isoformat()
        self.completed_at: Optional[str] = None
        self.error: Optional[str] = None


_retrain_jobs: Dict[str, RetrainJob] = {}


def _increment_version(
    version_map: Dict[str, str],
    model_key: str,
) -> str:
    """Increment the patch version for a given model."""
    current = version_map.get(model_key, "v0.0.0")
    parts = current.lstrip("v").split(".")
    major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
    new_version = f"v{major}.{minor}.{patch + 1}"
    version_map[model_key] = new_version
    return new_version


def _save_version_map(version_map: Dict[str, str]) -> None:
    """Persist version map to version.json."""
    version_file = get_settings().models_path / "version.json"
    version_file.parent.mkdir(parents=True, exist_ok=True)
    version_file.write_text(json.dumps(version_map, indent=2))


async def _run_retrain(job_id: str, model_type: str) -> None:
    """Execute retraining asynchronously.

    Creates its own DB session to avoid passing the request-scoped session
    to a background task that outlives the request context.
    """
    from ..database import SessionLocal

    job = _retrain_jobs.get(job_id)
    if not job:
        return

    db = SessionLocal()
    try:
        job.status = "running"
        job.message = f"Starting retrain for {model_type}..."

        from ..services.modeling_service import (
            load_cve_model,
            load_domain_model,
            load_ip_xgb_model,
            load_ip_logreg_model,
            load_otx_minilm_model,
            load_otx_label_encoder,
        )
        from joblib import dump

        types_to_train = ["ip", "domain", "cve", "otx"] if model_type == "all" else [model_type]

        version_map: Dict[str, str] = {}
        version_file = get_settings().models_path / "version.json"
        if version_file.is_file():
            version_map = json.loads(version_file.read_text())

        models_dir = get_settings().models_path
        models_dir.mkdir(parents=True, exist_ok=True)

        for t in types_to_train:
            job.message = f"Retraining {t} model..."
            job.progress = (types_to_train.index(t) / max(len(types_to_train), 1)) * 80.0

            if t == "ip":
                # Export IP data
                from ..models.ip import MaliciousIP
                records = db.query(MaliciousIP).filter(MaliciousIP.data_source != "csv_import").all()
                if not records:
                    job.message = f"Skipping {t}: no enriched records."
                    continue

                data_list = []
                labels = []
                for r in records:
                    data_list.append({
                        "Malicious_Votes": r.malicious_votes,
                        "Suspicious_Votes": r.suspicious_votes,
                        "Harmless_Votes": r.harmless_votes,
                        "Undetected_Votes": r.undetected_votes,
                        "Total_Reports": r.total_reports,
                        "Reputation_Score": r.reputation_score,
                        "Times_Submitted": r.times_submitted,
                        "Country": r.country,
                        "Continent": r.continent,
                        "ASN": r.asn,
                        "Owner": r.owner,
                        "Network": r.network,
                        "Threat_Label": str(r.threat_label or "clean"),
                        "Threat_Category": str(r.threat_category or "unrated"),
                        "Regional_Registry": r.regional_registry,
                        "TOR_Node": str(r.tor_node),
                    })
                    labels.append(1 if str(r.threat_label).lower() in ("malicious", "suspicious") else 0)

                df = pd.DataFrame(data_list)
                feature_cols = [c for c in df.columns if c not in ("Threat_Label", "Threat_Category")]
                X = pd.get_dummies(df[feature_cols], drop_first=True)
                y = pd.Series(labels)

                import xgboost as xgb
                from sklearn.linear_model import LogisticRegression

                # Train XGBoost
                xgb_model = xgb.XGBClassifier(
                    n_estimators=100, max_depth=6, eval_metric="logloss",
                    use_label_encoder=False, random_state=42
                )
                xgb_model.fit(X, y)
                dump({"model": xgb_model}, models_dir / "ip_xgb_model.joblib")
                cache_key_1 = "ip_xgb_model"
                load_ip_xgb_model.cache_clear()
                _increment_version(version_map, cache_key_1)

                # Train LogReg
                lr_model = LogisticRegression(max_iter=1000, random_state=42)
                lr_model.fit(X, y)
                dump({"model": lr_model}, models_dir / "ip_logreg_model.joblib")
                cache_key_2 = "ip_logreg_model"
                load_ip_logreg_model.cache_clear()
                _increment_version(version_map, cache_key_2)

            elif t == "domain":
                from ..models.domain import MaliciousDomain
                records = db.query(MaliciousDomain).filter(MaliciousDomain.data_source != "csv_import").all()
                if not records:
                    job.message = f"Skipping {t}: no enriched records."
                    continue

                data_list = []
                labels = []
                for r in records:
                    data_list.append({
                        "Domain": r.domain,
                        "Domain_Length": r.domain_length,
                        "Reputation": r.reputation,
                        "Malicious_Votes": r.malicious_votes,
                        "Suspicious_Votes": r.suspicious_votes,
                        "Harmless_Votes": r.harmless_votes,
                        "Undetected_Votes": r.undetected_votes,
                        "Total_Engines": r.total_engines,
                        "Has_Numbers": r.has_numbers,
                        "Has_Hyphen": r.has_hyphen,
                        "TLD": r.tld,
                        "Registrar": r.registrar,
                        "Categories": r.categories,
                        "Popularity_Rank": r.popularity_rank,
                    })
                    # Label: 1 if malicious_votes > 0, else 0
                    labels.append(1 if (r.malicious_votes or 0) > 0 else 0)

                df = pd.DataFrame(data_list)
                cat_cols = ["TLD", "Registrar", "Has_Numbers", "Has_Hyphen", "Categories"]
                X = pd.get_dummies(df, columns=[c for c in cat_cols if c in df.columns], drop_first=True)
                X = X.select_dtypes(include=["number"])
                y = pd.Series(labels)

                import lightgbm as lgb
                domain_model = lgb.LGBMClassifier(n_estimators=100, max_depth=8, random_state=42, verbose=-1)
                domain_model.fit(X, y)
                dump({"model": domain_model}, models_dir / "domain_model.joblib")
                load_domain_model.cache_clear()
                _increment_version(version_map, "domain_model")

            elif t == "cve":
                from ..models.cve import CVEVulnerability
                records = db.query(CVEVulnerability).filter(CVEVulnerability.enriched_at.isnot(None)).all()
                if not records:
                    job.message = f"Skipping {t}: no enriched records."
                    continue

                texts = []
                labels = []
                for r in records:
                    text = " ".join(filter(None, [
                        str(r.vulnerability_name or ""),
                        str(r.short_description or ""),
                        str(r.required_action or ""),
                    ]))
                    texts.append(text)
                    cvss = float(r.cvss_v3_score or 0)
                    labels.append(1 if cvss >= 7.0 else 0)

                from sklearn.feature_extraction.text import TfidfVectorizer
                from sklearn.linear_model import LogisticRegression
                from sklearn.pipeline import Pipeline

                cve_model = Pipeline([
                    ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
                    ("lr", LogisticRegression(max_iter=1000, random_state=42)),
                ])
                cve_model.fit(texts, labels)
                dump({"lr_model": cve_model.named_steps["lr"], "model": cve_model}, models_dir / "cve_tfidf_logreg.joblib")
                load_cve_model.cache_clear()
                _increment_version(version_map, "cve_tfidf_logreg")

            elif t == "otx":
                from ..models.otx import OTXPulse
                records = db.query(OTXPulse).all()
                if not records:
                    job.message = f"Skipping {t}: no records."
                    continue

                texts = []
                for r in records:
                    text = " ".join(filter(None, [
                        str(r.title or ""),
                        str(r.description or ""),
                        str(r.tags or ""),
                    ]))
                    texts.append(text)

                if not texts:
                    job.message = f"Skipping {t}: no text data."
                    continue

                from sklearn.linear_model import LogisticRegression
                from sklearn.preprocessing import MultiLabelBinarizer
                import numpy as np

                try:
                    from sentence_transformers import SentenceTransformer
                    st = SentenceTransformer("all-MiniLM-L6-v2")
                    embeddings = st.encode(texts, show_progress_bar=False)

                    # Generate multi-label targets from threat categories or tags
                    mlb = MultiLabelBinarizer()
                    y_labels = []
                    for r in records:
                        tags_str = str(r.tags or "")
                        y_labels.append([t.strip() for t in tags_str.split(",") if t.strip()])
                    y = mlb.fit_transform(y_labels)

                    otx_model = LogisticRegression(max_iter=1000, random_state=42, multi_class="ovr")
                    otx_model.fit(embeddings, y)
                    dump({
                        "model": otx_model,
                        "label_encoder": mlb,
                    }, models_dir / "otx_minilm_logreg.joblib")
                    load_otx_minilm_model.cache_clear()
                    _increment_version(version_map, "otx_minilm_logreg")
                except ImportError:
                    job.message = f"Skipping {t}: sentence-transformers not available."
                    continue

        _save_version_map(version_map)

        job.status = "completed"
        job.progress = 100.0
        job.message = f"Retrain complete for {model_type}. Models saved and versioned."
        job.completed_at = datetime.datetime.utcnow().isoformat()

        # Log to TrainingMetadata
        try:
            meta = TrainingMetadata(
                indicator_type=model_type,
                total_records=sum(len(db.query(
                    MaliciousIP if m == "ip" else (MaliciousDomain if m == "domain" else (CVEVulnerability if m == "cve" else OTXPulse))
                ).all()) for m in types_to_train),
                api_enriched_records=0,
                model_version=version_map.get(model_type, "v0.0.0"),
                notes=f"Retrain completed for {model_type}. Models: {', '.join(types_to_train)}",
            )
            db.add(meta)
            db.commit()
        except Exception:
            db.rollback()

    except Exception as e:
        job.status = "failed"
        job.message = f"Retrain failed: {str(e)}"
        job.error = str(e)
        job.completed_at = datetime.datetime.utcnow().isoformat()
        logger.exception(f"Retrain job {job_id} failed for {model_type}")
    finally:
        db.close()


@router.post("/retrain", status_code=202)
async def start_retrain(
    model_type: str = Query(default="all", pattern="^(ip|domain|cve|otx|all)$"),
):
    """
    Start asynchronous model retraining.
    
    model_type: "ip", "domain", "cve", "otx", or "all" (default)
    Returns 202 Accepted with job_id for status polling.
    """
    job_id = str(uuid.uuid4())[:8]
    job = RetrainJob(job_id=job_id, model_type=model_type)
    _retrain_jobs[job_id] = job

    asyncio.create_task(_run_retrain(job_id, model_type))

    return {
        "status": "accepted",
        "job_id": job_id,
        "model_type": model_type,
        "message": f"Retrain job {job_id} started for {model_type}.",
    }


@router.get("/retrain/status/{job_id}")
def retrain_status(job_id: str):
    """
    Poll the status of a retrain job.
    
    Returns status, progress %, message, and error if failed.
    """
    job = _retrain_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")

    resp = {
        "job_id": job.job_id,
        "status": job.status,
        "progress": job.progress,
        "message": job.message,
        "model_type": job.model_type,
        "created_at": job.created_at,
    }
    if job.completed_at:
        resp["completed_at"] = job.completed_at
    if job.error:
        resp["error"] = job.error

    return resp