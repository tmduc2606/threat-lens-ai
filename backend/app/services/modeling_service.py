from __future__ import annotations

import json
import logging
import sys as _sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np
import pandas as pd

from ..config import get_settings
from ..utils.normalization import clean_text, clean_text_list
from .ml_adapter import load_joblib_artifact, model_exists

# Add ml/src to path for shared feature engineering module
# Path: backend/app/services/modeling_service.py -> parents[3] = threat-lens-ia/
_tla_root = Path(__file__).resolve().parents[3]
_ml_src = _tla_root / "ml" / "src"
if str(_ml_src) not in _sys.path:
    _sys.path.insert(0, str(_ml_src))

# Fallback: also try legacy data_science/src for backward compatibility
_legacy_src = _tla_root / "data_science" / "src"
if str(_legacy_src) not in _sys.path and _legacy_src != _ml_src:
    _sys.path.insert(0, str(_legacy_src))

try:
    from features import build_domain_features, build_ip_features
except ImportError:
    # Fallback: define locally if import fails
    def build_ip_features(features):  # type: ignore
        return _build_ip_df_local(features)

    def build_domain_features(features):  # type: ignore
        return _build_domain_df_local(features)

logger = logging.getLogger(__name__)

LABEL_MAP = {
    0: "benign",
    1: "malicious",
}


def _to_python(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, (list, tuple)):
        return [_to_python(v) for v in value]
    if isinstance(value, dict):
        return {k: _to_python(v) for k, v in value.items()}
    return value


def _extract_model(artifact: Any) -> Any:
    if isinstance(artifact, dict) and "model" in artifact:
        return artifact["model"]
    if isinstance(artifact, dict) and "lr_model" in artifact:
        return artifact["lr_model"]
    return artifact


def _extract_label_encoder(artifact: Any) -> Optional[Any]:
    if isinstance(artifact, dict) and "label_encoder" in artifact:
        return artifact["label_encoder"]
    return None


def _normalize_prediction(
    model_name: str,
    prediction: Any,
    probabilities: Optional[list[float]] = None,
    classes: Optional[list[Any]] = None,
) -> Dict[str, Any]:
    confidence = max(probabilities) if probabilities else None
    return {
        "model": model_name,
        "label": LABEL_MAP.get(prediction, str(prediction)),
        "confidence": _to_python(confidence),
        "classes": _to_python(classes),
        "probabilities": _to_python(probabilities),
    }


# ---------------------------------------------------------------------------
# CVE
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def load_cve_model():
    return load_joblib_artifact("cve_tfidf_logreg.joblib")


def predict_cve(text: str) -> Optional[Dict[str, Any]]:
    artifact = load_cve_model()
    if artifact is None:
        return None
    try:
        text = (text or "").strip()
        if not text:
            return None
        # Artifact has both 'model' (Pipeline with TF-IDF + LogReg) and 'lr_model' (raw LogReg).
        # Use the Pipeline so text is properly vectorized before prediction.
        pipeline = _extract_model(artifact)
        if pipeline is None:
            return None
        if hasattr(pipeline, "predict_proba"):
            proba = pipeline.predict_proba([text])[0]
            prediction = pipeline.predict([text])[0]
            classes = getattr(pipeline, "classes_", None)
            return _normalize_prediction(
                model_name="cve_tfidf_logreg",
                prediction=prediction,
                probabilities=list(proba),
                classes=list(classes) if classes is not None else None,
            )
        pred = pipeline.predict([text])[0]
        return _normalize_prediction(model_name="cve_tfidf_logreg", prediction=pred)
    except Exception as e:
        logger.warning(f"CVE prediction failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def load_domain_model():
    return load_joblib_artifact("domain_model.joblib")


def _build_domain_df_local(features: Dict[str, Any]) -> pd.DataFrame:
    """Local fallback for build_domain_features when import fails."""
    import math, re as _re
    ml = int(features.get("malicious_votes", 0))
    sl = int(features.get("suspicious_votes", 0))
    hl = int(features.get("harmless_votes", 0))
    ul = int(features.get("undetected_votes", 0))
    te = int(features.get("total_engines", 0) or max(ml, sl, hl, ul))
    domain = str(features.get("domain", ""))
    tld = str(features.get("tld", ""))
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
        cons = _re.findall(r"[bcdfghjklmnpqrstvwxyz]{2,}", domain.lower())
        consecutive_consonants = max((len(c) for c in cons), default=0)
        digs = _re.findall(r"\d{2,}", domain)
        consecutive_digits = max((len(d) for d in digs), default=0)
    suspicious_keywords = ["login", "secure", "account", "verify", "bank", "update", "confirm", "password", "free", "win"]
    suspicious_keyword_count = sum(1 for kw in suspicious_keywords if kw in domain.lower())
    tld_risk_score = 1.0 if tld.lower() in ("tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click", "download") else 0.0
    contains_brand_keyword = 1 if any(b in domain.lower() for b in ["google", "facebook", "amazon", "apple", "microsoft", "paypal", "netflix"]) else 0
    contains_login_keyword = 1 if "login" in domain.lower() else 0
    contains_crypto_keyword = 1 if any(c in domain.lower() for c in ["bitcoin", "crypto", "wallet", "eth", "blockchain"]) else 0
    contains_bank_keyword = 1 if any(b in domain.lower() for b in ["bank", "chase", "wells", "citibank", "hsbc"]) else 0
    is_new_domain = 1 if int(features.get("domain_age_days", 0)) < 30 else 0
    domain_age_days = int(features.get("domain_age_days", 0))
    log_domain_age = math.log1p(max(domain_age_days, 0))
    return pd.DataFrame([{
        "Domain": domain, "TLD": tld, "Domain_Length": int(features.get("domain_length", len(domain))),
        "Has_Numbers": str(features.get("has_numbers", False)), "Has_Hyphen": str(features.get("has_hyphen", False)),
        "Registrar": str(features.get("registrar", "")), "Creation_Date": str(features.get("creation_date", "")),
        "Last_Update_Date": str(features.get("last_update_date", "")), "Reputation": float(features.get("reputation", 0.0)),
        "Malicious_Votes": ml, "Suspicious_Votes": sl, "Harmless_Votes": hl, "Undetected_Votes": ul, "Total_Engines": te,
        "Threat_Severity": str(features.get("threat_severity", "")), "Categories": str(features.get("categories", "")),
        "Popularity_Rank": int(features.get("popularity_rank", 0)),
        "Last_Analysis_Date": str(features.get("last_analysis_date", "")),
        "WHOIS_Summary": str(features.get("whois_summary", "")), "Data_Source": str(features.get("data_source", "")),
        "Creation_Date_year": int(features.get("creation_date_year", 0)),
        "Creation_Date_month": int(features.get("creation_date_month", 0)),
        "Creation_Date_day": int(features.get("creation_date_day", 0)),
        "domain_string": domain, "domain_age_days": domain_age_days, "log_domain_age": log_domain_age,
        "is_new_domain": is_new_domain, "entropy": entropy, "digit_ratio": digit_ratio, "vowel_ratio": vowel_ratio,
        "special_ratio": special_ratio, "subdomain_count": subdomain_count, "token_count": token_count,
        "max_token_length": max_token_length, "consecutive_consonants": consecutive_consonants,
        "consecutive_digits": consecutive_digits, "suspicious_keyword_count": suspicious_keyword_count,
        "contains_brand_keyword": contains_brand_keyword, "contains_login_keyword": contains_login_keyword,
        "contains_crypto_keyword": contains_crypto_keyword, "contains_bank_keyword": contains_bank_keyword,
        "is_randomized_domain": 1 if (len(domain) > 20 and entropy > 4.0) or digit_ratio > 0.5 else 0,
        "malicious_ratio": malicious_ratio, "suspicious_ratio": suspicious_ratio,
        "log_malicious": log_malicious, "log_suspicious": log_suspicious, "tld_risk_score": tld_risk_score,
        "has_creation_date": 1 if features.get("creation_date") else 0,
        "has_registrar": 1 if str(features.get("registrar", "")) not in ("", "Unknown") else 0,
        "has_nameservers": 1 if bool(features.get("nameservers")) else 0,
        "whois_field_count": int(features.get("whois_field_count", 0)),
    }])


def predict_domain(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    artifact = load_domain_model()
    model = _extract_model(artifact)
    le = _extract_label_encoder(artifact)
    if model is None:
        return None
    try:
        df = build_domain_features(features)
        if hasattr(model, "feature_names_in_"):
            df = df[list(model.feature_names_in_)]
        elif hasattr(model, "steps") and hasattr(model.steps[0][1], "_feature_names_in_"):
            expected = list(model.steps[0][1]._feature_names_in_)
            df = df[[c for c in expected if c in df.columns]]
        # Transform through pipeline steps separately to avoid sklearn 1.8+ auto-generated
        # integer column names (0,1,2…) clashing with LGBMClassifier's training-time
        # "Column_0" feature names. Wrap the post-preprocessing output in a DataFrame
        # using the exact column names the estimator was trained with.
        if hasattr(model, "steps") and len(model.steps) >= 2:
            X = model[:-1].transform(df)
            clf_est = model[-1]
            est_fnames = getattr(clf_est, "feature_names_in_", None)
            if est_fnames is not None and X.shape[1] == len(est_fnames):
                X = pd.DataFrame(X, columns=list(est_fnames))
            prediction = clf_est.predict(X)[0]
            if le is not None:
                prediction = le.inverse_transform([prediction])[0]
            if hasattr(clf_est, "predict_proba"):
                proba = clf_est.predict_proba(X)[0]
                classes = getattr(clf_est, "classes_", None)
                return _normalize_prediction(
                    model_name="domain_model",
                    prediction=prediction,
                    probabilities=list(proba),
                    classes=list(classes) if classes is not None else None,
                )
            return _normalize_prediction(model_name="domain_model", prediction=prediction)
        prediction = model.predict(df)[0]
        if le is not None:
            prediction = le.inverse_transform([prediction])[0]
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(df)[0]
            classes = getattr(model, "classes_", None)
            return _normalize_prediction(
                model_name="domain_model",
                prediction=prediction,
                probabilities=list(proba),
                classes=list(classes) if classes is not None else None,
            )
        return _normalize_prediction(model_name="domain_model", prediction=prediction)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# IP
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def load_ip_xgb_model():
    return load_joblib_artifact("ip_xgb_model.joblib")


@lru_cache(maxsize=1)
def load_ip_logreg_model():
    return load_joblib_artifact("ip_logreg_model.joblib")


def _build_ip_df_local(features: Dict[str, Any]) -> pd.DataFrame:
    """Local fallback for build_ip_features when import fails."""
    import math, datetime
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
    registry = str(features.get("regional_registry", ""))
    total = max(tr, 1)
    lad = features.get("last_analysis_date")
    if lad is None:
        lad_year, lad_month, lad_day = 0, 0, 0
    elif isinstance(lad, (datetime.datetime, datetime.date)):
        lad_year, lad_month, lad_day = lad.year, lad.month, lad.day
    elif isinstance(lad, str):
        try:
            dt = datetime.datetime.fromisoformat(lad)
            lad_year, lad_month, lad_day = dt.year, dt.month, dt.day
        except (ValueError, TypeError):
            lad_year, lad_month, lad_day = 0, 0, 0
    else:
        lad_year, lad_month, lad_day = 0, 0, 0
    ip_first_octet = 0
    if network and "/" in network:
        try:
            ip_first_octet = int(network.split("/")[0].split(".")[0])
        except (ValueError, IndexError):
            ip_first_octet = 0
    return pd.DataFrame([{
        "Malicious_Votes": mv, "Suspicious_Votes": sv, "Harmless_Votes": hv, "Undetected_Votes": uv,
        "Total_Reports": tr, "Reputation_Score": rep, "Times_Submitted": ts,
        "Country": country, "Continent": continent, "ASN": asn_str, "Owner": str(features.get("owner", "")),
        "Network": network, "Threat_Label": str(features.get("threat_label", "")),
        "Threat_Category": str(features.get("threat_category", "")), "Regional_Registry": registry,
        "TOR_Node": str(tor),
        "malicious_ratio": mv / total, "suspicious_ratio": sv / total,
        "log_malicious": math.log1p(mv), "log_suspicious": math.log1p(sv),
        "log_harmless": math.log1p(hv), "log_undetected": math.log1p(uv),
        "tor_flag": 1 if tor else 0, "zero_votes": 1 if (mv + sv + hv + uv) == 0 else 0,
        "negative_reputation": 1 if rep < 0 else 0,
        "unknown_continent": 1 if continent.lower() in ("", "unknown", "none") else 0,
        "high_risk_country": 1 if country.upper() in ("CN", "RU", "IR", "KP", "SY", "VE", "UA") else 0,
        "asn_risk_flag": 1 if asn_str and str(asn_str).lstrip("AS").lstrip("as").isdigit() and int(str(asn_str).lstrip("AS").lstrip("as")) > 200000 else 0,
        "reputation_score_scaled": max(-5.0, min(5.0, rep / 2.0)), "ip_first_octet": ip_first_octet,
        "Last_Analysis_Date_year": lad_year, "Last_Analysis_Date_month": lad_month,
        "Last_Analysis_Date_day": lad_day,
    }])


def predict_ip(features: Dict[str, Any], model_name: str = "xgb") -> Optional[Dict[str, Any]]:
    artifact = load_ip_xgb_model() if model_name == "xgb" else load_ip_logreg_model()
    model = _extract_model(artifact)
    le = _extract_label_encoder(artifact)
    if model is None:
        return None
    try:
        df = build_ip_features(features)
        prediction = model.predict(df)[0]
        if le is not None:
            prediction = le.inverse_transform([prediction])[0]
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(df)[0]
            classes = getattr(model, "classes_", None)
            return _normalize_prediction(
                model_name=f"ip_{model_name}",
                prediction=prediction,
                probabilities=list(proba),
                classes=list(classes) if classes is not None else None,
            )
        return _normalize_prediction(model_name=f"ip_{model_name}", prediction=prediction)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# OTX (MiniLM + LogisticRegression OvR)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_sentence_transformer():
    try:
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer("all-MiniLM-L6-v2")
    except ImportError:
        logger.warning("sentence-transformers not installed; OTX model unavailable")
        return None


@lru_cache(maxsize=1)
def load_otx_minilm_model():
    return load_joblib_artifact("otx_minilm_logreg.joblib")


@lru_cache(maxsize=1)
def load_otx_label_encoder():
    return load_joblib_artifact("otx_label_encoder.joblib")


def predict_otx_attackids(text: str) -> Optional[Dict[str, Any]]:
    artifact = load_otx_minilm_model()
    if artifact is None:
        return None
    model = _extract_model(artifact)
    mlb = artifact.get("label_encoder") if isinstance(artifact, dict) else None
    if model is None:
        return None
    try:
        text = (text or "").strip()
        if not text:
            return None

        st = _load_sentence_transformer()
        if st is None:
            return None

        # Encode text via MiniLM, then run through LogReg OvR
        emb = st.encode([text], show_progress_bar=False)
        pred_binary = model.predict(emb)[0]
        proba = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(emb)[0]

        labels: list[str] = []
        if mlb is not None:
            labels = mlb.inverse_transform(np.array([pred_binary]))[0]
        else:
            labels = [str(pred_binary)]

        confidence = None
        if proba is not None and len(labels) > 0 and mlb is not None:
            class_indices = []
            for lbl in labels:
                if lbl in mlb.classes_:
                    class_indices.append(np.where(mlb.classes_ == lbl)[0][0])
            if class_indices:
                confidence = float(np.mean([proba[i] for i in class_indices]))
            else:
                confidence = float(np.max(proba))
        elif proba is not None:
            confidence = float(np.max(proba))

        return {
            "model": "otx_minilm_logreg",
            "label": ", ".join(labels) if labels else None,
            "confidence": confidence,
        }
    except Exception as e:
        logger.warning(f"OTX prediction failed: {e}")
        return None


# ---------------------------------------------------------------------------
# SHAP Explainers
# ---------------------------------------------------------------------------

def _shap_explain(artifact, df, model_name: str, feature_names: list[str]) -> list[dict]:
    try:
        import shap
        import sklearn.pipeline
    except ImportError:
        return []

    try:
        model = _extract_model(artifact)
        if model is None:
            return []

        shap_vals = None
        used_feature_names = feature_names

        try:
            # If model is a Pipeline with ColumnTransformer, transform data first
            if isinstance(model, sklearn.pipeline.Pipeline) and len(model.steps) >= 2:
                prep = model.steps[0][1]
                est_step = model.steps[-1][1]
                # Get the raw estimator from CalibratedClassifierCV if present
                raw_est = est_step
                if hasattr(raw_est, "calibrated_classifiers_") and raw_est.calibrated_classifiers_:
                    raw_est = raw_est.calibrated_classifiers_[0].estimator
                # Transform data through preprocessing
                X_t = prep.transform(df)
                # Get transformed feature names
                if hasattr(prep, "get_feature_names_out"):
                    used_feature_names = list(prep.get_feature_names_out())
                else:
                    used_feature_names = [f"f{i}" for i in range(X_t.shape[1])]

                if model_name.startswith("ip_xgb"):
                    explainer = shap.TreeExplainer(raw_est)
                    shap_vals = explainer.shap_values(X_t)
                elif model_name.startswith("ip_logreg") or "logreg" in model_name:
                    explainer = shap.LinearExplainer(raw_est, X_t)
                    shap_vals = explainer.shap_values(X_t)
            else:
                # Non-pipeline model: drop string columns before SHAP
                numeric_df = df.select_dtypes(include=["number"]).copy()
                if numeric_df.empty or numeric_df.shape[1] == 0:
                    return []
                used_feature_names = list(numeric_df.columns)

                if hasattr(model, "calibrated_classifiers_") and model.calibrated_classifiers_:
                    model = model.calibrated_classifiers_[0].estimator
                if model_name.startswith("ip_xgb"):
                    explainer = shap.TreeExplainer(model)
                    shap_vals = explainer.shap_values(numeric_df)
                elif model_name.startswith("ip_logreg") or "logreg" in model_name:
                    explainer = shap.LinearExplainer(model, numeric_df)
                    shap_vals = explainer.shap_values(numeric_df)
                else:
                    return []
        except Exception as te:
            logger.warning(f"TreeExplainer failed for {model_name}: {te}")

        if shap_vals is None:
            return []

        # SHAP output: for multi-class, shap_vals is list of arrays, one per class.
        if isinstance(shap_vals, list):
            shap_vals = shap_vals[1] if len(shap_vals) > 1 else shap_vals[0]

        # Flatten to 1D:
        #   (1, n_features)       -> (n_features,)
        #   (1, n_features, n_cls) -> (n_features,)  (extract predicted class)
        if isinstance(shap_vals, np.ndarray):
            if shap_vals.ndim == 3:
                shap_vals = shap_vals[0, :, 1] if shap_vals.shape[2] == 2 else shap_vals[0, :, :].mean(axis=1)
            while shap_vals.ndim > 1:
                shap_vals = shap_vals[0]

        impacts = [float(v) for v in shap_vals]
        paired = list(zip(used_feature_names, impacts))
        paired.sort(key=lambda x: abs(x[1]), reverse=True)

        result = []
        for fname, imp in paired[:10]:
            result.append({
                "feature": fname,
                "value": None,
                "impact": round(imp, 4),
            })
        return result
    except Exception as exc:
        logger.warning(f"SHAP explanation failed for {model_name}: {exc}")
        return []


def shap_explain_ip(features: Dict[str, Any], model_name: str = "xgb") -> list[dict]:
    artifact = load_ip_xgb_model() if model_name == "xgb" else load_ip_logreg_model()
    if artifact is None:
        return []
    df = build_ip_features(features)
    return _shap_explain(artifact, df, f"ip_{model_name}", list(df.columns))


def shap_explain_domain(features: Dict[str, Any]) -> list[dict]:
    artifact = load_domain_model()
    if artifact is None:
        return []
    df = build_domain_features(features)
    return _shap_explain(artifact, df, "domain_model", list(df.columns))


def _load_version_map() -> Dict[str, str]:
    """Load model version map from models/version.json (single source of truth)."""
    version_file = get_settings().models_path / "version.json"
    if version_file.is_file():
        try:
            return json.loads(version_file.read_text())
        except Exception:
            logger.warning("Failed to parse models/version.json")
    return {}


def get_model_status() -> Dict[str, Dict[str, Any]]:
    from .nmap_scoring import nmap_model_exists

    version_map = _load_version_map()

    def _info(name, loader_fn, samples=None, f1=None, trained_at=None):
        loaded = loader_fn() is not None
        info: Dict[str, Any] = {"loaded": loaded}
        if loaded and samples:
            info["samples"] = samples
        if loaded and f1:
            info["f1_score"] = f1
        if loaded and trained_at:
            info["trained_at"] = trained_at
        # Add model_version from version.json if available
        if name in version_map:
            info["model_version"] = version_map[name]
        return info

    nmap_loaded = nmap_model_exists()
    return {
        "cve_tfidf_logreg": _info("cve_tfidf_logreg", load_cve_model, samples=1585, f1=0.49, trained_at="2026-05-28"),
        "domain_model": _info("domain_model", load_domain_model, samples=162, f1=0.92, trained_at="2026-05-28"),
        "ip_xgb_model": _info("ip_xgb_model", load_ip_xgb_model, samples=200, f1=1.0, trained_at="2026-05-28"),
        "ip_logreg_model": _info("ip_logreg_model", load_ip_logreg_model, samples=200, trained_at="2026-05-28"),
        "nmap_model": {"loaded": nmap_loaded},
        "otx_minilm_logreg": _info("otx_minilm_logreg", load_otx_minilm_model, samples=2352, f1=0.49, trained_at="2026-05-28"),
        "otx_label_encoder": {"loaded": load_otx_label_encoder() is not None},
    }


# ---------------------------------------------------------------------------
# Enrichment helpers used by scan/details
# ---------------------------------------------------------------------------
def enrich_cve(row: Any) -> Optional[Dict[str, Any]]:
    text_parts = [clean_text(getattr(row, attr, None)) for attr in ("vulnerability_name", "short_description", "required_action")]
    text = " ".join(part for part in text_parts if part)
    return predict_cve(text)


def enrich_domain(row: Any) -> Optional[Dict[str, Any]]:
    # Build a complete feature dict for build_domain_features().
    # The function computes derived features (entropy, digit_ratio, etc.) from the domain string.
    # We provide DB-enriched values for votes, reputation, registrar, etc.
    features: Dict[str, Any] = {}

    # Domain string (primary input for derived feature computation)
    domain_val = getattr(row, "domain", None)
    if domain_val:
        features["domain"] = str(domain_val)

    # Boolean fields stored as strings in DB ("True"/"False") — convert back
    has_numbers = getattr(row, "has_numbers", None)
    if has_numbers is not None:
        features["has_numbers"] = str(has_numbers)
    has_hyphen = getattr(row, "has_hyphen", None)
    if has_hyphen is not None:
        features["has_hyphen"] = str(has_hyphen)

    # Numeric enrichment fields
    for attr in (
        "domain_length",
        "reputation",
        "malicious_votes",
        "suspicious_votes",
        "harmless_votes",
        "undetected_votes",
        "total_engines",
        "popularity_rank",
        "domain_age_days",
        "whois_field_count",
    ):
        value = getattr(row, attr, None)
        if value is not None:
            features[attr] = value

    # String enrichment fields
    for attr in (
        "tld",
        "registrar",
        "categories",
        "data_source",
        "threat_severity",
        "whois_summary",
    ):
        value = getattr(row, attr, None)
        if value is not None:
            features[attr] = str(value)

    # Date fields — pass as strings; build_domain_features handles missing dates
    for attr in ("creation_date", "last_update_date", "last_analysis_date"):
        value = getattr(row, attr, None)
        if value is not None:
            features[attr] = str(value)
        # Also extract year/month/day components for the features that need them
        if attr == "creation_date" and value is not None:
            from datetime import date, datetime
            if isinstance(value, (date, datetime)):
                features["creation_date_year"] = value.year
                features["creation_date_month"] = value.month
                features["creation_date_day"] = value.day

    # Nameservers (may not exist on the model, but build_domain_features checks for it)
    nameservers = getattr(row, "nameservers", None)
    if nameservers is not None:
        features["nameservers"] = nameservers

    return predict_domain(features)


def enrich_ip(row: Any) -> Optional[Dict[str, Any]]:
    features: Dict[str, Any] = {}
    for attr in (
        "malicious_votes",
        "suspicious_votes",
        "harmless_votes",
        "undetected_votes",
        "total_reports",
        "reputation_score",
        "tor_node",
        "times_submitted",
        "threat_severity",
        "country",
        "continent",
        "asn",
        "owner",
        "network",
        "threat_label",
        "threat_category",
        "regional_registry",
    ):
        value = getattr(row, attr, None)
        if value is not None:
            features[attr] = value
    return predict_ip(features, model_name="xgb")


def enrich_otx(row: Any) -> Optional[Dict[str, Any]]:
    text_parts = []
    for attr in ("title", "description", "tags"):
        value = clean_text(getattr(row, attr, None))
        if value:
            text_parts.append(value)
    text = " ".join(text_parts)
    return {
        "attackids": predict_otx_attackids(text),
    }
