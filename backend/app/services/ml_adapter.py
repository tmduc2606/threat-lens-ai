from __future__ import annotations

import os
import sys as _sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import joblib

from ..config import get_settings

# Re-register notebook-scoped functions so pickled domain_model.joblib can deserialize
import __main__ as _main_mod
if not hasattr(_main_mod, '_select_domain_string'):
    def _select_domain_string(X):
        return X["domain_string"].values
    _main_mod._select_domain_string = _select_domain_string


def _candidate_paths(filename: str) -> list[Path]:
    settings = get_settings()
    candidates = []

    if settings.joblib_model_path:
        candidates.append(Path(settings.joblib_model_path))

    models_dir = settings.models_path
    candidates.append(models_dir / filename)

    candidates.append(Path.cwd() / "models" / filename)

    candidates.append(Path("/models") / filename)

    return candidates


def _load_from_candidates(filename: str) -> Optional[Any]:
    for path in _candidate_paths(filename):
        if not path.exists():
            continue
        try:
            return joblib.load(path)
        except Exception:
            continue
    return None


@lru_cache(maxsize=None)
def load_joblib_artifact(filename: str) -> Optional[Any]:
    return _load_from_candidates(filename)


def predict_from_artifact(filename: str, feature_vector: Any) -> Optional[float]:
    model = load_joblib_artifact(filename)
    if model is None:
        return None

    try:
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba([feature_vector])[0]
            if isinstance(proba, (list, tuple)) and len(proba) > 1:
                return float(proba[-1]) * 10.0
            return float(proba[0]) * 10.0

        if hasattr(model, "predict"):
            pred = model.predict([feature_vector])[0]
            try:
                return float(pred)
            except Exception:
                return None
    except Exception:
        return None

    return None


def model_exists(filename: str) -> bool:
    return load_joblib_artifact(filename) is not None