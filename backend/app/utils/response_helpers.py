from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..schemas.common import DetailResponse, SearchResult


def make_result(
    *,
    source_type: str,
    source_key: str,
    title: str,
    summary: Optional[str],
    severity: str,
    score: float,
    tags: List[str],
    created_at=None,
    updated_at=None,
) -> SearchResult:
    return SearchResult(
        source_type=source_type,
        source_key=source_key,
        title=title,
        summary=summary,
        severity=severity,
        score=round(float(score), 2),
        tags=list(dict.fromkeys([tag for tag in tags if tag])),
        created_at=created_at,
        updated_at=updated_at,
    )


def make_detail(
    result: SearchResult,
    metadata: Dict[str, Any],
    evidence: Dict[str, Any],
    timeline: Dict[str, Any],
    raw: Dict[str, Any],
    ml_prediction: Optional[Dict[str, Any]] = None,
    shap_values: Optional[List[Dict[str, Any]]] = None,
) -> DetailResponse:
    return DetailResponse(
        **result.model_dump(),
        metadata=metadata,
        evidence=evidence,
        timeline=timeline,
        raw=raw,
        ml_prediction=ml_prediction or {},
        shap_values=shap_values or [],
    )