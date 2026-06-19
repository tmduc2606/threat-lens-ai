from __future__ import annotations

from datetime import date, datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "ThreatLensAI API"


class SearchResult(BaseModel):
    source_type: str
    source_key: str
    title: str
    summary: Optional[str] = None
    severity: str = "Unknown"
    score: float = Field(default=0.0, ge=0.0, le=10.0)
    tags: List[str] = Field(default_factory=list)
    created_at: Optional[datetime | date] = None
    updated_at: Optional[datetime | date] = None


class DetailResponse(SearchResult):
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timeline: Dict[str, Any] = Field(default_factory=dict)
    raw: Dict[str, Any] = Field(default_factory=dict)
    ml_prediction: Dict[str, Any] = Field(default_factory=dict)
    shap_values: List[Dict[str, Any]] = Field(default_factory=list)


class SearchResponse(BaseModel):
    query: str
    count: int
    results: List[SearchResult] = Field(default_factory=list)


class RecentResponse(BaseModel):
    items: List[SearchResult] = Field(default_factory=list)


class FeedbackPayload(BaseModel):
    query: str
    action: str
    source_type: Optional[str] = None


class FeedbackResponse(BaseModel):
    accepted: bool = True
    message: str = "Feedback received"


class DetectionSummary(BaseModel):
    malicious: int = 0
    suspicious: int = 0
    clean: int = 0
    unknown: int = 0
    total: int = 0


class ScanRequest(BaseModel):
    query: str
    limit: int = Field(default=10, ge=1, le=50)


class ScanResponse(BaseModel):
    query: str
    input_type: str
    verdict: str
    confidence: str
    score: float
    summary: str

    title: str = ""
    source_type: Optional[str] = None
    source_key: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    detections: DetectionSummary = Field(default_factory=DetectionSummary)
    source_breakdown: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, str]] = Field(default_factory=list)

    engine_count: int = 0
    signals: List[str] = Field(default_factory=list)
    primary: Optional[DetailResponse] = None
    results: List[SearchResult] = Field(default_factory=list)

    latest_scan: Dict[str, Any] = Field(default_factory=dict)
    model_status: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    calibrated_confidence: Optional[float] = None
    confidence_interval: Optional[Dict[str, float]] = None
    risk_band: Optional[str] = None
    score_breakdown: Optional[Dict[str, float]] = None


class DashboardResponse(BaseModel):
    summary: Dict[str, int]
    recent: List[SearchResult] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    detail: str