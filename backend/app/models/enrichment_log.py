from __future__ import annotations

from sqlalchemy import Column, String, Text, DateTime, Integer, Boolean, func

from .base import Base


class EnrichmentLog(Base):
    __tablename__ = "enrichment_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String, nullable=False, index=True)
    indicator_value = Column(String, nullable=False, index=True)
    api_source = Column(String, nullable=False, index=True)
    success = Column(Boolean, default=True)
    error_message = Column(Text)
    enriched_at = Column(DateTime, default=func.now())
    latency_ms = Column(Integer)
