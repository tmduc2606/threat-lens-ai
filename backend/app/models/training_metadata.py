from __future__ import annotations

from sqlalchemy import Column, String, Text, DateTime, Integer, func

from .base import Base


class TrainingMetadata(Base):
    __tablename__ = "training_metadata"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String, nullable=False, index=True)
    total_records = Column(Integer, nullable=False)
    api_enriched_records = Column(Integer, nullable=False)
    exported_at = Column(DateTime, default=func.now())
    model_version = Column(String)
    notes = Column(Text)
