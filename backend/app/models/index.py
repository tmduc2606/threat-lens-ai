from sqlalchemy import Column, DateTime, Numeric, String, Text, Float, Integer

from .base import Base


class IntelIndex(Base):
    __tablename__ = "intel_index"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_type = Column(String, nullable=False, index=True)  # OTX / CVE / DOMAIN / IP
    source_key = Column(String, nullable=False, index=True)
    title = Column(Text)
    summary = Column(Text)
    severity = Column(String, index=True)
    score = Column(Float, index=True)
    tags = Column(Text)
    created_at = Column(DateTime, index=True)
    updated_at = Column(DateTime, index=True)