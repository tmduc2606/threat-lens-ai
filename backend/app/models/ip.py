from sqlalchemy import Boolean, Column, Date, Integer, Numeric, String, Text, Float, DateTime

from .base import Base


class MaliciousIP(Base):
    __tablename__ = "malicious_ips"

    ip = Column(String, primary_key=True, index=True)
    country = Column(String, index=True)
    continent = Column(String, index=True)
    asn = Column(String, index=True)
    owner = Column(String, index=True)
    network = Column(String)
    malicious_votes = Column(Integer, default=0, nullable=False)
    suspicious_votes = Column(Integer, default=0, nullable=False)
    harmless_votes = Column(Integer, default=0, nullable=False)
    undetected_votes = Column(Integer, default=0, nullable=False)
    total_reports = Column(Integer, default=0, nullable=False)
    reputation_score = Column(Float)
    threat_label = Column(String, index=True)
    threat_category = Column(String, index=True)
    regional_registry = Column(String, index=True)
    whois_summary = Column(Text)
    tor_node = Column(Boolean, default=False, nullable=False)
    times_submitted = Column(Integer, default=0, nullable=False)
    last_analysis_date = Column(Date, index=True)
    threat_severity = Column(String, index=True)
    data_source = Column(String, index=True, default="csv_import")
    enriched_at = Column(DateTime, index=True)
    enrichment_breakdown = Column(Text)