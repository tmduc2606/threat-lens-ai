from sqlalchemy import Boolean, Column, Date, Integer, Numeric, String, Text, Float, DateTime

from .base import Base


class MaliciousDomain(Base):
    __tablename__ = "malicious_domains"

    domain = Column(String, primary_key=True, index=True)
    tld = Column(String, index=True)
    domain_length = Column(Integer)
    has_numbers = Column(Boolean, default=False, nullable=False)
    has_hyphen = Column(Boolean, default=False, nullable=False)
    registrar = Column(String, index=True)
    creation_date = Column(Date, index=True)
    last_update_date = Column(Date, index=True)
    reputation = Column(Float)
    malicious_votes = Column(Integer, default=0, nullable=False)
    suspicious_votes = Column(Integer, default=0, nullable=False)
    harmless_votes = Column(Integer, default=0, nullable=False)
    undetected_votes = Column(Integer, default=0, nullable=False)
    total_engines = Column(Integer, default=0, nullable=False)
    threat_severity = Column(String, index=True)
    categories = Column(Text)
    popularity_rank = Column(Integer)
    last_analysis_date = Column(Date, index=True)
    whois_summary = Column(Text)
    data_source = Column(String, index=True)
    enriched_at = Column(DateTime, index=True)
    enrichment_breakdown = Column(Text)