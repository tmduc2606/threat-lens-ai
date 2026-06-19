from sqlalchemy import Column, Date, String, Text, Float, DateTime

from .base import Base


class CVEVulnerability(Base):
    __tablename__ = "cve_vulnerabilities"

    cve_id = Column(String, primary_key=True, index=True)
    vendor_project = Column(String, index=True)
    product = Column(String, index=True)
    vulnerability_name = Column(Text)
    date_added = Column(Date, index=True)
    short_description = Column(Text)
    required_action = Column(Text)
    due_date = Column(Date, index=True)
    known_ransomware_campaign_use = Column(String, index=True)
    cwes = Column(Text)
    cvss_v3_score = Column(Float)
    cvss_v3_vector = Column(Text)
    enriched_at = Column(DateTime, index=True)
    enrichment_breakdown = Column(Text)