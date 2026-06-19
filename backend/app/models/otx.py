from sqlalchemy import Column, DateTime, Integer, String, Text

from .base import Base


class OTXPulse(Base):
    __tablename__ = "otx_pulses"

    pulse_id = Column(String, primary_key=True, index=True)
    title = Column(Text, nullable=False, index=True)
    description = Column(Text)
    author = Column(String, index=True)
    created_at = Column(DateTime, index=True)
    modified_at = Column(DateTime, index=True)
    tlp = Column(String, index=True)
    tags = Column(Text)
    malware_families = Column(Text)
    attack_ids = Column(Text)
    industries = Column(Text)
    countries = Column(Text)
    indicators_count = Column(Integer, default=0, nullable=False)
    subscribers = Column(Integer, default=0, nullable=False)