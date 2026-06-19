from sqlalchemy import Column, String, Integer, DateTime, Boolean, Text
from .base import Base


class NmapResult(Base):
    __tablename__ = "nmap_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String, index=True, nullable=False)
    scan_date = Column(DateTime, nullable=False)
    hostname = Column(String, default="")
    open_ports = Column(Text, default="[]")
    os_guess = Column(String, default="")
    cpe_entries = Column(Text, default="[]")
    raw_xml = Column(Text, default="")
    is_local_ip = Column(Boolean, default=False)
