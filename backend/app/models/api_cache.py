from __future__ import annotations

from sqlalchemy import Column, String, Text, DateTime

from .base import Base


class APICache(Base):
    __tablename__ = "api_cache"

    cache_key = Column(String, primary_key=True)
    source = Column(String, nullable=False, index=True)
    response_json = Column(Text, nullable=False)
    queried_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
