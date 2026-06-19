from __future__ import annotations

from sqlalchemy.orm import Session

from .search_service import recent_index


def get_recent_items(db: Session, limit: int = 20):
    return recent_index(db, limit=limit)