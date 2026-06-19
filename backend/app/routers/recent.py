from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas.common import RecentResponse
from ..services.recent_service import get_recent_items

router = APIRouter(tags=["recent"])


@router.get("/recent", response_model=RecentResponse)
def recent(limit: int = Query(default=20, ge=1, le=100), db: Session = Depends(get_db)):
    return RecentResponse(items=get_recent_items(db, limit=limit))