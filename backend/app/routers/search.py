from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas.common import SearchResponse
from ..services.search_service import search_intelligence

router = APIRouter(tags=["search"])


@router.get("/search", response_model=SearchResponse)
def search(q: str = Query(..., min_length=1), db: Session = Depends(get_db)):
    return search_intelligence(db, q)


@router.post("/query", response_model=SearchResponse)
def query(payload: dict, db: Session = Depends(get_db)):
    return search_intelligence(db, payload.get("q", ""))