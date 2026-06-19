from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas.common import ScanRequest, ScanResponse
from ..services.scan_service import scan_intelligence

router = APIRouter(tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
async def scan(
    payload: ScanRequest,
    dry_run: bool = Query(False),
    db: Session = Depends(get_db),
):
    return await scan_intelligence(db, payload.query, limit=payload.limit, dry_run=dry_run)


@router.get("/scan", response_model=ScanResponse)
async def scan_query(
    q: str = Query(..., min_length=1),
    dry_run: bool = Query(False),
    db: Session = Depends(get_db),
):
    return await scan_intelligence(db, q, dry_run=dry_run)
