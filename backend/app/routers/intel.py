from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas.common import DetailResponse
from ..services.intel_service import get_intel_detail

router = APIRouter(tags=["intel"])


@router.get("/intel/{source_type}/{value}", response_model=DetailResponse)
def intel_detail(source_type: str, value: str, db: Session = Depends(get_db)):
    detail = get_intel_detail(db, source_type, value)
    if detail is None:
        raise HTTPException(status_code=404, detail="Record not found")
    return detail