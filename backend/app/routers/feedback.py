from fastapi import APIRouter

from ..schemas.common import FeedbackPayload, FeedbackResponse

router = APIRouter(tags=["feedback"])


@router.post("/feedback", response_model=FeedbackResponse)
def feedback(payload: FeedbackPayload):
    return FeedbackResponse(message=f"Feedback received for {payload.action}")