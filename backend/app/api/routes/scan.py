from fastapi import APIRouter

from app.models import URLCheckRequest
from app.services.detector_service import analyze_url

router = APIRouter(
    prefix="/scan",
    tags=["URL Scanner"]
)


@router.post("/")
def check_url(request: URLCheckRequest):

    result = analyze_url(request.url)

    return {
        "url": request.url,
        "is_safe": result["is_safe"],
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "ml_probability": result["ml_probability"],
        "rule_score": result["rule_score"],
        "summary": result["summary"],
        "findings": result["findings"],
        "guidance": result["guidance"],
        "breakdown": result["breakdown"]
    }