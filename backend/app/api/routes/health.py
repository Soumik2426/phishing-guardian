from fastapi import APIRouter
from app.utils.response_builder import success_response

router = APIRouter(
    tags=["Health"]
)


@router.get("/")
def root():
    return success_response(
        message="Welcome to Phishing Guardian API",
        data={
            "version": "2.0.0"
        }
    )


@router.get("/health")
def health():
    return success_response(
        message="Application is healthy.",
        data={
            "status": "UP"
        }
    )