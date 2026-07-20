from fastapi import APIRouter

router = APIRouter(
    tags=["Health"]
)


@router.get("/")
def root():
    return {
        "message": "Phishing Guardian API is running"
    }


@router.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": True,
        "version": "2.0.0"
    }