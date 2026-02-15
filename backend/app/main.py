from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.models import URLCheckRequest
from app.detector import predict_url


app = FastAPI(
    title="Phishing Guardian API",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "Phishing Guardian API is running"}


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model_loaded": True,
        "version": "2.0.0"
    }


@app.post("/check-url")
def check_url(request: URLCheckRequest):

    result = predict_url(request.url)

    return {
        "url": request.url,
        "is_safe": not result["is_phishing"],
        "risk_level": result["risk_level"],
        "confidence_score": result["confidence"],
        "warning": result["warning"],
        "reasons": result["reasons"],
        "guidance": result["guidance"]
    }
