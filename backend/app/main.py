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
        "is_safe": result["is_safe"],
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "ml_probability": result["ml_probability"],
        "rule_score": result["rule_score"],
        "summary": result["summary"],
        "findings": result["findings"],
        "guidance": result["guidance"]
    }
