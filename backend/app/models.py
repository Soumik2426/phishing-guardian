from pydantic import BaseModel, Field

class URLCheckRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="URL to check for phishing"
    )

class URLCheckResponse(BaseModel):
    url: str
    is_safe: bool
    threat_level: str
    confidence_score: float
    summary: str
