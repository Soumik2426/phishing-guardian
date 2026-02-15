from pydantic import BaseModel, Field

class URLCheckRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="URL to check for phishing"
    )

class URLCheckResponse(BaseModel):
    class URLCheckResponse(BaseModel):
        url: str
        is_safe: bool
        risk_level: str
        risk_score: float
        ml_probability: float
        rule_score: float
        summary: str
        findings: list
        guidance: str
