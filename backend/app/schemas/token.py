from pydantic import BaseModel, ConfigDict


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "<JWT_ACCESS_TOKEN>",
                "refresh_token": "<JWT_REFRESH_TOKEN>",
                "token_type": "Bearer",
            }
        }
    )