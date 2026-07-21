from typing import Any

from app.schemas.response import ApiResponse


def success_response(
    message: str,
    data: Any = None,
) -> ApiResponse:
    return ApiResponse(
        success=True,
        message=message,
        data=data,
    )


def error_response(
    message: str,
    errors: list[str] | None = None,
) -> ApiResponse:
    return ApiResponse(
        success=False,
        message=message,
        errors=errors or [],
    )