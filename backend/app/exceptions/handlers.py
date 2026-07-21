from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.logger import logger
from app.exceptions import AppException
from app.schemas.response import ApiResponse


FIELD_NAMES = {
    "first_name": "First Name",
    "last_name": "Last Name",
    "email": "Email",
    "password": "Password",
}


def _humanize_field_name(field_name: str | int | None) -> str:
    if field_name is None:
        return "Field"

    return FIELD_NAMES.get(
        str(field_name),
        str(field_name).replace("_", " ").title(),
    )


def _format_generic_validation_message(message: str) -> str:
    normalized = message.removeprefix("Value error, ").strip()

    if not normalized:
        return "Invalid input."

    if normalized.endswith("."):
        return normalized

    return f"{normalized[:1].upper()}{normalized[1:]}."


def _format_validation_error(
    field_name: str,
    error: dict,
) -> list[str]:
    message = str(error.get("msg", "")).removeprefix("Value error, ").strip()
    error_type = str(error.get("type", ""))
    context = error.get("ctx") or {}

    if message == "Field required":
        return [f"{field_name} is required."]

    if error_type == "missing":
        return [f"{field_name} is required."]

    if "valid email address" in message.lower():
        return ["Please enter a valid email address."]

    min_length = context.get("min_length")
    if min_length is not None:
        return [f"{field_name} is required."]

    max_length = context.get("max_length")
    if max_length is not None:
        return [f"{field_name} is required"]

    if not message:
        return ["Invalid input."]

    lines = [line.strip() for line in message.splitlines() if line.strip()]
    return [_format_generic_validation_message(line) for line in lines]


def _extract_validation_errors(exc: RequestValidationError) -> list[str]:
    errors: list[str] = []
    seen_messages: set[str] = set()
    missing_fields: set[tuple[str, ...]] = set()

    for error in exc.errors():
        raw_loc = error.get("loc") or ()
        loc = tuple(str(item) for item in raw_loc if item not in {"body", "query", "path"})
        field_key = loc or ("non_field",)
        field_name = _humanize_field_name(loc[-1] if loc else None)

        if field_key in missing_fields:
            continue

        formatted_messages = _format_validation_error(field_name, error)

        if any(message == f"{field_name} is required." for message in formatted_messages):
            missing_fields.add(field_key)

        for message in formatted_messages:
            if message not in seen_messages:
                seen_messages.add(message)
                errors.append(message)

    return errors or ["Validation failed."]


def _build_error_response(
    *,
    message: str,
    errors: list[str],
    status_code: int,
) -> JSONResponse:
    response = ApiResponse(
        success=False,
        message=message,
        data=None,
        errors=errors,
    )

    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
    )


def register_exception_handlers(app: FastAPI):
    """
    Register all global exception handlers.
    """

    @app.exception_handler(AppException)
    async def app_exception_handler(
        request: Request,
        exc: AppException,
    ):
        logger.warning(
            f"{request.method} {request.url} -> {exc.message}"
        )

        return _build_error_response(
            message=exc.message,
            errors=exc.errors,
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ):
        logger.warning(
            f"Validation failed for {request.method} {request.url}"
        )

        errors = _extract_validation_errors(exc)

        return _build_error_response(
            message="Validation failed.",
            errors=errors,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request,
        exc: HTTPException,
    ):
        logger.warning(
            f"{request.method} {request.url} -> {exc.detail}"
        )

        message = (
            exc.detail
            if isinstance(exc.detail, str)
            else "Request failed."
        )

        return _build_error_response(
            message=message,
            errors=[message],
            status_code=exc.status_code,
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(
        request: Request,
        exc: Exception,
    ):
        logger.exception(
            f"Unhandled exception while processing "
            f"{request.method} {request.url}"
        )

        return _build_error_response(
            message="Internal Server Error",
            errors=[
                "An unexpected error occurred. Please try again later."
            ],
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
