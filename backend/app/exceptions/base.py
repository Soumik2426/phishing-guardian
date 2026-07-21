from collections.abc import Iterable

from fastapi import status


class AppException(Exception):
    default_message = "Application error."
    default_status_code = status.HTTP_400_BAD_REQUEST

    def __init__(
        self,
        message: str | None = None,
        status_code: int | None = None,
        errors: str | Iterable[str] | None = None,
    ) -> None:
        resolved_message = message or self.default_message
        resolved_status_code = status_code or self.default_status_code

        self.message = resolved_message
        self.status_code = resolved_status_code
        self.errors = self._normalize_errors(errors, resolved_message)

        super().__init__(resolved_message)

    @staticmethod
    def _normalize_errors(
        errors: str | Iterable[str] | None,
        fallback_message: str,
    ) -> list[str]:
        if errors is None:
            return [fallback_message]

        if isinstance(errors, str):
            normalized = [errors]
        else:
            normalized = [
                str(error).strip()
                for error in errors
                if str(error).strip()
            ]

        return normalized or [fallback_message]
