from fastapi import status

from app.exceptions.base import AppException


class ResourceNotFoundException(AppException):
    default_status_code = status.HTTP_404_NOT_FOUND

    def __init__(self, resource: str = "Resource"):
        super().__init__(
            message=f"{resource} not found.",
        )


class DuplicateResourceException(AppException):
    default_status_code = status.HTTP_409_CONFLICT

    def __init__(self, resource: str = "Resource"):
        super().__init__(
            message=f"{resource} already exists.",
        )


class ConflictException(AppException):
    default_message = "Resource conflict."
    default_status_code = status.HTTP_409_CONFLICT


class DuplicateException(DuplicateResourceException):
    pass
