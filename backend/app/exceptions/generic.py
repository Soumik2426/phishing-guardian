from fastapi import status

from app.exceptions.base import AppException


class BadRequestException(AppException):
    default_message = "Bad request."
    default_status_code = status.HTTP_400_BAD_REQUEST


class ValidationException(AppException):
    default_message = "Validation failed."
    default_status_code = status.HTTP_422_UNPROCESSABLE_ENTITY


class ForbiddenOperationException(AppException):
    default_message = "This operation is not allowed."
    default_status_code = status.HTTP_403_FORBIDDEN


class ServiceUnavailableException(AppException):
    default_message = "Service is temporarily unavailable."
    default_status_code = status.HTTP_503_SERVICE_UNAVAILABLE


class ExternalServiceException(AppException):
    default_message = "External service request failed."
    default_status_code = status.HTTP_502_BAD_GATEWAY


class ModelNotLoadedException(AppException):
    default_message = "Model has not been loaded."
    default_status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
