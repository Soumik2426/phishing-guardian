from fastapi import status

from app.exceptions.base import AppException


class AuthenticationException(AppException):
    default_message = "Authentication failed."
    default_status_code = status.HTTP_401_UNAUTHORIZED


class AuthorizationException(AppException):
    default_message = "Access denied."
    default_status_code = status.HTTP_403_FORBIDDEN


class InvalidCredentialsException(AuthenticationException):
    default_message = "Invalid email or password."


class EmailAlreadyRegisteredException(AppException):
    default_message = "Email is already registered."
    default_status_code = status.HTTP_409_CONFLICT


class EmailNotVerifiedException(AuthorizationException):
    default_message = "Please verify your email before logging in."


class AccountDisabledException(AuthorizationException):
    default_message = "Your account has been disabled."


class InvalidTokenException(AuthenticationException):
    default_message = "Invalid token."


class ExpiredTokenException(AuthenticationException):
    default_message = "Token has expired."


class RefreshTokenException(AuthenticationException):
    default_message = "Refresh token is invalid or expired."
