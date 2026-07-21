from pydantic import BaseModel, ConfigDict, EmailStr, Field
from pydantic import field_validator
from app.schemas.validators import validate_password

class RegisterRequest(BaseModel):
    first_name: str = Field(
        min_length=2
    )

    @field_validator("first_name")
    @classmethod
    def validate_first_name(cls, value: str):

        value = value.strip()
        if not value:
            raise ValueError("First Name is required.")

        if len(value) < 2:
            raise ValueError("First Name must be at least 2 characters.")
        return value

    last_name: str = Field(
        min_length=2
    )

    @field_validator("last_name")
    @classmethod
    def validate_last_name(cls, value: str):

        value = value.strip()

        if not value:
            raise ValueError("Last Name is required.")

        if len(value) < 2:
            raise ValueError("Last Name must be at least 2 characters.")

        return value

    email: EmailStr = Field(
        ...,
        description="User's email address",
    )

    @field_validator("email", mode="before")
    @classmethod
    def validate_email(cls, value):
        if value is None:
            raise ValueError("Email is required.")

        if isinstance(value, str):
            value = value.strip()

            if value == "":
                raise ValueError("Email is required.")

        return value

    password: str = Field(
        ...,
        max_length=128,
        description="User password",
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Password is required.")

        errors = validate_password(value)

        if errors:
            raise ValueError("\n".join(errors))

        return value

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "first_name": "Soumik",
                "last_name": "Maity",
                "email": "soumik@example.com",
                "password": "Password@123",
            }
        }
    )


class LoginRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        description="Registered email address",
    )

    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Account password",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "soumik@example.com",
                "password": "Password@123",
            }
        }
    )


class VerifyEmailRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        description="Registered email address",
    )

    otp: str = Field(
        ...,
        min_length=6,
        max_length=6,
        description="6-digit OTP",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "soumik@example.com",
                "otp": "123456",
            }
        }
    )


class ResendOtpRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        description="Registered email address",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "soumik@example.com",
            }
        }
    )