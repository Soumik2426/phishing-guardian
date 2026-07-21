from fastapi import APIRouter, Depends, status
from app.schemas.user import UserResponse
from app.core.response_builder import success_response
from app.dependencies import get_auth_service
from app.schemas.auth import LoginRequest, RegisterRequest
from app.services.auth_service import AuthService

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
)
def register(
    request: RegisterRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    user = auth_service.register(request)

    return success_response(
        message="User registered successfully.",
        data=UserResponse.model_validate(user),
    )


@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
)
def login(
    request: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    tokens = auth_service.login(request)

    return success_response(
        message="Login successful.",
        data=tokens,
    )