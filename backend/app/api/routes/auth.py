from fastapi import APIRouter, Depends, status
from app.schemas.user import UserResponse
from app.core.response_builder import success_response
from app.dependencies import get_auth_service
from app.schemas.auth import LoginRequest, RegisterRequest
from app.services.auth_service import AuthService
from app.services.email_service import EmailService
from app.services.otp_service import OTPService
from app.services.redis_service import RedisService
from app.schemas.auth import VerifyEmailRequest

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
)
async def register(
    request: RegisterRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    user = await auth_service.register(request)

    return success_response(
        message="Registration successful. Please verify your email.",
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

@router.post(
    "/verify-email",
    status_code=status.HTTP_200_OK,
)
async def verify_email(
    request: VerifyEmailRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    await auth_service.verify_email(request)

    return success_response(
        message="Email verified successfully.",
    )

@router.get("/test-email")
async def test_email():
    service = EmailService()

    await service.send_email(
        recipient="itssoumik02@gmail.com",
        subject="Email Test",
        template_name="otp_email.html",
        context={
            "first_name": "Soumik",
            "otp": "123456",
        },
    )

    return {"message": "Email sent successfully"}

@router.get("/test-redis")
async def test_redis():
    redis_service = RedisService()

    await redis_service.set(
        key="test",
        value="Redis is working!",
        ttl=60,
    )

    value = await redis_service.get("test")

    return {
        "message": value
    }

@router.get("/test-otp")
async def test_otp():

    otp_service = OTPService()

    otp = await otp_service.create_otp(
        "soumik@gmail.com"
    )

    return {
        "otp": otp
    }