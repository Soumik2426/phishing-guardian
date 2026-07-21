from sqlalchemy.orm import Session

from app.exceptions.custom_exceptions import AuthenticationException, DuplicateException
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.auth import LoginRequest, RegisterRequest
from app.schemas.token import TokenResponse
from app.security.jwt_service import JwtService
from app.security.password import hash_password, verify_password


class AuthService:

    def __init__(
        self,
        db: Session,
        user_repository: UserRepository,
        jwt_service: JwtService,
    ):
        self.db = db
        self.user_repository = user_repository
        self.jwt_service = jwt_service

    def register(
        self,
        request: RegisterRequest,
    ) -> User:

        if self.user_repository.exists_by_email(
            self.db,
            request.email,
        ):
            raise DuplicateException(
                "Email is already registered."
            )

        user = User(
            first_name=request.first_name,
            last_name=request.last_name,
            email=request.email,
            password_hash=hash_password(
                request.password
            ),
        )

        return self.user_repository.create(
            self.db,
            user,
        )

    def login(
        self,
        request: LoginRequest,
    ) -> TokenResponse:

        user = self.user_repository.get_by_email(
            self.db,
            request.email,
        )

        if user is None:
            raise AuthenticationException(
                "Invalid email or password."
            )

        if not verify_password(
            request.password,
            user.password_hash,
        ):
            raise AuthenticationException(
                "Invalid email or password."
            )

        if not user.is_active:
            raise AuthenticationException(
                "Your account has been disabled."
            )

        if not user.is_verified:
            raise AuthenticationException(
                "Please verify your email."
            )

        self.user_repository.update_last_login(
            self.db,
            user,
        )

        access_token = self.jwt_service.create_access_token(
            user.id,
            user.role,
        )

        refresh_token = self.jwt_service.create_refresh_token(
            user.id,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
        )