from fastapi import Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.repositories.user_repository import UserRepository
from app.security.jwt_service import JwtService
from app.services.auth_service import AuthService


def get_auth_service(
    db: Session = Depends(get_db),
) -> AuthService:
    return AuthService(
        db=db,
        user_repository=UserRepository(),
        jwt_service=JwtService(),
    )