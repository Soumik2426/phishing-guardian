from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr

from app.enums.user_role import UserRole


class UserResponse(BaseModel):
    id: UUID
    first_name: str
    last_name: str
    email: EmailStr
    role: UserRole
    is_verified: bool
    is_active: bool

    model_config = ConfigDict(from_attributes=True)