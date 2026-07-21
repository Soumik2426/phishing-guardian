from typing import Generic, Type, TypeVar
from uuid import UUID

from sqlalchemy.orm import Session

from app.database.base import Base

T = TypeVar("T", bound=Base)


class BaseRepository(Generic[T]):
    def __init__(self, model: Type[T]):
        self.model = model

    def create(self, db: Session, entity: T) -> T:
        db.add(entity)
        db.commit()
        db.refresh(entity)
        return entity

    def update(self, db: Session, entity: T) -> T:
        db.commit()
        db.refresh(entity)
        return entity

    def get_by_id(self, db: Session, entity_id: UUID) -> T | None:
        return db.get(self.model, entity_id)

    def get_all(self, db: Session) -> list[T]:
        return db.query(self.model).all()

    def delete(self, db: Session, entity: T) -> None:
        db.delete(entity)
        db.commit()