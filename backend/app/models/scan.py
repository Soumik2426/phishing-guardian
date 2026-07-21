from uuid import UUID

from sqlalchemy import Enum, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.database import BaseEntity
from app.enums import ScanVerdict


class Scan(BaseEntity):
    __tablename__ = "scans"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    verdict: Mapped[ScanVerdict] = mapped_column(
        Enum(ScanVerdict, name="scan_verdict"),
        nullable=False,
    )

    # Relationship with User
    user = relationship(
        "User",
        back_populates="scans",
    )

    # Relationship with ScanMetric
    metrics = relationship(
        "ScanMetric",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("idx_scans_user_id", "user_id"),
        Index("idx_scans_verdict", "verdict"),
    )