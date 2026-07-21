from sqlalchemy import Boolean, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import BaseEntity


class MetricType(BaseEntity):
    __tablename__ = "metric_types"

    code: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        unique=True,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    display_order: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    scan_metrics = relationship(
        "ScanMetric",
        back_populates="metric_type",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("idx_metric_type_code", "code"),
    )