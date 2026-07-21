from uuid import UUID

from sqlalchemy import ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.database import BaseEntity


class ScanMetric(BaseEntity):
    __tablename__ = "scan_metrics"

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )

    metric_type_id: Mapped[UUID] = mapped_column(
        ForeignKey("metric_types.id", ondelete="CASCADE"),
        nullable=False,
    )

    score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    raw_value: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    scan = relationship(
        "Scan",
        back_populates="metrics",
    )

    metric_type = relationship(
        "MetricType",
        back_populates="scan_metrics",
    )

    __table_args__ = (
        Index("idx_scan_metric_scan", "scan_id"),
        Index("idx_scan_metric_metric_type", "metric_type_id"),
    )