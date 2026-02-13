"""Assessment model — periodic security assessments."""

from __future__ import annotations

from sqlalchemy import Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base


class Assessment(Base):
    """A security assessment run for an organisation."""

    __tablename__ = "assessments"

    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    assessment_type: Mapped[str] = mapped_column(String(50), nullable=False, default="full")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    overall_score: Mapped[float] = mapped_column(Float, default=0.0)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<Assessment {self.id[:8]} org={self.org_id[:8]}>"
