"""Organisation model — core entity for Digital Sentinel."""

from __future__ import annotations

from sqlalchemy import Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base


class Organisation(Base):
    """An organisation being assessed by Digital Sentinel."""

    __tablename__ = "organisations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    industry_sector: Mapped[str] = mapped_column(String(100), nullable=False, default="general")
    domain: Mapped[str] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Aggregated scores (updated by assessment engine)
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    culture_score: Mapped[float] = mapped_column(Float, default=0.0)
    compliance_score: Mapped[float] = mapped_column(Float, default=0.0)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    remediation_velocity: Mapped[float] = mapped_column(Float, default=0.0)

    def __repr__(self) -> str:
        return f"<Organisation {self.slug}>"
