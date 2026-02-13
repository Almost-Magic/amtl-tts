"""Database models for Digital Sentinel."""

from src.models.base import Base
from src.models.organisation import Organisation
from src.models.vulnerability import Vulnerability
from src.models.assessment import Assessment
from src.models.benchmark import BenchmarkRecord, IndustrySnapshot
from src.models.wazuh import WazuhConnection, WazuhAlert, CorrelationResult

__all__ = [
    "Base",
    "Organisation",
    "Vulnerability",
    "Assessment",
    "BenchmarkRecord",
    "IndustrySnapshot",
    "WazuhConnection",
    "WazuhAlert",
    "CorrelationResult",
]
