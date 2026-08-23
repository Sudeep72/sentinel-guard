"""sentinelguard_contracts — shared wire-format models for Agent <-> Dashboard.

Import everything needed from the top level, e.g.::

    from sentinelguard_contracts import ScanPayload, Finding, Severity
"""

from sentinelguard_contracts.enums import (
    Distro,
    FindingStatus,
    GuardianCategory,
    GuardianRunStatus,
    ReportFormat,
    ScanStatus,
    ServerStatus,
    Severity,
)
from sentinelguard_contracts.finding import Finding
from sentinelguard_contracts.guardian import GuardianResult
from sentinelguard_contracts.report import Report, ReportRequest
from sentinelguard_contracts.scan import ScanPayload
from sentinelguard_contracts.score import CategoryScore, SecurityScore
from sentinelguard_contracts.server import ServerInfo, ServerRegistration

__all__ = [
    "Distro",
    "FindingStatus",
    "GuardianCategory",
    "GuardianRunStatus",
    "ReportFormat",
    "ScanStatus",
    "ServerStatus",
    "Severity",
    "Finding",
    "GuardianResult",
    "Report",
    "ReportRequest",
    "ScanPayload",
    "CategoryScore",
    "SecurityScore",
    "ServerInfo",
    "ServerRegistration",
]

__version__ = "1.0.1"
