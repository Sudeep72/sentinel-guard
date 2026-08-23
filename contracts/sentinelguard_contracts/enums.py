"""Enumerations shared by the Agent and Dashboard wire contracts.

All enums subclass ``str`` so they serialize as plain strings over JSON
(agent -> dashboard HTTP payloads, dashboard -> MCP tool responses)
without requiring custom encoders.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Finding severity, used both for scoring weight lookup and display."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class GuardianCategory(str, Enum):
    """The nine V1 Guardian modules.

    This is the single place a new Guardian category is registered.
    Adding a Guardian in Phases 8-16 means adding a member here first.
    """

    PERMISSION = "permission"
    OWNERSHIP = "ownership"
    SSH = "ssh"
    SUDO = "sudo"
    CRON = "cron"
    SECRET = "secret"
    DOCKER = "docker"
    FIREWALL = "firewall"
    KERNEL = "kernel"


class FindingStatus(str, Enum):
    """Lifecycle status of a finding, set/updated dashboard-side."""

    OPEN = "open"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class ScanStatus(str, Enum):
    """Overall status of a single scan run."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"  # scan completed but one or more Guardians failed to collect


class ServerStatus(str, Enum):
    """Connectivity status of a registered server, derived from last_seen_at."""

    ONLINE = "online"
    OFFLINE = "offline"
    STALE = "stale"


class Distro(str, Enum):
    """Linux distributions supported by the V1 agent."""

    UBUNTU = "ubuntu"
    DEBIAN = "debian"
    FEDORA = "fedora"
    ROCKY = "rocky"
    CENTOS = "centos"
    UNKNOWN = "unknown"


class ReportFormat(str, Enum):
    """Supported report output formats."""

    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    JSON = "json"
    MARKDOWN = "markdown"


class GuardianRunStatus(str, Enum):
    """Outcome of a single Guardian's collection run."""

    OK = "ok"
    ERROR = "error"
