"""Dashboard-side Guardian module registry.

Server-side analyzers interpret the raw ``Finding`` objects an agent
collector emits and compare them against distro-aware baselines from
``app/baselines/``.  Each analyzer can:

- Upgrade or downgrade a finding's severity based on the baseline.
- Add baseline-derived findings that the agent never saw (e.g. a
  missing ``PermitRootLogin no`` directive when the key is absent from
  sshd_config rather than explicitly set to ``yes``).
- Return ``BaselineComparisonItem`` objects for the
  ``compare_to_baseline`` MCP tool / REST endpoint.

Registration pattern (mirrors the agent-side ``GUARDIAN_REGISTRY``):

    from app.modules.registry import register_analyzer
    from app.modules.permission.analyzer import PermissionAnalyzer

    register_analyzer(PermissionAnalyzer)

Called at app startup from ``app/main.py``.  New Guardians (Phases 3B+)
simply add a ``register_analyzer`` call without touching any existing
code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from sentinelguard_contracts import GuardianCategory

from app.schemas.baselines import BaselineComparisonItem
from app.schemas.findings import FindingRecord


class BaseAnalyzer(ABC):
    """Interface every dashboard-side Guardian analyzer implements."""

    category: GuardianCategory

    @abstractmethod
    def analyze(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[FindingRecord]:
        """Post-process agent-emitted findings against the baseline.

        Implementations may adjust severity or add baseline-derived
        findings that the agent did not emit.
        """
        ...

    @abstractmethod
    def compare(
        self,
        findings: list[FindingRecord],
        distro: str,
        distro_version: str | None,
    ) -> list[BaselineComparisonItem]:
        """Produce a current-vs-expected comparison for every rule
        this analyzer owns.
        """
        ...


# ---------------------------------------------------------------------------
# Registry (populated by register_analyzer() calls at startup)
# ---------------------------------------------------------------------------

_REGISTRY: dict[GuardianCategory, BaseAnalyzer] = {}


def register_analyzer(analyzer: BaseAnalyzer) -> None:
    """Register a dashboard-side analyzer for a Guardian category."""
    _REGISTRY[analyzer.category] = analyzer


def clear_registry() -> None:
    """Clear all registered analyzers (used in tests for isolation)."""
    _REGISTRY.clear()


def get_analyzer(category: GuardianCategory) -> BaseAnalyzer | None:
    """Return the registered analyzer for *category*, or ``None``."""
    return _REGISTRY.get(category)


def all_analyzers() -> list[BaseAnalyzer]:
    """Return all registered analyzers."""
    return list(_REGISTRY.values())
