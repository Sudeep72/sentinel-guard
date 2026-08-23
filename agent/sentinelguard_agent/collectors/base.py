"""BaseGuardian — the interface every Guardian collector implements.

A Guardian's job is narrow: gather raw facts about one area of the
host's security posture (permissions, SSH config, sudo rules, etc.) and
turn them into ``Finding`` objects. It does not decide what "secure"
means in the abstract — comparisons against baselines happen dashboard-
side (see ``dashboard/app/modules/`` and ``dashboard/app/baselines/``,
Phase 17). For V1 simplicity a Guardian may still assign a preliminary
severity to each finding it emits; the dashboard's baseline engine can
refine this later without requiring an agent change.

Subclasses implement ``_collect()``. The public ``run()`` method wraps
that call so that an exception in one Guardian never crashes the whole
scan — it's converted into a ``GuardianResult`` with ``status=ERROR``
instead, which is what lets ``aggregator.run_scan`` mark the overall
scan ``PARTIAL`` rather than ``FAILED``.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime

from sentinelguard_contracts import (
    Finding,
    GuardianCategory,
    GuardianResult,
    GuardianRunStatus,
)

logger = logging.getLogger(__name__)


class BaseGuardian(ABC):
    """Abstract base class for all Guardian collectors.

    Subclasses must set the ``category`` class attribute and implement
    ``_collect()``.
    """

    category: GuardianCategory

    @abstractmethod
    def _collect(self) -> list[Finding]:
        """Gather findings for this Guardian's category.

        Implementations should raise on unrecoverable errors (e.g. a
        required binary is missing) rather than swallowing them —
        ``run()`` converts any exception into a structured error result.
        """
        raise NotImplementedError

    def run(self) -> GuardianResult:
        """Execute this Guardian and return a structured result.

        Never raises: collection failures are captured as
        ``GuardianResult(status=ERROR, error_message=...)``.
        """
        start = time.monotonic()
        try:
            findings = self._collect()
        except Exception as exc:  # noqa: BLE001 - intentionally broad: isolate Guardian failures
            duration_ms = (time.monotonic() - start) * 1000
            logger.exception("Guardian %s failed to collect", self.category.value)
            return GuardianResult(
                module=self.category,
                status=GuardianRunStatus.ERROR,
                error_message=str(exc),
                collected_at=datetime.now(UTC),
                duration_ms=duration_ms,
            )

        duration_ms = (time.monotonic() - start) * 1000
        return GuardianResult(
            module=self.category,
            status=GuardianRunStatus.OK,
            findings=findings,
            collected_at=datetime.now(UTC),
            duration_ms=duration_ms,
        )
