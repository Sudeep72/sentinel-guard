"""Baseline Engine Service (Phase 17).

YAML files under ``app/baselines/`` remain the canonical source of
truth for baseline rules — this service does not replace them, it adds
three capabilities on top:

1. **Versioning**: ``get_baseline_version()`` exposes the baseline
   file's own ``version`` key, so a computed score can record exactly
   which baseline revision produced it (see
   ``app/services/scoring_service.py``).
2. **DB snapshotting**: ``sync_baselines_to_db()`` persists the current
   YAML content into the ``baselines`` table, giving a durable,
   queryable historical record of "what was the baseline at time T"
   independent of the YAML files on disk (which could theoretically
   change without a corresponding DB migration).
3. **Custom organization baseline overrides** (extension point):
   ``get_effective_rules()`` layers any DB-stored ``source="custom"``
   rows on top of the YAML defaults. ``set_custom_rule_override()``
   writes those rows. No REST/MCP surface exposes creating custom
   overrides yet — that's future work — but the mechanism is real,
   tested, and ready to be wired up without further service-layer
   changes.

**Deliberate scope boundary**: the nine Guardian analyzers
(``app/modules/*/analyzer.py``) call ``baseline_loader.get_baseline_rules()``
directly (YAML-only), not this service's ``get_effective_rules()``.
Routing custom overrides into live analyzer ``analyze()``/``compare()``
calls would require adding a ``db: Session`` parameter to all eighteen
analyzer methods across nine files — a real signature change — for a
feature with no caller yet (no custom-override management UI/API
exists in this milestone). This service function is ready for that
day; wiring it in is deferred until there's an actual feature that
needs it, per YAGNI.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models.baseline import Baseline
from app.modules.baseline_loader import get_baseline_rules, get_baseline_version

logger = logging.getLogger(__name__)

# The five distros with YAML baseline files, per ARCHITECTURE.md.
_SUPPORTED_DISTROS = ("ubuntu", "debian", "fedora", "rocky", "centos")

# The nine v1 Guardian categories, per GuardianCategory.
_CATEGORIES = (
    "permission",
    "ownership",
    "ssh",
    "sudo",
    "cron",
    "secret",
    "docker",
    "firewall",
    "kernel",
)


def sync_baselines_to_db(db: Session, distros: tuple[str, ...] | None = None) -> int:
    """Persist the current YAML baseline content into the ``baselines`` table.

    Upserts one row per (distro, category) with ``source="yaml"``. Safe
    to call repeatedly (e.g. on every app startup) — existing rows are
    updated in place rather than duplicated.

    Args:
        db: Active database session.
        distros: Specific distros to sync, or all five supported
            distros if omitted.

    Returns:
        The number of (distro, category) rows upserted.
    """
    target_distros = distros or _SUPPORTED_DISTROS
    upserted = 0

    for distro in target_distros:
        version = get_baseline_version(distro) or "unknown"
        for category in _CATEGORIES:
            rules = get_baseline_rules(distro, category)
            if not rules:
                continue

            existing = (
                db.query(Baseline)
                .filter(
                    Baseline.distro == distro,
                    Baseline.category == category,
                    Baseline.source == "yaml",
                )
                .one_or_none()
            )

            rules_json = json.dumps(rules)
            if existing is not None:
                existing.rules_json = rules_json
                existing.version = version
            else:
                db.add(
                    Baseline(
                        distro=distro,
                        distro_version=None,
                        category=category,
                        rules_json=rules_json,
                        version=version,
                        source="yaml",
                    )
                )
            upserted += 1

    db.commit()
    logger.info("Synced %d baseline rule sets to the database", upserted)
    return upserted


def get_effective_rules(db: Session, distro: str, category: str) -> dict[str, Any]:
    """Return baseline rules for (distro, category), with any custom
    organization overrides layered on top of the YAML defaults.

    Custom overrides replace individual rule keys — a custom baseline
    doesn't need to redefine every rule in a category, only the ones it
    wants to change.
    """
    rules = dict(get_baseline_rules(distro, category))

    custom_row = (
        db.query(Baseline)
        .filter(
            Baseline.distro == distro,
            Baseline.category == category,
            Baseline.source == "custom",
        )
        .one_or_none()
    )
    if custom_row is not None:
        try:
            custom_rules = json.loads(custom_row.rules_json)
            rules.update(custom_rules)
        except json.JSONDecodeError:
            logger.warning("Invalid custom baseline JSON for %s/%s — ignoring", distro, category)

    return rules


def set_custom_rule_override(
    db: Session, distro: str, category: str, rule_name: str, rule: dict[str, Any]
) -> None:
    """Add or update a single custom organization rule override.

    Merges into any existing custom override row for this
    (distro, category) rather than replacing the whole row, so multiple
    calls can build up a custom rule set one rule at a time.
    """
    existing = (
        db.query(Baseline)
        .filter(
            Baseline.distro == distro,
            Baseline.category == category,
            Baseline.source == "custom",
        )
        .one_or_none()
    )

    if existing is not None:
        current_rules: dict[str, Any] = json.loads(existing.rules_json)
        current_rules[rule_name] = rule
        existing.rules_json = json.dumps(current_rules)
    else:
        version = get_baseline_version(distro) or "custom-1.0.0"
        db.add(
            Baseline(
                distro=distro,
                distro_version=None,
                category=category,
                rules_json=json.dumps({rule_name: rule}),
                version=version,
                source="custom",
            )
        )

    db.commit()
