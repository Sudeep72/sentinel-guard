"""Baseline loader.

Loads distro-specific YAML baseline files from ``app/baselines/`` and
exposes them as plain Python dicts.  Results are cached by distro name
so each file is only read and parsed once per process lifetime.

Every dashboard-side Guardian analyzer calls ``get_baseline_rules`` to
retrieve the rules relevant to its category, then uses those rules in
``analyze()`` and ``compare()`` implementations.
"""

from __future__ import annotations

import functools
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_BASELINES_DIR = Path(__file__).parent.parent / "baselines"

# Sentinel so we can distinguish "not loaded yet" from "loaded, but empty".
_MISSING: dict[str, Any] = {}


@functools.lru_cache(maxsize=16)
def _load_baseline_yaml(distro: str) -> dict[str, Any]:
    """Load and return the raw YAML dict for *distro*.  Cached."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("PyYAML is not installed; baseline comparisons will be unavailable.")
        return {}

    path = _BASELINES_DIR / f"{distro}.yaml"
    if not path.exists():
        logger.debug("No baseline file found for distro %r at %s", distro, path)
        return {}

    try:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data or {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load baseline %s: %s", path, exc)
        return {}


def get_baseline_rules(distro: str, category: str) -> dict[str, Any]:
    """Return the baseline rules for *category* on *distro*.

    Returns an empty dict if no baseline exists for this distro or
    the distro baseline has no rules for the given category.
    """
    data = _load_baseline_yaml(distro)
    rules: dict[str, Any] = data.get(category, {})
    return rules


def get_severity_from_baseline(rule: dict[str, Any]) -> str:
    """Extract severity string from a baseline rule dict, defaulting to 'medium'."""
    return str(rule.get("severity", "medium"))


def get_baseline_version(distro: str) -> str | None:
    """Return the top-level ``version`` string for a distro's baseline file.

    Returns ``None`` if the distro has no baseline file or the file has
    no ``version`` key. This is a distinct concept from a rule's own
    metadata — it identifies the overall baseline *file* revision, which
    is what gets recorded alongside computed scores so a score can be
    traced back to exactly which baseline content produced it, even if
    the YAML is edited later.
    """
    data = _load_baseline_yaml(distro)
    version = data.get("version")
    return str(version) if version is not None else None
