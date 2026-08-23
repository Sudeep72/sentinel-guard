"""Tests for baseline_engine_service (Phase 17)."""

from __future__ import annotations

import json

from app.models.baseline import Baseline
from app.services.baseline_engine_service import (
    get_effective_rules,
    set_custom_rule_override,
    sync_baselines_to_db,
)

# ── sync_baselines_to_db ─────────────────────────────────────────────────────


def test_sync_baselines_creates_rows_for_all_distros_and_categories(db_session):
    count = sync_baselines_to_db(db_session)
    # 5 distros x 9 categories = 45 rows
    assert count == 45

    rows = db_session.query(Baseline).filter(Baseline.source == "yaml").all()
    assert len(rows) == 45


def test_sync_baselines_specific_distro_only(db_session):
    count = sync_baselines_to_db(db_session, distros=("ubuntu",))
    assert count == 9  # 9 categories for one distro

    rows = db_session.query(Baseline).filter(Baseline.distro == "ubuntu").all()
    assert len(rows) == 9


def test_sync_baselines_is_idempotent_no_duplicates(db_session):
    sync_baselines_to_db(db_session, distros=("ubuntu",))
    sync_baselines_to_db(db_session, distros=("ubuntu",))

    rows = db_session.query(Baseline).filter(Baseline.distro == "ubuntu").all()
    assert len(rows) == 9  # still 9, not 18


def test_sync_baselines_records_version(db_session):
    sync_baselines_to_db(db_session, distros=("ubuntu",))
    row = (
        db_session.query(Baseline)
        .filter(Baseline.distro == "ubuntu", Baseline.category == "ssh")
        .one()
    )
    assert row.version == "1.0.0"
    assert row.source == "yaml"


def test_sync_baselines_content_matches_yaml(db_session):
    sync_baselines_to_db(db_session, distros=("ubuntu",))
    row = (
        db_session.query(Baseline)
        .filter(Baseline.distro == "ubuntu", Baseline.category == "ssh")
        .one()
    )
    rules = json.loads(row.rules_json)
    assert "PermitRootLogin" in rules
    assert rules["PermitRootLogin"]["expected"] == "no"


def test_sync_baselines_updates_existing_row_in_place(db_session):
    sync_baselines_to_db(db_session, distros=("ubuntu",))
    row_id_before = (
        db_session.query(Baseline)
        .filter(Baseline.distro == "ubuntu", Baseline.category == "ssh")
        .one()
        .id
    )

    sync_baselines_to_db(db_session, distros=("ubuntu",))
    row_id_after = (
        db_session.query(Baseline)
        .filter(Baseline.distro == "ubuntu", Baseline.category == "ssh")
        .one()
        .id
    )

    assert row_id_before == row_id_after  # same row updated, not a new one


# ── get_effective_rules ──────────────────────────────────────────────────────


def test_get_effective_rules_yaml_only_when_no_custom_override(db_session):
    rules = get_effective_rules(db_session, "ubuntu", "ssh")
    assert "PermitRootLogin" in rules
    assert rules["PermitRootLogin"]["expected"] == "no"


def test_get_effective_rules_applies_custom_override(db_session):
    set_custom_rule_override(
        db_session,
        "ubuntu",
        "ssh",
        "PermitRootLogin",
        {"expected": "prohibit-password", "severity": "low"},
    )

    rules = get_effective_rules(db_session, "ubuntu", "ssh")
    assert rules["PermitRootLogin"]["expected"] == "prohibit-password"
    assert rules["PermitRootLogin"]["severity"] == "low"


def test_get_effective_rules_custom_override_does_not_remove_other_yaml_rules(db_session):
    set_custom_rule_override(
        db_session, "ubuntu", "ssh", "PermitRootLogin", {"expected": "no", "severity": "critical"}
    )

    rules = get_effective_rules(db_session, "ubuntu", "ssh")
    # Other YAML rules for this category remain untouched
    assert "PasswordAuthentication" in rules
    assert "PermitEmptyPasswords" in rules


def test_get_effective_rules_unknown_distro_returns_empty(db_session):
    rules = get_effective_rules(db_session, "windows", "ssh")
    assert rules == {}


def test_get_effective_rules_invalid_custom_json_ignored(db_session):
    db_session.add(
        Baseline(
            distro="ubuntu",
            category="ssh",
            rules_json="not valid json {{{",
            version="custom-1.0.0",
            source="custom",
        )
    )
    db_session.commit()

    # Should not raise; falls back to YAML-only rules
    rules = get_effective_rules(db_session, "ubuntu", "ssh")
    assert "PermitRootLogin" in rules


# ── set_custom_rule_override ─────────────────────────────────────────────────


def test_set_custom_rule_override_creates_new_row(db_session):
    set_custom_rule_override(
        db_session, "ubuntu", "ssh", "MaxAuthTries", {"expected": "3", "severity": "low"}
    )

    row = (
        db_session.query(Baseline)
        .filter(
            Baseline.distro == "ubuntu",
            Baseline.category == "ssh",
            Baseline.source == "custom",
        )
        .one()
    )
    rules = json.loads(row.rules_json)
    assert rules["MaxAuthTries"]["expected"] == "3"


def test_set_custom_rule_override_merges_into_existing_row(db_session):
    set_custom_rule_override(
        db_session, "ubuntu", "ssh", "MaxAuthTries", {"expected": "3", "severity": "low"}
    )
    set_custom_rule_override(
        db_session, "ubuntu", "ssh", "PermitRootLogin", {"expected": "no", "severity": "critical"}
    )

    row = (
        db_session.query(Baseline)
        .filter(
            Baseline.distro == "ubuntu",
            Baseline.category == "ssh",
            Baseline.source == "custom",
        )
        .one()
    )
    rules = json.loads(row.rules_json)
    assert "MaxAuthTries" in rules
    assert "PermitRootLogin" in rules  # both present, not overwritten


def test_set_custom_rule_override_updates_existing_rule(db_session):
    set_custom_rule_override(
        db_session, "ubuntu", "ssh", "MaxAuthTries", {"expected": "3", "severity": "low"}
    )
    set_custom_rule_override(
        db_session, "ubuntu", "ssh", "MaxAuthTries", {"expected": "5", "severity": "medium"}
    )

    rules = get_effective_rules(db_session, "ubuntu", "ssh")
    assert rules["MaxAuthTries"]["expected"] == "5"
    assert rules["MaxAuthTries"]["severity"] == "medium"
