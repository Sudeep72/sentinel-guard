"""Tests for the baseline loader."""

from app.modules.baseline_loader import get_baseline_rules, get_severity_from_baseline


def test_get_baseline_rules_ubuntu_permission():
    rules = get_baseline_rules("ubuntu", "permission")
    assert len(rules) > 0
    assert "/etc/shadow" in rules


def test_get_baseline_rules_ubuntu_ssh():
    rules = get_baseline_rules("ubuntu", "ssh")
    assert "PermitRootLogin" in rules
    assert "PasswordAuthentication" in rules
    assert "PermitEmptyPasswords" in rules


def test_get_baseline_rules_ubuntu_ownership():
    rules = get_baseline_rules("ubuntu", "ownership")
    assert "/etc/shadow" in rules


def test_get_baseline_rules_debian():
    rules = get_baseline_rules("debian", "ssh")
    assert len(rules) > 0


def test_get_baseline_rules_fedora():
    rules = get_baseline_rules("fedora", "permission")
    assert "/etc/shadow" in rules


def test_get_baseline_rules_rocky():
    rules = get_baseline_rules("rocky", "ssh")
    assert len(rules) > 0


def test_get_baseline_rules_centos():
    rules = get_baseline_rules("centos", "ssh")
    assert len(rules) > 0


def test_get_baseline_rules_unknown_distro_returns_empty():
    rules = get_baseline_rules("windows", "ssh")
    assert rules == {}


def test_get_baseline_rules_unknown_category_returns_empty():
    rules = get_baseline_rules("ubuntu", "nonexistent_category")
    assert rules == {}


def test_get_severity_from_baseline_known():
    rule = {"expected": "no", "severity": "critical"}
    assert get_severity_from_baseline(rule) == "critical"


def test_get_severity_from_baseline_default():
    rule = {"expected": "no"}
    assert get_severity_from_baseline(rule) == "medium"
