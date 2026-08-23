import pytest
from pydantic import ValidationError

from sentinelguard_contracts import Finding, GuardianCategory, Severity


def _valid_finding_kwargs(**overrides):
    kwargs = dict(
        check_id="SSH-001",
        module=GuardianCategory.SSH,
        title="PermitRootLogin is enabled",
        severity=Severity.HIGH,
        description="sshd_config allows root login over SSH.",
        why_it_matters="Root login over SSH removes a key barrier to full compromise.",
        attack_scenario="An attacker with a leaked or brute-forced root credential gains "
        "immediate root shell access with no privilege escalation needed.",
        recommendation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
    )
    kwargs.update(overrides)
    return kwargs


def test_finding_valid_construction():
    finding = Finding(**_valid_finding_kwargs())
    assert finding.check_id == "SSH-001"
    assert finding.severity == Severity.HIGH
    assert finding.current_value is None


def test_finding_optional_fields_default_none():
    finding = Finding(**_valid_finding_kwargs())
    assert finding.current_value is None
    assert finding.expected_value is None


def test_finding_optional_fields_can_be_set():
    finding = Finding(**_valid_finding_kwargs(current_value="yes", expected_value="no"))
    assert finding.current_value == "yes"
    assert finding.expected_value == "no"


@pytest.mark.parametrize(
    "field,value",
    [
        ("check_id", ""),
        ("title", ""),
        ("description", ""),
        ("why_it_matters", ""),
        ("attack_scenario", ""),
        ("recommendation", ""),
    ],
)
def test_finding_rejects_empty_required_strings(field, value):
    with pytest.raises(ValidationError):
        Finding(**_valid_finding_kwargs(**{field: value}))


def test_finding_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        Finding(**_valid_finding_kwargs(severity="catastrophic"))


def test_finding_rejects_invalid_module():
    with pytest.raises(ValidationError):
        Finding(**_valid_finding_kwargs(module="networking"))


def test_finding_strips_whitespace():
    finding = Finding(**_valid_finding_kwargs(title="  Padded title  "))
    assert finding.title == "Padded title"


def test_finding_serializes_round_trip():
    finding = Finding(**_valid_finding_kwargs())
    dumped = finding.model_dump_json()
    restored = Finding.model_validate_json(dumped)
    assert restored == finding
