"""Tests for the Kernel Guardian collector."""

from __future__ import annotations

from unittest.mock import patch

from sentinelguard_contracts import GuardianCategory, GuardianRunStatus, Severity

from sentinelguard_agent.collectors.kernel_guardian import SYSCTL_RULES, KernelGuardian


def test_category_is_kernel():
    assert KernelGuardian.category == GuardianCategory.KERNEL


def test_run_returns_guardian_result():
    result = KernelGuardian().run()
    assert result.module == GuardianCategory.KERNEL
    assert result.status in (GuardianRunStatus.OK, GuardianRunStatus.ERROR)


# ── KERNEL-013: Version check ────────────────────────────────────────────────


def test_kernel_013_eol_version():
    guardian = KernelGuardian()
    with patch(
        "sentinelguard_agent.collectors.kernel_guardian.get_kernel_version",
        return_value="3.10.0-1160.el7.x86_64",
    ):
        findings = guardian._check_kernel_version()

    k013 = [f for f in findings if f.check_id == "KERNEL-013"]
    assert len(k013) == 1
    assert k013[0].severity == Severity.HIGH
    assert "3.10.0" in k013[0].current_value


def test_kernel_013_supported_version_no_finding():
    guardian = KernelGuardian()
    with patch(
        "sentinelguard_agent.collectors.kernel_guardian.get_kernel_version",
        return_value="5.15.0-91-generic",
    ):
        findings = guardian._check_kernel_version()

    assert len(findings) == 0


def test_kernel_013_exactly_minimum_version_no_finding():
    guardian = KernelGuardian()
    with patch(
        "sentinelguard_agent.collectors.kernel_guardian.get_kernel_version",
        return_value="4.14.0",
    ):
        findings = guardian._check_kernel_version()

    assert len(findings) == 0


def test_kernel_013_no_version_available_no_finding():
    guardian = KernelGuardian()
    with patch(
        "sentinelguard_agent.collectors.kernel_guardian.get_kernel_version",
        return_value=None,
    ):
        findings = guardian._check_kernel_version()

    assert len(findings) == 0


# ── KERNEL-001: ASLR ─────────────────────────────────────────────────────────


def _sysctl_collect_with(values: dict[str, str]) -> list:
    """Collect with a fake sysctl dict and no kernel version issues."""
    guardian = KernelGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.kernel_guardian.read_sysctl_all",
            return_value=values,
        ),
        patch(
            "sentinelguard_agent.collectors.kernel_guardian.read_sysctl",
            return_value=None,
        ),
        patch(
            "sentinelguard_agent.collectors.kernel_guardian.get_kernel_version",
            return_value="6.1.0",
        ),
    ):
        return guardian._collect()


def test_kernel_001_aslr_disabled():
    findings = _sysctl_collect_with({"kernel.randomize_va_space": "0"})
    k001 = [f for f in findings if f.check_id == "KERNEL-001"]
    assert len(k001) == 1
    assert k001[0].severity == Severity.HIGH
    assert k001[0].current_value == "0"
    assert k001[0].expected_value == "2"


def test_kernel_001_aslr_partial():
    findings = _sysctl_collect_with({"kernel.randomize_va_space": "1"})
    k001 = [f for f in findings if f.check_id == "KERNEL-001"]
    assert len(k001) == 1


def test_kernel_001_aslr_fully_enabled_no_finding():
    # Build an all-secure sysctl dict
    all_secure = {rule[1]: rule[2] for rule in SYSCTL_RULES}
    findings = _sysctl_collect_with(all_secure)
    k001 = [f for f in findings if f.check_id == "KERNEL-001"]
    assert len(k001) == 0


# ── KERNEL-002: ptrace scope ─────────────────────────────────────────────────


def test_kernel_002_ptrace_unrestricted():
    findings = _sysctl_collect_with({"kernel.yama.ptrace_scope": "0"})
    k002 = [f for f in findings if f.check_id == "KERNEL-002"]
    assert len(k002) == 1
    assert k002[0].severity == Severity.MEDIUM


def test_kernel_002_ptrace_restricted_no_finding():
    all_secure = {rule[1]: rule[2] for rule in SYSCTL_RULES}
    findings = _sysctl_collect_with(all_secure)
    k002 = [f for f in findings if f.check_id == "KERNEL-002"]
    assert len(k002) == 0


# ── KERNEL-003: core dump ────────────────────────────────────────────────────


def test_kernel_003_suid_dumpable_enabled():
    findings = _sysctl_collect_with({"fs.suid_dumpable": "1"})
    k003 = [f for f in findings if f.check_id == "KERNEL-003"]
    assert len(k003) == 1
    assert k003[0].severity == Severity.MEDIUM


# ── KERNEL-007: SYN cookies ─────────────────────────────────────────────────


def test_kernel_007_syncookies_disabled():
    findings = _sysctl_collect_with({"net.ipv4.tcp_syncookies": "0"})
    k007 = [f for f in findings if f.check_id == "KERNEL-007"]
    assert len(k007) == 1
    assert k007[0].severity == Severity.HIGH


def test_kernel_007_syncookies_enabled_no_finding():
    all_secure = {rule[1]: rule[2] for rule in SYSCTL_RULES}
    findings = _sysctl_collect_with(all_secure)
    k007 = [f for f in findings if f.check_id == "KERNEL-007"]
    assert len(k007) == 0


# ── Missing sysctl key treated as insecure ───────────────────────────────────


def test_missing_sysctl_treated_as_insecure():
    # Empty sysctl dict — all keys "not set" → all should be flagged as insecure
    guardian = KernelGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.kernel_guardian.read_sysctl_all",
            return_value={},
        ),
        patch(
            "sentinelguard_agent.collectors.kernel_guardian.read_sysctl",
            return_value=None,
        ),
        patch(
            "sentinelguard_agent.collectors.kernel_guardian.get_kernel_version",
            return_value="6.1.0",
        ),
    ):
        findings = guardian._check_sysctl_rules()

    # Every rule should fire since all values are "not set"
    assert len(findings) == len(SYSCTL_RULES)
    for finding in findings:
        assert finding.current_value == "not set (default insecure)"


# ── All secure → no sysctl findings ─────────────────────────────────────────


def test_all_secure_sysctl_produces_no_findings():
    all_secure = {rule[1]: rule[2] for rule in SYSCTL_RULES}
    guardian = KernelGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.kernel_guardian.read_sysctl_all",
            return_value=all_secure,
        ),
        patch(
            "sentinelguard_agent.collectors.kernel_guardian.read_sysctl",
            return_value=None,
        ),
    ):
        findings = guardian._check_sysctl_rules()

    assert findings == []


# ── Full copilot payload ─────────────────────────────────────────────────────


def test_all_findings_have_full_copilot_payload():
    # Trigger all sysctl findings by passing empty sysctl dict
    guardian = KernelGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.kernel_guardian.read_sysctl_all",
            return_value={},
        ),
        patch(
            "sentinelguard_agent.collectors.kernel_guardian.read_sysctl",
            return_value=None,
        ),
        patch(
            "sentinelguard_agent.collectors.kernel_guardian.get_kernel_version",
            return_value="3.10.0",
        ),
    ):
        findings = guardian._collect()

    assert len(findings) > 0
    for f in findings:
        assert f.check_id
        assert f.title
        assert f.description
        assert f.why_it_matters
        assert f.attack_scenario
        assert f.recommendation
        assert f.current_value is not None
        assert f.expected_value is not None


# ── SYSCTL_RULES structure ───────────────────────────────────────────────────


def test_sysctl_rules_have_twelve_entries():
    assert len(SYSCTL_RULES) == 12


def test_sysctl_rules_check_ids_are_unique():
    ids = [rule[0] for rule in SYSCTL_RULES]
    assert len(ids) == len(set(ids))


def test_sysctl_rules_all_have_kernel_prefix_check_ids():
    for rule in SYSCTL_RULES:
        assert rule[0].startswith("KERNEL-")


# ── Registry ─────────────────────────────────────────────────────────────────


def test_registered_in_registry():
    from sentinelguard_agent.collectors.registry import GUARDIAN_REGISTRY

    categories = [g.category for g in GUARDIAN_REGISTRY]
    assert GuardianCategory.KERNEL in categories


def test_registry_has_all_nine_guardians():
    from sentinelguard_agent.collectors.registry import GUARDIAN_REGISTRY

    assert len(GUARDIAN_REGISTRY) == 9
