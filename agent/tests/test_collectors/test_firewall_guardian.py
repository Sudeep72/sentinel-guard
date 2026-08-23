"""Tests for the Firewall Guardian collector."""

from __future__ import annotations

from unittest.mock import patch

from sentinelguard_contracts import GuardianCategory, GuardianRunStatus, Severity

from sentinelguard_agent.collectors.firewall_guardian import FirewallGuardian


def test_category_is_firewall():
    assert FirewallGuardian.category == GuardianCategory.FIREWALL


def test_run_returns_guardian_result():
    result = FirewallGuardian().run()
    assert result.module == GuardianCategory.FIREWALL
    assert result.status in (GuardianRunStatus.OK, GuardianRunStatus.ERROR)


def _guardian_no_firewall():
    """Patch helper: simulate no firewall present."""
    guardian = FirewallGuardian()
    with (
        patch.object(guardian, "_is_ufw_active", return_value=False),
        patch.object(guardian, "_is_firewalld_active", return_value=False),
        patch.object(guardian, "_get_iptables_rules", return_value=""),
        patch.object(guardian, "_get_nftables_rules", return_value=""),
        patch.object(guardian, "_ufw_installed", return_value=False),
        patch.object(guardian, "_firewalld_installed", return_value=False),
    ):
        return guardian._collect()


# ── FIREWALL-001: No firewall active ────────────────────────────────────────


def test_firewall_001_no_firewall():
    findings = _guardian_no_firewall()
    fw001 = [f for f in findings if f.check_id == "FIREWALL-001"]
    assert len(fw001) == 1
    assert fw001[0].severity == Severity.CRITICAL


def test_firewall_001_stops_further_checks():
    """When no firewall is active, only FIREWALL-001 is returned."""
    findings = _guardian_no_firewall()
    assert all(f.check_id == "FIREWALL-001" for f in findings)


# ── FIREWALL-006: UFW inactive ───────────────────────────────────────────────


def test_firewall_006_ufw_installed_but_inactive():
    guardian = FirewallGuardian()
    with (
        patch.object(guardian, "_is_ufw_active", return_value=False),
        patch.object(guardian, "_is_firewalld_active", return_value=False),
        patch.object(
            guardian, "_get_iptables_rules", return_value=_iptables_with_policies("DROP", "DROP")
        ),
        patch.object(guardian, "_get_nftables_rules", return_value=""),
        patch.object(guardian, "_ufw_installed", return_value=True),
        patch.object(guardian, "_firewalld_installed", return_value=False),
    ):
        findings = guardian._collect()

    fw006 = [f for f in findings if f.check_id == "FIREWALL-006"]
    assert len(fw006) == 1
    assert fw006[0].severity == Severity.HIGH


# ── FIREWALL-007: firewalld inactive ────────────────────────────────────────


def test_firewall_007_firewalld_installed_but_inactive():
    guardian = FirewallGuardian()
    with (
        patch.object(guardian, "_is_ufw_active", return_value=False),
        patch.object(guardian, "_is_firewalld_active", return_value=False),
        patch.object(
            guardian, "_get_iptables_rules", return_value=_iptables_with_policies("DROP", "DROP")
        ),
        patch.object(guardian, "_get_nftables_rules", return_value=""),
        patch.object(guardian, "_ufw_installed", return_value=False),
        patch.object(guardian, "_firewalld_installed", return_value=True),
    ):
        findings = guardian._collect()

    fw007 = [f for f in findings if f.check_id == "FIREWALL-007"]
    assert len(fw007) == 1
    assert fw007[0].severity == Severity.HIGH


# ── FIREWALL-002: Default INPUT policy ──────────────────────────────────────


def _iptables_with_policies(input_policy: str, forward_policy: str) -> str:
    return (
        f"Chain INPUT (policy {input_policy} 0 packets, 0 bytes)\n"
        f"Chain FORWARD (policy {forward_policy} 0 packets, 0 bytes)\n"
        "Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)\n"
    )


def test_firewall_002_input_accept_policy():
    guardian = FirewallGuardian()
    rules = _iptables_with_policies("ACCEPT", "DROP")
    findings = guardian._check_iptables_policies(rules)
    fw002 = [f for f in findings if f.check_id == "FIREWALL-002"]
    assert len(fw002) == 1
    assert fw002[0].severity == Severity.HIGH


def test_firewall_002_drop_policy_no_finding():
    guardian = FirewallGuardian()
    rules = _iptables_with_policies("DROP", "DROP")
    findings = guardian._check_iptables_policies(rules)
    fw002 = [f for f in findings if f.check_id == "FIREWALL-002"]
    assert len(fw002) == 0


# ── FIREWALL-003: Default FORWARD policy ────────────────────────────────────


def test_firewall_003_forward_accept_policy():
    guardian = FirewallGuardian()
    rules = _iptables_with_policies("DROP", "ACCEPT")
    findings = guardian._check_iptables_policies(rules)
    fw003 = [f for f in findings if f.check_id == "FIREWALL-003"]
    assert len(fw003) == 1
    assert fw003[0].severity == Severity.MEDIUM


# ── FIREWALL-005: Dangerous ports ───────────────────────────────────────────


def test_firewall_005_mysql_port_open():
    guardian = FirewallGuardian()
    rules = (
        _iptables_with_policies("DROP", "DROP")
        + "ACCEPT     tcp -- 0.0.0.0/0  0.0.0.0/0  tcp dpt:3306\n"
    )
    findings = guardian._check_dangerous_ports_iptables(rules)
    fw005 = [f for f in findings if f.check_id == "FIREWALL-005"]
    assert len(fw005) == 1
    assert fw005[0].severity == Severity.HIGH


def test_firewall_005_no_dangerous_ports():
    guardian = FirewallGuardian()
    rules = (
        _iptables_with_policies("DROP", "DROP")
        + "ACCEPT     tcp -- 0.0.0.0/0  0.0.0.0/0  tcp dpt:443\n"
    )
    findings = guardian._check_dangerous_ports_iptables(rules)
    fw005 = [f for f in findings if f.check_id == "FIREWALL-005"]
    assert len(fw005) == 0


# ── FIREWALL-002 via UFW ─────────────────────────────────────────────────────


def test_firewall_002_ufw_allow_incoming():
    guardian = FirewallGuardian()
    with (
        patch.object(guardian, "_is_ufw_active", return_value=True),
        patch(
            "sentinelguard_agent.collectors.firewall_guardian.run_command",
            return_value="Default: allow (incoming)\nDefault: allow (outgoing)\n",
        ),
    ):
        findings = guardian._check_ufw_default_policies()

    fw002 = [f for f in findings if f.check_id == "FIREWALL-002"]
    assert len(fw002) == 1


def test_firewall_002_ufw_deny_incoming_no_finding():
    guardian = FirewallGuardian()
    with patch(
        "sentinelguard_agent.collectors.firewall_guardian.run_command",
        return_value="Default: deny (incoming)\nDefault: allow (outgoing)\n",
    ):
        findings = guardian._check_ufw_default_policies()

    assert len(findings) == 0


# ── FIREWALL-004: SSH exposure via UFW ──────────────────────────────────────


def test_firewall_004_ssh_open_to_anywhere():
    guardian = FirewallGuardian()
    ufw_numbered = (
        "Status: active\n"
        "     To                         Action      From\n"
        "     --                         ------      ----\n"
        "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
    )
    with patch(
        "sentinelguard_agent.collectors.firewall_guardian.run_command",
        return_value=ufw_numbered,
    ):
        findings = guardian._check_ufw_ssh_exposure()

    fw004 = [f for f in findings if f.check_id == "FIREWALL-004"]
    assert len(fw004) == 1
    assert fw004[0].severity == Severity.MEDIUM


def test_firewall_004_ssh_restricted_no_finding():
    guardian = FirewallGuardian()
    ufw_numbered = "Status: active\n" "[ 1] 22/tcp                     ALLOW IN    192.168.1.0/24\n"
    with patch(
        "sentinelguard_agent.collectors.firewall_guardian.run_command",
        return_value=ufw_numbered,
    ):
        findings = guardian._check_ufw_ssh_exposure()

    assert len(findings) == 0


# ── iptables chain policy extractor ─────────────────────────────────────────


def test_extract_chain_policy_drop():
    guardian = FirewallGuardian()
    rules = "Chain INPUT (policy DROP 0 packets, 0 bytes)\n"
    assert guardian._extract_chain_policy(rules, "INPUT") == "DROP"


def test_extract_chain_policy_accept():
    guardian = FirewallGuardian()
    rules = "Chain INPUT (policy ACCEPT 10 packets)\n"
    assert guardian._extract_chain_policy(rules, "INPUT") == "ACCEPT"


def test_extract_chain_policy_not_found():
    guardian = FirewallGuardian()
    assert guardian._extract_chain_policy("", "INPUT") is None


# ── Full copilot payload ─────────────────────────────────────────────────────


def test_all_findings_have_full_copilot_payload():
    findings = _guardian_no_firewall()
    for f in findings:
        assert f.check_id
        assert f.title
        assert f.description
        assert f.why_it_matters
        assert f.attack_scenario
        assert f.recommendation
        assert f.current_value is not None
        assert f.expected_value is not None


# ── Registry ─────────────────────────────────────────────────────────────────


def test_registered_in_registry():
    from sentinelguard_agent.collectors.registry import GUARDIAN_REGISTRY

    categories = [g.category for g in GUARDIAN_REGISTRY]
    assert GuardianCategory.FIREWALL in categories
