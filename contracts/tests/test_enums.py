from sentinelguard_contracts.enums import Distro, GuardianCategory, Severity


def test_guardian_category_has_exactly_nine_v1_modules():
    """Guards against accidentally adding a v2+ category (e.g. 'vuln_scan')
    to the v1 contracts package."""
    expected = {
        "permission",
        "ownership",
        "ssh",
        "sudo",
        "cron",
        "secret",
        "docker",
        "firewall",
        "kernel",
    }
    actual = {member.value for member in GuardianCategory}
    assert actual == expected


def test_severity_ordering_values():
    assert {s.value for s in Severity} == {"critical", "high", "medium", "low", "info"}


def test_distro_includes_all_v1_supported_distros():
    expected = {"ubuntu", "debian", "fedora", "rocky", "centos", "unknown"}
    assert {d.value for d in Distro} == expected
