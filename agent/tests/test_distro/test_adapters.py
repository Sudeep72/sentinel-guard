import pytest
from sentinelguard_contracts import Distro

from sentinelguard_agent.distro.adapters import get_adapter


@pytest.mark.parametrize(
    "distro,expected_pkg_mgr,expected_firewall",
    [
        (Distro.UBUNTU, "apt", "ufw"),
        (Distro.DEBIAN, "apt", "ufw"),
        (Distro.FEDORA, "dnf", "firewalld"),
        (Distro.ROCKY, "dnf", "firewalld"),
        (Distro.CENTOS, "dnf", "firewalld"),
    ],
)
def test_get_adapter_returns_correct_tools(distro, expected_pkg_mgr, expected_firewall):
    adapter = get_adapter(distro)
    assert adapter.distro == distro
    assert adapter.package_manager == expected_pkg_mgr
    assert adapter.firewall_tool == expected_firewall


def test_get_adapter_unknown_distro_falls_back_safely():
    adapter = get_adapter(Distro.UNKNOWN)
    assert adapter.distro == Distro.UNKNOWN
    assert adapter.firewall_tool == "iptables"
    assert adapter.service_manager == "systemd"


def test_all_adapters_share_standard_paths_by_default():
    for distro in [Distro.UBUNTU, Distro.DEBIAN, Distro.FEDORA, Distro.ROCKY, Distro.CENTOS]:
        adapter = get_adapter(distro)
        assert adapter.sudoers_path == "/etc/sudoers"
        assert adapter.ssh_config_path == "/etc/ssh/sshd_config"
