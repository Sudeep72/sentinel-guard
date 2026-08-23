"""Per-distro adapters: the paths and tool names that differ across
Ubuntu/Debian/Fedora/Rocky/CentOS, so Guardian collectors (Phases 8-16)
can stay distro-agnostic by asking the adapter instead of hardcoding
paths.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinelguard_contracts import Distro


@dataclass(frozen=True)
class DistroAdapter:
    """Distro-specific facts a Guardian may need.

    Attributes:
        distro: Which distro this adapter describes.
        package_manager: Primary package manager binary name.
        service_manager: Init/service manager (systemd for all v1-supported distros).
        firewall_tool: Default firewall front-end for this distro family.
        sudoers_path: Path to the main sudoers file.
        sudoers_d_path: Path to the sudoers drop-in directory.
        ssh_config_path: Path to the sshd server config.
    """

    distro: Distro
    package_manager: str
    service_manager: str
    firewall_tool: str
    sudoers_path: str = "/etc/sudoers"
    sudoers_d_path: str = "/etc/sudoers.d"
    ssh_config_path: str = "/etc/ssh/sshd_config"


_ADAPTERS: dict[Distro, DistroAdapter] = {
    Distro.UBUNTU: DistroAdapter(
        distro=Distro.UBUNTU, package_manager="apt", service_manager="systemd", firewall_tool="ufw"
    ),
    Distro.DEBIAN: DistroAdapter(
        distro=Distro.DEBIAN, package_manager="apt", service_manager="systemd", firewall_tool="ufw"
    ),
    Distro.FEDORA: DistroAdapter(
        distro=Distro.FEDORA,
        package_manager="dnf",
        service_manager="systemd",
        firewall_tool="firewalld",
    ),
    Distro.ROCKY: DistroAdapter(
        distro=Distro.ROCKY,
        package_manager="dnf",
        service_manager="systemd",
        firewall_tool="firewalld",
    ),
    Distro.CENTOS: DistroAdapter(
        distro=Distro.CENTOS,
        package_manager="dnf",
        service_manager="systemd",
        firewall_tool="firewalld",
    ),
}

_UNKNOWN_ADAPTER = DistroAdapter(
    distro=Distro.UNKNOWN,
    package_manager="unknown",
    service_manager="systemd",
    firewall_tool="iptables",
)


def get_adapter(distro: Distro) -> DistroAdapter:
    """Return the adapter for a distro, falling back to a conservative
    default (systemd + iptables + standard paths) for UNKNOWN."""
    return _ADAPTERS.get(distro, _UNKNOWN_ADAPTER)
