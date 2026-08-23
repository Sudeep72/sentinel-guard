"""Guardian registry — all nine v1 Guardians."""

from __future__ import annotations

from sentinelguard_agent.collectors.base import BaseGuardian
from sentinelguard_agent.collectors.cron_guardian import CronGuardian
from sentinelguard_agent.collectors.docker_guardian import DockerGuardian
from sentinelguard_agent.collectors.firewall_guardian import FirewallGuardian
from sentinelguard_agent.collectors.kernel_guardian import KernelGuardian
from sentinelguard_agent.collectors.ownership_guardian import OwnershipGuardian
from sentinelguard_agent.collectors.permission_guardian import PermissionGuardian
from sentinelguard_agent.collectors.secret_guardian import SecretGuardian
from sentinelguard_agent.collectors.ssh_guardian import SSHGuardian
from sentinelguard_agent.collectors.sudo_guardian import SudoGuardian

GUARDIAN_REGISTRY: list[type[BaseGuardian]] = [
    PermissionGuardian,
    OwnershipGuardian,
    SSHGuardian,
    SudoGuardian,
    CronGuardian,
    SecretGuardian,
    DockerGuardian,
    FirewallGuardian,
    KernelGuardian,
]
