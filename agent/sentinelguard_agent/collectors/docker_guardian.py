"""Docker Guardian — audits Docker daemon and container security.

Checks:
- Docker daemon socket permissions
- Privileged containers
- Containers running as root
- Host namespace sharing (PID, network, IPC)
- Dangerous capabilities (SYS_ADMIN, NET_ADMIN, etc.)
- Docker API exposure over TCP
- Docker daemon configuration (userland-proxy, no-new-privileges, etc.)
- Latest-tag image warnings

Follows the ``permission_guardian.py`` reference pattern.
Docker may not be installed — every check handles that gracefully by
returning an empty list (no Guardian failure) so a scan on a host
without Docker reports ``status=OK`` with no Docker findings, not an
error.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from sentinelguard_contracts import Finding, GuardianCategory, Severity

from sentinelguard_agent.collectors.base import BaseGuardian
from sentinelguard_agent.collectors.utils import (
    file_mode_octal,
    is_world_writable,
    path_exists,
    read_file,
    run_command,
    run_command_json,
)

logger = logging.getLogger(__name__)

DOCKER_SOCKET_PATH = "/var/run/docker.sock"
DOCKER_DAEMON_JSON = "/etc/docker/daemon.json"

# Capabilities that grant near-root access
_DANGEROUS_CAPS: frozenset[str] = frozenset(
    [
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "DAC_READ_SEARCH",
        "SETUID",
        "SETGID",
        "NET_RAW",
        "SYS_RAWIO",
        "SYS_BOOT",
        "MAC_ADMIN",
        "MAC_OVERRIDE",
    ]
)


class DockerGuardian(BaseGuardian):
    """Audits Docker daemon and running container security configuration."""

    category = GuardianCategory.DOCKER

    def _collect(self) -> list[Finding]:
        # If Docker is not installed or socket absent, no findings (not an error)
        if not self._docker_available():
            logger.debug("Docker socket not found or docker CLI unavailable — skipping")
            return []

        findings: list[Finding] = []
        findings.extend(self._check_socket_permissions())
        findings.extend(self._check_tcp_socket_exposure())
        findings.extend(self._check_daemon_config())
        findings.extend(self._check_containers())
        return findings

    # ------------------------------------------------------------------
    # Docker availability
    # ------------------------------------------------------------------

    def _docker_available(self) -> bool:
        return path_exists(DOCKER_SOCKET_PATH) or bool(run_command(["docker", "version"]))

    # ------------------------------------------------------------------
    # Socket permission checks
    # ------------------------------------------------------------------

    def _check_socket_permissions(self) -> list[Finding]:
        findings: list[Finding] = []
        if not path_exists(DOCKER_SOCKET_PATH):
            return findings

        mode = file_mode_octal(DOCKER_SOCKET_PATH)
        if mode is None:
            return findings

        if is_world_writable(DOCKER_SOCKET_PATH):
            findings.append(
                Finding(
                    check_id="DOCKER-001",
                    module=GuardianCategory.DOCKER,
                    title="Docker socket is world-writable",
                    severity=Severity.CRITICAL,
                    description=(
                        f"{DOCKER_SOCKET_PATH} is world-writable (mode {mode}). "
                        "Any local user can control the Docker daemon."
                    ),
                    why_it_matters=(
                        "Write access to the Docker socket is equivalent to root "
                        "access — anyone who can write to it can spawn privileged "
                        "containers, mount the host filesystem, and escape to the host."
                    ),
                    attack_scenario=(
                        "A local attacker runs: docker run -v /:/host --rm -it ubuntu "
                        "chroot /host bash — instantly getting a root shell on the host "
                        "from an unprivileged account."
                    ),
                    recommendation=(
                        "chmod 660 /var/run/docker.sock && "
                        "chown root:docker /var/run/docker.sock. "
                        "Only add users to the docker group who require it."
                    ),
                    current_value=mode,
                    expected_value="not world-writable (660 owned by root:docker)",
                )
            )

        # Check group ownership — should be docker group, not world-accessible
        try:
            import grp

            st = os.stat(DOCKER_SOCKET_PATH)
            try:
                group_name = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                group_name = str(st.st_gid)

            if group_name not in ("docker", "root") and not is_world_writable(DOCKER_SOCKET_PATH):
                findings.append(
                    Finding(
                        check_id="DOCKER-002",
                        module=GuardianCategory.DOCKER,
                        title="Docker socket has unexpected group ownership",
                        severity=Severity.HIGH,
                        description=(
                            f"{DOCKER_SOCKET_PATH} is owned by group '{group_name}'. "
                            "Expected group 'docker' or 'root'."
                        ),
                        why_it_matters=(
                            "Unexpected group ownership of the Docker socket may "
                            "allow unintended users to control the Docker daemon."
                        ),
                        attack_scenario=(
                            f"Any user in the '{group_name}' group can issue Docker "
                            "commands, potentially spawning privileged containers "
                            "and escaping to the host."
                        ),
                        recommendation=(
                            "chown root:docker /var/run/docker.sock && "
                            "chmod 660 /var/run/docker.sock"
                        ),
                        current_value=f"group={group_name}",
                        expected_value="group=docker",
                    )
                )
        except (OSError, ImportError):
            pass

        return findings

    # ------------------------------------------------------------------
    # TCP socket exposure
    # ------------------------------------------------------------------

    def _check_tcp_socket_exposure(self) -> list[Finding]:
        """Check if Docker daemon is listening on an unprotected TCP socket."""
        findings: list[Finding] = []

        # Check daemon.json for tcp hosts
        daemon_cfg = self._load_daemon_json()
        if daemon_cfg:
            hosts = daemon_cfg.get("hosts", [])
            tcp_hosts = [h for h in hosts if isinstance(h, str) and h.startswith("tcp://")]
            for host in tcp_hosts:
                tls_verify = daemon_cfg.get("tlsverify", False)
                severity = Severity.MEDIUM if tls_verify else Severity.CRITICAL
                findings.append(
                    Finding(
                        check_id="DOCKER-003",
                        module=GuardianCategory.DOCKER,
                        title=f"Docker daemon exposed on TCP: {host}",
                        severity=severity,
                        description=(
                            f"Docker daemon is configured to listen on TCP at {host}. "
                            + (
                                "TLS verification is enabled."
                                if tls_verify
                                else "TLS verification is NOT enabled."
                            )
                        ),
                        why_it_matters=(
                            "An unprotected Docker TCP socket is a remote code "
                            "execution vulnerability — any host that can reach the "
                            "port has full Docker API access (equivalent to root)."
                        ),
                        attack_scenario=(
                            "An attacker who can reach the Docker TCP port runs "
                            f"DOCKER_HOST={host} docker run -v /:/host ubuntu "
                            "chroot /host bash to get a remote root shell."
                        ),
                        recommendation=(
                            "Remove TCP hosts from /etc/docker/daemon.json and use "
                            "the Unix socket instead. If TCP is required, enforce "
                            "mutual TLS: set tlsverify=true with client certs."
                        ),
                        current_value=host,
                        expected_value="no TCP socket, or TCP with TLS mutual auth",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Daemon configuration checks
    # ------------------------------------------------------------------

    def _check_daemon_config(self) -> list[Finding]:
        """Check /etc/docker/daemon.json for insecure settings."""
        findings: list[Finding] = []
        daemon_cfg = self._load_daemon_json()

        if daemon_cfg is None:
            # No daemon.json — check if Docker has live config to compare
            return findings

        # no-new-privileges
        if not daemon_cfg.get("no-new-privileges", False):
            findings.append(
                Finding(
                    check_id="DOCKER-004",
                    module=GuardianCategory.DOCKER,
                    title="Docker daemon: no-new-privileges not enforced globally",
                    severity=Severity.MEDIUM,
                    description="no-new-privileges is not set to true in /etc/docker/daemon.json.",
                    why_it_matters=(
                        "Without no-new-privileges, processes inside containers can "
                        "use setuid/setgid binaries to gain additional capabilities, "
                        "making container breakouts easier."
                    ),
                    attack_scenario=(
                        "A containerized process exploits a setuid binary inside "
                        "the container to escalate privileges and escape the "
                        "container namespace."
                    ),
                    recommendation=(
                        "Add '\"no-new-privileges\": true' to /etc/docker/daemon.json "
                        "and restart the Docker daemon."
                    ),
                    current_value="not set",
                    expected_value="true",
                )
            )

        # userland-proxy
        if daemon_cfg.get("userland-proxy", True):
            findings.append(
                Finding(
                    check_id="DOCKER-005",
                    module=GuardianCategory.DOCKER,
                    title="Docker daemon: userland-proxy enabled",
                    severity=Severity.LOW,
                    description="userland-proxy is enabled (or not explicitly disabled).",
                    why_it_matters=(
                        "The userland proxy runs as root and forwards container "
                        "port traffic. Disabling it reduces the attack surface and "
                        "improves performance by using iptables rules directly."
                    ),
                    attack_scenario=(
                        "A vulnerability in the Docker userland proxy process "
                        "could be exploited by network traffic, potentially leading "
                        "to host compromise."
                    ),
                    recommendation=("Set '\"userland-proxy\": false' in /etc/docker/daemon.json."),
                    current_value="true",
                    expected_value="false",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Running container checks
    # ------------------------------------------------------------------

    def _check_containers(self) -> list[Finding]:
        """Inspect all running containers for dangerous configurations."""
        findings: list[Finding] = []

        container_ids = self._get_running_container_ids()
        for cid in container_ids:
            inspect = self._inspect_container(cid)
            if inspect is None:
                continue
            findings.extend(self._check_privileged(inspect, cid))
            findings.extend(self._check_host_namespaces(inspect, cid))
            findings.extend(self._check_dangerous_capabilities(inspect, cid))
            findings.extend(self._check_root_user(inspect, cid))
            findings.extend(self._check_host_mounts(inspect, cid))
            findings.extend(self._check_latest_tag(inspect, cid))

        return findings

    def _get_running_container_ids(self) -> list[str]:
        output = run_command(["docker", "ps", "-q", "--no-trunc"])
        if not output:
            return []
        return [cid.strip() for cid in output.splitlines() if cid.strip()]

    def _inspect_container(self, container_id: str) -> dict[str, Any] | None:
        result = run_command_json(["docker", "inspect", container_id])
        if isinstance(result, list) and result:
            return result[0]
        return None

    def _get_container_name(self, inspect: dict[str, Any]) -> str:
        name = inspect.get("Name", "unknown")
        return str(name).lstrip("/")

    def _check_privileged(self, inspect: dict[str, Any], cid: str) -> list[Finding]:
        host_config = inspect.get("HostConfig", {})
        if not host_config.get("Privileged", False):
            return []
        name = self._get_container_name(inspect)
        return [
            Finding(
                check_id="DOCKER-006",
                module=GuardianCategory.DOCKER,
                title=f"Privileged container running: {name}",
                severity=Severity.CRITICAL,
                description=f"Container '{name}' ({cid[:12]}) is running in privileged mode.",
                why_it_matters=(
                    "Privileged containers have full access to all host devices, "
                    "bypass all seccomp/AppArmor/SELinux restrictions, and can "
                    "load kernel modules — they are effectively root on the host."
                ),
                attack_scenario=(
                    f"An attacker who exploits a vulnerability in the '{name}' "
                    "container immediately has root access to the host with no "
                    "further privilege escalation required."
                ),
                recommendation=(
                    "Remove --privileged from the container run command. "
                    "Grant only the specific capabilities the container needs "
                    "using --cap-add."
                ),
                current_value="privileged=true",
                expected_value="privileged=false",
            )
        ]

    def _check_host_namespaces(self, inspect: dict[str, Any], cid: str) -> list[Finding]:
        findings: list[Finding] = []
        host_config = inspect.get("HostConfig", {})
        name = self._get_container_name(inspect)

        checks = [
            ("PidMode", "host", "DOCKER-007", "host PID namespace", "host PID namespace sharing"),
            ("NetworkMode", "host", "DOCKER-008", "host network namespace", "host network mode"),
            ("IpcMode", "host", "DOCKER-009", "host IPC namespace", "host IPC namespace sharing"),
        ]

        for config_key, host_value, check_id, label, title_suffix in checks:
            if host_config.get(config_key, "") == host_value:
                findings.append(
                    Finding(
                        check_id=check_id,
                        module=GuardianCategory.DOCKER,
                        title=f"Container using {title_suffix}: {name}",
                        severity=Severity.HIGH,
                        description=(
                            f"Container '{name}' ({cid[:12]}) shares the {label} with the host."
                        ),
                        why_it_matters=(
                            f"Sharing the {label} breaks the container isolation boundary. "
                            "The container can see and interact with host processes or "
                            "network interfaces, facilitating privilege escalation or "
                            "lateral movement."
                        ),
                        attack_scenario=(
                            f"A process inside '{name}' uses the shared {label} to "
                            "access host resources (e.g. sending signals to host PIDs, "
                            "sniffing host network traffic) and escapes the container."
                        ),
                        recommendation=(
                            f"Remove the --{config_key.lower().replace('mode','')}=host "
                            "flag from the container configuration."
                        ),
                        current_value=host_value,
                        expected_value="isolated (default)",
                    )
                )
        return findings

    def _check_dangerous_capabilities(self, inspect: dict[str, Any], cid: str) -> list[Finding]:
        findings: list[Finding] = []
        host_config = inspect.get("HostConfig", {})
        added_caps = host_config.get("CapAdd") or []
        name = self._get_container_name(inspect)

        dangerous_found = [cap for cap in added_caps if cap.upper() in _DANGEROUS_CAPS]
        if dangerous_found:
            findings.append(
                Finding(
                    check_id="DOCKER-010",
                    module=GuardianCategory.DOCKER,
                    title=f"Container has dangerous capabilities: {name}",
                    severity=Severity.HIGH,
                    description=(
                        f"Container '{name}' ({cid[:12]}) has been granted dangerous "
                        f"capabilities: {', '.join(dangerous_found)}"
                    ),
                    why_it_matters=(
                        "Capabilities like SYS_ADMIN, NET_ADMIN, and SYS_PTRACE grant "
                        "powers that break container isolation — they allow kernel "
                        "interactions, reading host memory, and loading kernel modules."
                    ),
                    attack_scenario=(
                        f"A process in '{name}' exploits SYS_ADMIN to mount the host "
                        "filesystem, or uses SYS_PTRACE to read memory of host processes, "
                        "leading to full host compromise."
                    ),
                    recommendation=(
                        "Remove unnecessary capabilities. If a capability is truly "
                        "required, document why and review alternatives. Never grant "
                        "SYS_ADMIN unless absolutely unavoidable."
                    ),
                    current_value=", ".join(dangerous_found),
                    expected_value="no dangerous capabilities",
                )
            )
        return findings

    def _check_root_user(self, inspect: dict[str, Any], cid: str) -> list[Finding]:
        config = inspect.get("Config", {})
        user = config.get("User", "")
        name = self._get_container_name(inspect)

        # Empty user means root (Docker default)
        if user in ("", "0", "root"):
            return [
                Finding(
                    check_id="DOCKER-011",
                    module=GuardianCategory.DOCKER,
                    title=f"Container running as root: {name}",
                    severity=Severity.HIGH,
                    description=(
                        f"Container '{name}' ({cid[:12]}) is running as root "
                        f"(user='{user or 'root (default)'}')."
                    ),
                    why_it_matters=(
                        "Running containers as root means any process inside that "
                        "escapes the container namespace is already root on the host. "
                        "A non-root user inside the container limits blast radius."
                    ),
                    attack_scenario=(
                        "A vulnerability in the containerized application gives the "
                        f"attacker a shell inside '{name}'. Because the container "
                        "runs as root, the attacker maps to host root uid=0, "
                        "making container escape immediately catastrophic."
                    ),
                    recommendation=(
                        "Add a USER directive to the Dockerfile and run as a "
                        "non-root user. Use --user flag or user: in docker-compose."
                    ),
                    current_value=f"user={user or 'root'}",
                    expected_value="non-root user",
                )
            ]
        return []

    def _check_host_mounts(self, inspect: dict[str, Any], cid: str) -> list[Finding]:
        findings: list[Finding] = []
        name = self._get_container_name(inspect)
        mounts = inspect.get("Mounts", [])

        dangerous_mounts = [
            m
            for m in mounts
            if isinstance(m, dict)
            and m.get("Type") == "bind"
            and str(m.get("Source", "")).startswith("/")
            and str(m.get("Source", ""))
            in (
                "/",
                "/etc",
                "/root",
                "/var",
                "/proc",
                "/sys",
                "/dev",
                "/boot",
                "/usr",
                "/bin",
                "/sbin",
                "/lib",
                "/lib64",
            )
        ]

        for mount in dangerous_mounts:
            source = mount.get("Source", "unknown")
            dest = mount.get("Destination", "unknown")
            findings.append(
                Finding(
                    check_id="DOCKER-012",
                    module=GuardianCategory.DOCKER,
                    title=f"Dangerous host mount in container: {name} ({source})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Container '{name}' ({cid[:12]}) mounts the sensitive "
                        f"host path '{source}' at '{dest}'."
                    ),
                    why_it_matters=(
                        f"Mounting '{source}' gives the container read/write access "
                        "to critical host directories, effectively bypassing the "
                        "container isolation boundary."
                    ),
                    attack_scenario=(
                        f"A process inside '{name}' writes to '{dest}' (host '{source}'), "
                        "modifying critical host files (e.g. /etc/passwd, SSH keys, "
                        "cron jobs) to establish persistence or escalate privileges."
                    ),
                    recommendation=(
                        f"Remove the '{source}' bind mount. Use named Docker volumes "
                        "or mount only specific files/directories that the container "
                        "legitimately requires."
                    ),
                    current_value=f"{source} -> {dest}",
                    expected_value="no sensitive host directory mounts",
                )
            )
        return findings

    def _check_latest_tag(self, inspect: dict[str, Any], cid: str) -> list[Finding]:
        config = inspect.get("Config", {})
        image = config.get("Image", "")
        name = self._get_container_name(inspect)

        if image.endswith(":latest") or (":" not in image):
            return [
                Finding(
                    check_id="DOCKER-013",
                    module=GuardianCategory.DOCKER,
                    title=f"Container using 'latest' image tag: {name}",
                    severity=Severity.LOW,
                    description=(
                        f"Container '{name}' ({cid[:12]}) uses image '{image}' "
                        "which has no pinned version tag."
                    ),
                    why_it_matters=(
                        "The 'latest' tag resolves to whatever was most recently "
                        "pushed to the registry. This makes deployments unpredictable "
                        "and can silently introduce vulnerable or malicious image layers."
                    ),
                    attack_scenario=(
                        "An attacker who can push to the registry (supply-chain attack) "
                        "pushes a malicious ':latest' image. The next container restart "
                        f"automatically runs the malicious image as '{name}'."
                    ),
                    recommendation=(
                        "Pin images to a specific digest or version tag. "
                        f"Replace '{image}' with '{image.split(':')[0]}:<version>'."
                    ),
                    current_value=image,
                    expected_value="pinned version tag (e.g. nginx:1.25.3)",
                )
            ]
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_daemon_json(self) -> dict[str, Any] | None:
        content = read_file(DOCKER_DAEMON_JSON)
        if content is None:
            return None
        try:
            result: dict[str, Any] = json.loads(content)
            return result
        except json.JSONDecodeError:
            logger.debug("Invalid JSON in %s", DOCKER_DAEMON_JSON)
            return None
