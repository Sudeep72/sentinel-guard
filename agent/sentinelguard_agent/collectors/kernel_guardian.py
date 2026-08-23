"""Kernel Guardian — audits kernel security configuration and sysctl hardening.

Checks:
- KERNEL-001: ASLR (kernel.randomize_va_space)
- KERNEL-002: ptrace scope (kernel.yama.ptrace_scope)
- KERNEL-003: core dump restrictions (fs.suid_dumpable)
- KERNEL-004: dmesg restrictions (kernel.dmesg_restrict)
- KERNEL-005: kexec restrictions (kernel.kexec_load_disabled)
- KERNEL-006: IPv4 forwarding (net.ipv4.ip_forward)
- KERNEL-007: SYN flood protection (net.ipv4.tcp_syncookies)
- KERNEL-008: ICMP redirect acceptance
- KERNEL-009: Source routing
- KERNEL-010: IPv6 router advertisements
- KERNEL-011: Kernel pointer exposure (kernel.kptr_restrict)
- KERNEL-012: Unprivileged BPF access
- KERNEL-013: Kernel version check (EOL detection)

Follows the ``permission_guardian.py`` reference pattern.
"""

from __future__ import annotations

import logging

from sentinelguard_contracts import Finding, GuardianCategory, Severity

from sentinelguard_agent.collectors.base import BaseGuardian
from sentinelguard_agent.collectors.utils import (
    get_kernel_version,
    parse_kernel_version,
    read_sysctl,
    read_sysctl_all,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sysctl security rules
# Each entry: (check_id, key, expected_value, severity, title, why, scenario, rec)
# ---------------------------------------------------------------------------
_SysctlRule = tuple[str, str, str, Severity, str, str, str, str]

SYSCTL_RULES: list[_SysctlRule] = [
    (
        "KERNEL-001",
        "kernel.randomize_va_space",
        "2",
        Severity.HIGH,
        "ASLR is not fully enabled",
        (
            "Address Space Layout Randomization (ASLR) randomizes the memory locations "
            "of the stack, heap, and libraries, making it significantly harder to "
            "exploit memory corruption vulnerabilities."
        ),
        (
            "An attacker exploiting a buffer overflow in a system service needs to "
            "know where libc or the stack is located. Without ASLR, these addresses "
            "are static and predictable, making exploitation trivial."
        ),
        "sysctl -w kernel.randomize_va_space=2 (persist in /etc/sysctl.d/99-security.conf)",
    ),
    (
        "KERNEL-002",
        "kernel.yama.ptrace_scope",
        "1",
        Severity.MEDIUM,
        "ptrace is unrestricted (scope=0)",
        (
            "The ptrace syscall allows one process to inspect and modify another. "
            "Without restriction, any user can attach to and debug any of their "
            "own processes, enabling credential extraction from process memory."
        ),
        (
            "An attacker with a local shell runs a ptrace-based tool like 'gdb' or "
            "'mimikatz-for-linux' to attach to a running process (e.g. a password "
            "manager or SSH agent) and extract credentials from its memory."
        ),
        "sysctl -w kernel.yama.ptrace_scope=1 (persist in /etc/sysctl.d/99-security.conf)",
    ),
    (
        "KERNEL-003",
        "fs.suid_dumpable",
        "0",
        Severity.MEDIUM,
        "Core dumps allowed for setuid programs (fs.suid_dumpable != 0)",
        (
            "When fs.suid_dumpable is non-zero, setuid programs can produce core "
            "dumps containing sensitive memory contents (passwords, private keys) "
            "that may be readable by the process owner."
        ),
        (
            "A setuid binary (e.g. sudo) crashes or is forced to crash. The resulting "
            "core dump contains the password or sensitive data that was in memory, "
            "readable by the user who triggered the crash."
        ),
        "sysctl -w fs.suid_dumpable=0 (persist in /etc/sysctl.d/99-security.conf)",
    ),
    (
        "KERNEL-004",
        "kernel.dmesg_restrict",
        "1",
        Severity.LOW,
        "Kernel ring buffer (dmesg) readable by unprivileged users",
        (
            "The kernel ring buffer contains information about kernel events, "
            "hardware addresses, and loaded modules that can help attackers map "
            "the system and develop targeted exploits."
        ),
        (
            "An unprivileged attacker runs 'dmesg' to read kernel logs revealing "
            "memory addresses, driver versions, and system configuration that "
            "assist in developing a privilege escalation exploit."
        ),
        "sysctl -w kernel.dmesg_restrict=1 (persist in /etc/sysctl.d/99-security.conf)",
    ),
    (
        "KERNEL-005",
        "kernel.kexec_load_disabled",
        "1",
        Severity.MEDIUM,
        "kexec is not disabled (kernel.kexec_load_disabled=0)",
        (
            "kexec allows loading a new kernel without a full reboot. An attacker "
            "with root access can use it to bypass Secure Boot, replace the running "
            "kernel, or subvert measured boot chains."
        ),
        (
            "A root-level attacker uses kexec to load a malicious kernel, completely "
            "bypassing Secure Boot protections and any integrity measurements taken "
            "during the normal boot process."
        ),
        "sysctl -w kernel.kexec_load_disabled=1 (persist in /etc/sysctl.d/99-security.conf)",
    ),
    (
        "KERNEL-006",
        "net.ipv4.ip_forward",
        "0",
        Severity.LOW,
        "IPv4 forwarding is enabled on a non-router host",
        (
            "IP forwarding allows the host to route packets between interfaces. "
            "On a server that is not acting as a router, this is unnecessary and "
            "can be abused to route traffic through the host."
        ),
        (
            "An attacker on a network segment uses this host as a relay to reach "
            "otherwise isolated internal systems by sending traffic through its "
            "enabled IP forwarding capability."
        ),
        "sysctl -w net.ipv4.ip_forward=0 (unless host is intentionally a router)",
    ),
    (
        "KERNEL-007",
        "net.ipv4.tcp_syncookies",
        "1",
        Severity.HIGH,
        "SYN flood protection (TCP syncookies) is disabled",
        (
            "TCP SYN cookies protect against SYN flood DoS attacks by not allocating "
            "state for each half-open connection until the handshake is completed."
        ),
        (
            "An attacker sends thousands of SYN packets with spoofed source IPs, "
            "exhausting the server's connection queue and making it unreachable "
            "for legitimate connections (SYN flood DoS)."
        ),
        "sysctl -w net.ipv4.tcp_syncookies=1 (persist in /etc/sysctl.d/99-security.conf)",
    ),
    (
        "KERNEL-008",
        "net.ipv4.conf.all.accept_redirects",
        "0",
        Severity.MEDIUM,
        "ICMP redirect acceptance is enabled",
        (
            "Accepting ICMP redirects allows an attacker on the local network to "
            "redirect the host's traffic through a malicious gateway, enabling "
            "man-in-the-middle attacks."
        ),
        (
            "An attacker on the same network segment sends forged ICMP redirect "
            "messages, causing the victim host to send all traffic through the "
            "attacker's machine, enabling traffic interception."
        ),
        "sysctl -w net.ipv4.conf.all.accept_redirects=0 (persist in sysctl.d)",
    ),
    (
        "KERNEL-009",
        "net.ipv4.conf.all.accept_source_route",
        "0",
        Severity.MEDIUM,
        "Source routing is enabled",
        (
            "Source routing allows packets to specify their own route through the "
            "network. This can be used to bypass firewalls by specifying a path "
            "that circumvents security controls."
        ),
        (
            "An attacker sends source-routed packets specifying a path that "
            "bypasses firewall rules, reaching internal services that should be "
            "protected."
        ),
        "sysctl -w net.ipv4.conf.all.accept_source_route=0",
    ),
    (
        "KERNEL-010",
        "net.ipv6.conf.all.accept_ra",
        "0",
        Severity.LOW,
        "IPv6 router advertisements are accepted",
        (
            "Accepting IPv6 router advertisements (RA) can allow a rogue router on "
            "the local network to redirect all IPv6 traffic through an attacker's "
            "machine."
        ),
        (
            "An attacker sends forged IPv6 RA messages, causing the host to use "
            "the attacker's machine as its default IPv6 gateway, enabling full "
            "network traffic interception."
        ),
        "sysctl -w net.ipv6.conf.all.accept_ra=0 (if IPv6 not required, also disable entirely)",
    ),
    (
        "KERNEL-011",
        "kernel.kptr_restrict",
        "2",
        Severity.MEDIUM,
        "Kernel pointer exposure not restricted (kernel.kptr_restrict < 2)",
        (
            "kernel.kptr_restrict controls whether kernel pointers (addresses) can "
            "be read by unprivileged users. Exposed kernel pointers help attackers "
            "bypass KASLR and develop kernel exploits."
        ),
        (
            "An attacker reads /proc/kallsyms or /proc/modules to obtain kernel "
            "symbol addresses, bypassing KASLR and enabling targeted kernel "
            "exploitation."
        ),
        "sysctl -w kernel.kptr_restrict=2 (persist in /etc/sysctl.d/99-security.conf)",
    ),
    (
        "KERNEL-012",
        "kernel.unprivileged_bpf_disabled",
        "1",
        Severity.MEDIUM,
        "Unprivileged BPF access is allowed",
        (
            "BPF (Berkeley Packet Filter) has a long history of kernel vulnerabilities. "
            "Allowing unprivileged access to BPF gives any local user access to a "
            "powerful attack surface against the kernel."
        ),
        (
            "An attacker exploits a BPF vulnerability (e.g. JIT spraying, verifier "
            "bypass) to gain kernel code execution from an unprivileged account."
        ),
        "sysctl -w kernel.unprivileged_bpf_disabled=1 (persist in sysctl.d)",
    ),
]

# Minimum supported kernel versions per distro family
# Major versions older than this are considered EOL
_EOL_KERNEL_MAJOR_MINOR = (4, 14)  # kernels below 4.14 are broadly EOL


class KernelGuardian(BaseGuardian):
    """Audits kernel security configuration via sysctl and version checks."""

    category = GuardianCategory.KERNEL

    def _collect(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_kernel_version())
        findings.extend(self._check_sysctl_rules())
        return findings

    # ------------------------------------------------------------------
    # Kernel version check
    # ------------------------------------------------------------------

    def _check_kernel_version(self) -> list[Finding]:
        """Warn if the running kernel is below the minimum supported version."""
        version_str = get_kernel_version()
        if version_str is None:
            return []

        major, minor, patch = parse_kernel_version(version_str)
        eol_major, eol_minor = _EOL_KERNEL_MAJOR_MINOR

        if (major, minor) < (eol_major, eol_minor):
            return [
                Finding(
                    check_id="KERNEL-013",
                    module=GuardianCategory.KERNEL,
                    title=f"Running kernel version may be EOL: {version_str}",
                    severity=Severity.HIGH,
                    description=(
                        f"The running kernel version {version_str} (parsed as "
                        f"{major}.{minor}.{patch}) is below the broadly supported "
                        f"minimum of {eol_major}.{eol_minor}. It may no longer "
                        "receive security patches."
                    ),
                    why_it_matters=(
                        "EOL kernels no longer receive security patches. Known "
                        "vulnerabilities (including local privilege escalation "
                        "exploits) accumulate without remediation."
                    ),
                    attack_scenario=(
                        "An attacker uses a public local privilege escalation "
                        f"exploit targeting kernels below {eol_major}.{eol_minor} "
                        "(e.g. Dirty COW, DirtyCred) to gain root from an "
                        "unprivileged account."
                    ),
                    recommendation=(
                        "Upgrade to a supported kernel version for your distribution. "
                        "Ubuntu: apt update && apt upgrade linux-generic. "
                        "RHEL/Fedora: dnf update kernel."
                    ),
                    current_value=version_str,
                    expected_value=f">={eol_major}.{eol_minor}",
                )
            ]
        return []

    # ------------------------------------------------------------------
    # Sysctl rule checks
    # ------------------------------------------------------------------

    def _check_sysctl_rules(self) -> list[Finding]:
        """Check each sysctl rule and emit a finding when the value is insecure."""
        findings: list[Finding] = []
        # Read all sysctl values once to avoid spawning a subprocess per key
        all_values = read_sysctl_all()

        for check_id, key, expected, severity, title_suffix, why, scenario, rec in SYSCTL_RULES:
            current = all_values.get(key)
            if current is None:
                # Key not present — try direct read (some keys only exist on
                # specific kernels; absence means "not configured" = insecure default)
                current = read_sysctl(key)

            if current is None:
                # Key truly absent from this kernel — treat as insecure default
                current = "not set (default insecure)"

            current_clean = current.strip()
            expected_clean = expected.strip()

            if current_clean != expected_clean:
                findings.append(
                    Finding(
                        check_id=check_id,
                        module=GuardianCategory.KERNEL,
                        title=f"{title_suffix} ({key}={current_clean}, expected {expected_clean})",
                        severity=severity,
                        description=(
                            f"Sysctl {key} is '{current_clean}', "
                            f"but the secure value is '{expected_clean}'."
                        ),
                        why_it_matters=why,
                        attack_scenario=scenario,
                        recommendation=rec,
                        current_value=current_clean,
                        expected_value=expected_clean,
                    )
                )

        return findings
