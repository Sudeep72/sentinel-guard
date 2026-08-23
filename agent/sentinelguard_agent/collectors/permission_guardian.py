"""Permission Guardian — checks critical file permission bits.

This is the **reference implementation** for all SentinelGuard
Guardian collectors.  Every Guardian follows this pattern:

1.  Declare ``category: GuardianCategory`` at class level.
2.  Implement ``_collect(self) -> list[Finding]`` calling the shared
    utilities in ``collectors/utils.py``.
3.  Each finding carries the full AI-copilot payload: ``check_id``,
    ``title``, ``severity``, ``description``, ``why_it_matters``,
    ``attack_scenario``, ``recommendation``, ``current_value``,
    ``expected_value``.
4.  Raise on unrecoverable setup failures; the ``BaseGuardian.run()``
    wrapper converts them to ``GuardianResult(status=ERROR)`` so the
    overall scan stays ``PARTIAL`` rather than ``FAILED``.

Collector responsibility boundary:
    The collector gathers *raw, observable facts* from the host and
    converts them directly into ``Finding`` objects with preliminary
    severities.  It does **not** compare against per-distro baselines —
    that comparison happens server-side in
    ``dashboard/app/modules/permission/analyzer.py``.  The dashboard
    may upgrade or downgrade a finding's severity based on the baseline;
    the collector's judgment is always the starting point, never the
    final word.
"""

from __future__ import annotations

import logging
import os

from sentinelguard_contracts import Finding, GuardianCategory, Severity

from sentinelguard_agent.collectors.base import BaseGuardian
from sentinelguard_agent.collectors.utils import file_mode_octal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Files the Permission Guardian checks, with their expected safe modes.
# Stored as a list of (path, expected_octal, severity_if_wrong) tuples
# so adding a new check is a one-line change in PERMISSION_CHECKS below.
# ---------------------------------------------------------------------------
_PermCheck = tuple[str, str, Severity]

PERMISSION_CHECKS: list[_PermCheck] = [
    ("/etc/shadow", "0o600", Severity.CRITICAL),
    ("/etc/gshadow", "0o640", Severity.CRITICAL),
    ("/etc/passwd", "0o644", Severity.MEDIUM),
    ("/etc/group", "0o644", Severity.MEDIUM),
    ("/etc/sudoers", "0o440", Severity.HIGH),
    ("/etc/ssh/sshd_config", "0o600", Severity.HIGH),
    ("/boot", "0o700", Severity.HIGH),
    ("/var/log", "0o755", Severity.LOW),
    ("/root", "0o700", Severity.HIGH),
]

# Directories / glob roots to scan for world-writable files.
WORLD_WRITABLE_SCAN_ROOTS: list[str] = [
    "/etc",
    "/var/log",
    "/tmp",
]

# Mode bit constants
_WORLD_WRITABLE = 0o002
_WORLD_READABLE = 0o004
_WORLD_EXECUTABLE = 0o001

_SENSITIVE_WORLD_READABLE: list[tuple[str, Severity]] = [
    ("/etc/shadow", Severity.CRITICAL),
    ("/etc/gshadow", Severity.CRITICAL),
    ("/etc/sudoers", Severity.HIGH),
    ("/etc/ssh/sshd_config", Severity.HIGH),
    ("/etc/passwd", Severity.LOW),
]


class PermissionGuardian(BaseGuardian):
    """Checks permission bits on security-sensitive files and directories."""

    category = GuardianCategory.PERMISSION

    def _collect(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_sensitive_file_permissions())
        findings.extend(self._check_world_writable_sensitive())
        findings.extend(self._check_world_readable_sensitive())
        return findings

    # ------------------------------------------------------------------
    # Individual check methods — each returns 0-N findings
    # ------------------------------------------------------------------

    def _check_sensitive_file_permissions(self) -> list[Finding]:
        """Check that each sensitive path has its expected permission mode."""
        findings: list[Finding] = []
        for path, expected_octal, severity in PERMISSION_CHECKS:
            current = file_mode_octal(path)
            if current is None:
                # Path doesn't exist or we can't stat it — skip.
                continue
            if current != expected_octal:
                findings.append(
                    Finding(
                        check_id="PERM-001",
                        module=GuardianCategory.PERMISSION,
                        title=f"Insecure permissions on {path}",
                        severity=severity,
                        description=(
                            f"{path} has permissions {current}, "
                            f"but the expected secure value is {expected_octal}."
                        ),
                        why_it_matters=(
                            f"Incorrect permissions on {path} may allow unauthorized "
                            "users to read or modify security-critical data, "
                            "potentially leading to privilege escalation or credential theft."
                        ),
                        attack_scenario=(
                            f"A locally authenticated attacker discovers {path} is "
                            f"accessible with mode {current}. Depending on the file, "
                            "this may allow them to read password hashes for offline cracking, "
                            "inject configuration that survives reboots, or tamper with "
                            "authentication policies."
                        ),
                        recommendation=f"Run: chmod {expected_octal.replace('0o', '')} {path}",
                        current_value=current,
                        expected_value=expected_octal,
                    )
                )
        return findings

    def _check_world_writable_sensitive(self) -> list[Finding]:
        """Find world-writable files in sensitive directories."""
        findings: list[Finding] = []
        for root in WORLD_WRITABLE_SCAN_ROOTS:
            from sentinelguard_agent.collectors.utils import walk_directory

            for file_path in walk_directory(root, max_depth=2):
                try:
                    import stat

                    st_result = os.stat(file_path)
                    mode = st_result.st_mode
                    if (mode & _WORLD_WRITABLE) and not stat.S_ISLNK(mode):
                        current = oct(mode & 0o7777)
                        findings.append(
                            Finding(
                                check_id="PERM-002",
                                module=GuardianCategory.PERMISSION,
                                title=f"World-writable file: {file_path}",
                                severity=Severity.HIGH,
                                description=(
                                    f"{file_path} is world-writable (mode {current}). "
                                    "Any local user can modify it."
                                ),
                                why_it_matters=(
                                    "World-writable files in system directories allow "
                                    "any local user to replace or corrupt system files, "
                                    "inject malicious content, or escalate privileges."
                                ),
                                attack_scenario=(
                                    f"A low-privilege attacker writes a malicious payload to "
                                    f"{file_path}. If the file is a script or config read by "
                                    "a privileged process, the attacker gains elevated access."
                                ),
                                recommendation=(
                                    f"Run: chmod o-w {file_path}  "
                                    "Then audit why the file became world-writable."
                                ),
                                current_value=current,
                                expected_value="mode without world-write (o-w)",
                            )
                        )
                except (PermissionError, FileNotFoundError, OSError):
                    continue
        return findings

    def _check_world_readable_sensitive(self) -> list[Finding]:
        """Check that known sensitive files are not world-readable."""
        findings: list[Finding] = []
        for path, severity in _SENSITIVE_WORLD_READABLE:
            current = file_mode_octal(path)
            if current is None:
                continue
            mode_int = int(current, 8)
            if mode_int & _WORLD_READABLE:
                findings.append(
                    Finding(
                        check_id="PERM-003",
                        module=GuardianCategory.PERMISSION,
                        title=f"World-readable sensitive file: {path}",
                        severity=severity,
                        description=(
                            f"{path} is world-readable (mode {current}). "
                            "Its contents can be read by any local user."
                        ),
                        why_it_matters=(
                            f"{path} contains sensitive security data. "
                            "Making it world-readable exposes that data to all local users, "
                            "enabling offline attacks or privilege escalation."
                        ),
                        attack_scenario=(
                            f"Any local user runs `cat {path}` and reads the file's contents. "
                            "For /etc/shadow this means password hashes; for sudoers it reveals "
                            "the exact privilege escalation paths available on this host."
                        ),
                        recommendation=(
                            f"Remove world-read bit: chmod o-r {path}  "
                            "Typical secure mode: "
                            + ("600" if "shadow" in path or "sudoers" in path else "644")
                        ),
                        current_value=current,
                        expected_value="mode without world-read (o-r)",
                    )
                )
        return findings
