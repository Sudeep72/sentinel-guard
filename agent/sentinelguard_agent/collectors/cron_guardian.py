"""Cron Guardian — audits cron jobs and startup scripts.

Checks system cron directories and the spool directory for:
- World-writable cron files (injection risk)
- Unexpected permissions on cron directories
- Cron scripts that are world-writable
- Root crontabs that reference world-writable scripts

Follows the same pattern as ``permission_guardian.py`` (reference).
"""

from __future__ import annotations

import logging

from sentinelguard_contracts import Finding, GuardianCategory, Severity

from sentinelguard_agent.collectors.base import BaseGuardian
from sentinelguard_agent.collectors.utils import (
    file_mode_octal,
    is_world_writable,
    path_exists,
    read_file,
    walk_directory,
)

logger = logging.getLogger(__name__)

# System cron directories and their expected modes
CRON_DIR_CHECKS: list[tuple[str, str]] = [
    ("/etc/cron.d", "0o755"),
    ("/etc/cron.daily", "0o755"),
    ("/etc/cron.hourly", "0o755"),
    ("/etc/cron.monthly", "0o755"),
    ("/etc/cron.weekly", "0o755"),
    ("/etc/crontab", "0o644"),
]

# Cron job directories to scan for world-writable files
CRON_SCAN_DIRS: list[str] = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.monthly",
    "/etc/cron.weekly",
]

# User spool directory
CRON_SPOOL_DIR = "/var/spool/cron"
AT_SPOOL_DIR = "/var/spool/at"


class CronGuardian(BaseGuardian):
    """Audits cron jobs and startup scripts for security issues."""

    category = GuardianCategory.CRON

    def _collect(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_cron_directory_permissions())
        findings.extend(self._check_world_writable_cron_files())
        findings.extend(self._check_crontab_scripts())
        findings.extend(self._check_spool_permissions())
        return findings

    # ------------------------------------------------------------------
    # Directory permission checks
    # ------------------------------------------------------------------

    def _check_cron_directory_permissions(self) -> list[Finding]:
        """Check that cron directories/files have safe permissions."""
        findings: list[Finding] = []
        for path_str, expected_mode in CRON_DIR_CHECKS:
            if not path_exists(path_str):
                continue
            current = file_mode_octal(path_str)
            if current is None:
                continue
            if current != expected_mode:
                findings.append(
                    Finding(
                        check_id="CRON-001",
                        module=GuardianCategory.CRON,
                        title=f"Insecure permissions on cron path: {path_str}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"{path_str} has permissions {current}, " f"expected {expected_mode}."
                        ),
                        why_it_matters=(
                            "Cron directories with loose permissions allow "
                            "unprivileged users to add or modify cron jobs "
                            "that run as root."
                        ),
                        attack_scenario=(
                            f"A local attacker creates a malicious script in "
                            f"{path_str} (or modifies an existing one) that "
                            "executes as root on the next cron cycle, escalating privileges."
                        ),
                        recommendation=f"chmod {expected_mode.replace('0o0', '')} {path_str}",
                        current_value=current,
                        expected_value=expected_mode,
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # World-writable cron files
    # ------------------------------------------------------------------

    def _check_world_writable_cron_files(self) -> list[Finding]:
        """Find world-writable files inside cron directories."""
        findings: list[Finding] = []
        for cron_dir in CRON_SCAN_DIRS:
            for file_path in walk_directory(cron_dir, max_depth=1):
                if is_world_writable(str(file_path)):
                    mode = file_mode_octal(str(file_path)) or "unknown"
                    findings.append(
                        Finding(
                            check_id="CRON-002",
                            module=GuardianCategory.CRON,
                            title=f"World-writable cron file: {file_path}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"{file_path} is world-writable (mode {mode}). "
                                "Any local user can modify this cron job."
                            ),
                            why_it_matters=(
                                "Cron files that run as root but are writable by "
                                "any user are a direct path to privilege escalation."
                            ),
                            attack_scenario=(
                                f"A local attacker writes a reverse shell command to "
                                f"{file_path}. The next time cron runs this file "
                                "(potentially within a minute), the attacker receives "
                                "a root shell."
                            ),
                            recommendation=(
                                f"chmod o-w {file_path} && chown root:root {file_path}"
                            ),
                            current_value=mode,
                            expected_value="not world-writable",
                        )
                    )
        return findings

    # ------------------------------------------------------------------
    # Crontab script reference checks
    # ------------------------------------------------------------------

    def _check_crontab_scripts(self) -> list[Finding]:
        """Check that scripts referenced in /etc/crontab are not world-writable."""
        findings: list[Finding] = []
        content = read_file("/etc/crontab")
        if content is None:
            return findings

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Extract command field (7th field in standard crontab format)
            parts = stripped.split()
            if len(parts) < 7:
                continue
            cmd = parts[6]
            if cmd.startswith("/") and path_exists(cmd):
                if is_world_writable(cmd):
                    mode = file_mode_octal(cmd) or "unknown"
                    findings.append(
                        Finding(
                            check_id="CRON-003",
                            module=GuardianCategory.CRON,
                            title=f"World-writable script in root crontab: {cmd}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"/etc/crontab schedules {cmd} but {cmd} is "
                                f"world-writable (mode {mode})."
                            ),
                            why_it_matters=(
                                "A script scheduled in root's crontab that is "
                                "world-writable gives any local user the ability "
                                "to inject arbitrary commands that run as root."
                            ),
                            attack_scenario=(
                                f"A local attacker overwrites {cmd} with a malicious "
                                "script. The next cron execution runs it as root, "
                                "giving the attacker a root shell or backdoor."
                            ),
                            recommendation=(f"chmod o-w {cmd} && chown root:root {cmd}"),
                            current_value=f"world-writable at {mode}",
                            expected_value="not world-writable",
                        )
                    )
        return findings

    # ------------------------------------------------------------------
    # Spool directory checks
    # ------------------------------------------------------------------

    def _check_spool_permissions(self) -> list[Finding]:
        """Check cron/at spool directory permissions."""
        findings: list[Finding] = []
        for spool_dir, expected_mode in [
            (CRON_SPOOL_DIR, "0o700"),
            (AT_SPOOL_DIR, "0o700"),
        ]:
            if not path_exists(spool_dir):
                continue
            current = file_mode_octal(spool_dir)
            if current is None:
                continue
            # Allow 0o1700 (sticky bit) variants as well
            if current not in (expected_mode, "0o1700"):
                findings.append(
                    Finding(
                        check_id="CRON-004",
                        module=GuardianCategory.CRON,
                        title=f"Insecure spool directory permissions: {spool_dir}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"{spool_dir} has permissions {current}, " f"expected {expected_mode}."
                        ),
                        why_it_matters=(
                            "The cron/at spool directory stores user crontabs. "
                            "Loose permissions allow one user to read or tamper "
                            "with another user's scheduled jobs."
                        ),
                        attack_scenario=(
                            f"An attacker reads user crontabs in {spool_dir} to "
                            "discover credentials, scripts, or backup jobs that "
                            "contain sensitive information or can be manipulated."
                        ),
                        recommendation=f"chmod 700 {spool_dir} && chown root:root {spool_dir}",
                        current_value=current,
                        expected_value=expected_mode,
                    )
                )
        return findings
