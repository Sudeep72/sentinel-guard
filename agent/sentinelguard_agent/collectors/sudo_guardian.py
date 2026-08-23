"""Sudo Guardian — audits sudo configuration for dangerous rules.

Checks ``/etc/sudoers`` and every file under ``/etc/sudoers.d/``.
Follows the same pattern as ``permission_guardian.py`` (reference).
"""

from __future__ import annotations

import logging
from pathlib import Path

from sentinelguard_contracts import Finding, GuardianCategory, Severity

from sentinelguard_agent.collectors.base import BaseGuardian
from sentinelguard_agent.collectors.utils import (
    file_mode_octal,
    is_world_writable,
    parse_sudoers_lines,
    path_exists,
    read_file,
)

logger = logging.getLogger(__name__)

SUDOERS_PATH = "/etc/sudoers"
SUDOERS_D_PATH = "/etc/sudoers.d"

# Expected permission for sudoers files: 0440 (read-only, root:root/root:sudo)
EXPECTED_SUDOERS_MODE = "0o440"


class SudoGuardian(BaseGuardian):
    """Audits sudo configuration for dangerous rules and permissions."""

    category = GuardianCategory.SUDO

    def _collect(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_sudoers_permissions())
        findings.extend(self._check_sudoers_rules())
        return findings

    # ------------------------------------------------------------------
    # Permission checks
    # ------------------------------------------------------------------

    def _check_sudoers_permissions(self) -> list[Finding]:
        """Ensure sudoers files have safe permissions and are not world-writable."""
        findings: list[Finding] = []

        for path_str in self._all_sudoers_paths():
            if not path_exists(path_str):
                continue

            mode = file_mode_octal(path_str)
            if mode and mode != EXPECTED_SUDOERS_MODE:
                findings.append(
                    Finding(
                        check_id="SUDO-001",
                        module=GuardianCategory.SUDO,
                        title=f"Insecure permissions on sudoers file: {path_str}",
                        severity=Severity.HIGH,
                        description=(
                            f"{path_str} has permissions {mode}, "
                            f"expected {EXPECTED_SUDOERS_MODE}."
                        ),
                        why_it_matters=(
                            "Sudoers files with loose permissions can be read by "
                            "unprivileged users, exposing the exact privilege-escalation "
                            "paths available on the system."
                        ),
                        attack_scenario=(
                            f"A local attacker reads {path_str} to learn which "
                            "commands are available without a password, then exploits "
                            "those rules for privilege escalation."
                        ),
                        recommendation=f"chmod 0440 {path_str}",
                        current_value=mode,
                        expected_value=EXPECTED_SUDOERS_MODE,
                    )
                )

            if is_world_writable(path_str):
                findings.append(
                    Finding(
                        check_id="SUDO-002",
                        module=GuardianCategory.SUDO,
                        title=f"World-writable sudoers file: {path_str}",
                        severity=Severity.CRITICAL,
                        description=f"{path_str} is world-writable.",
                        why_it_matters=(
                            "A world-writable sudoers file lets any local user inject "
                            "arbitrary sudo rules, granting themselves root access."
                        ),
                        attack_scenario=(
                            f"An unprivileged attacker appends 'attacker ALL=(ALL) NOPASSWD:ALL' "
                            f"to {path_str} and immediately gains root via sudo."
                        ),
                        recommendation=f"chmod 0440 {path_str} && chown root:root {path_str}",
                        current_value="world-writable",
                        expected_value="not world-writable (mode 0440)",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Rule content checks
    # ------------------------------------------------------------------

    def _check_sudoers_rules(self) -> list[Finding]:
        """Scan sudoers content for dangerous privilege grants."""
        findings: list[Finding] = []

        for path_str in self._all_sudoers_paths():
            content = read_file(path_str)
            if content is None:
                continue
            for line in parse_sudoers_lines(content):
                findings.extend(self._check_line(line, path_str))

        return findings

    def _check_line(self, line: str, source: str) -> list[Finding]:
        """Analyse a single (continuation-joined) sudoers rule line."""
        findings: list[Finding] = []
        line_upper = line.upper()

        # NOPASSWD anywhere in a user spec
        if "NOPASSWD" in line_upper and not line_upper.startswith("DEFAULTS"):
            findings.append(
                Finding(
                    check_id="SUDO-003",
                    module=GuardianCategory.SUDO,
                    title="Passwordless sudo rule detected",
                    severity=Severity.HIGH,
                    description=(f"A NOPASSWD rule was found in {source}: " f"{line[:120]}"),
                    why_it_matters=(
                        "NOPASSWD rules mean a user (or an attacker who has compromised "
                        "that account) can escalate to root without knowing any additional "
                        "credential, eliminating the password as a second control."
                    ),
                    attack_scenario=(
                        "An attacker who has compromised a low-privilege account that "
                        "has a NOPASSWD rule immediately gains root by running "
                        "'sudo <command>' — no brute-force of the root password needed."
                    ),
                    recommendation=(
                        "Remove NOPASSWD from sudo rules where possible. "
                        "If it must be used, restrict to specific commands only and "
                        "never to shells or interpreters."
                    ),
                    current_value=line[:200],
                    expected_value="no NOPASSWD rules, or restricted to specific safe commands",
                )
            )

        # ALL=(ALL) ALL — effectively root grant
        if self._is_all_all_rule(line):
            findings.append(
                Finding(
                    check_id="SUDO-004",
                    module=GuardianCategory.SUDO,
                    title="Unrestricted ALL=(ALL) ALL sudo rule",
                    severity=Severity.HIGH,
                    description=(
                        f"An unrestricted ALL=(ALL) ALL rule was found in {source}: "
                        f"{line[:120]}"
                    ),
                    why_it_matters=(
                        "ALL=(ALL) ALL grants a user the ability to run any command "
                        "as any user, making it equivalent to unconditional root access."
                    ),
                    attack_scenario=(
                        "An attacker who compromises an account with ALL=(ALL) ALL "
                        "runs 'sudo su -' or 'sudo bash' to get a root shell, "
                        "bypassing all other access controls."
                    ),
                    recommendation=(
                        "Restrict sudo rules to specific commands. "
                        "Replace ALL=(ALL) ALL with a specific command list, "
                        "e.g. 'user host = /usr/bin/systemctl restart nginx'."
                    ),
                    current_value=line[:200],
                    expected_value="specific command list, not ALL",
                )
            )

        # Shell escapes or dangerous commands
        dangerous = self._find_dangerous_commands(line)
        if dangerous:
            findings.append(
                Finding(
                    check_id="SUDO-005",
                    module=GuardianCategory.SUDO,
                    title=f"Dangerous command in sudo rule: {', '.join(dangerous)}",
                    severity=Severity.HIGH,
                    description=(
                        f"Sudo rule in {source} grants access to commands that "
                        f"allow shell escapes or arbitrary code execution: "
                        f"{', '.join(dangerous)}"
                    ),
                    why_it_matters=(
                        "Commands like vim, less, find, awk, python, perl, and bash "
                        "can be used to escape into a root shell even when only "
                        "that specific command is allowed in the sudo rule."
                    ),
                    attack_scenario=(
                        "An attacker with 'sudo vim /etc/hosts' permission types "
                        "':!bash' inside vim to get a root shell, turning a "
                        "seemingly limited sudo rule into full root access."
                    ),
                    recommendation=(
                        "Remove shell-escapable commands from sudo rules. "
                        "If text-editor access is needed as root, use sudoedit "
                        "instead, which prevents shell escapes."
                    ),
                    current_value=line[:200],
                    expected_value="no shell-escapable commands in sudo rules",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _all_sudoers_paths(self) -> list[str]:
        """Return sudoers + all drop-in file paths."""
        paths = [SUDOERS_PATH]
        sudoers_d = Path(SUDOERS_D_PATH)
        if sudoers_d.is_dir():
            for drop_in in sorted(sudoers_d.iterdir()):
                if drop_in.is_file():
                    paths.append(str(drop_in))
        return paths

    def _is_all_all_rule(self, line: str) -> bool:
        """Return True if line is a user spec granting ALL=(ALL) or ALL=(ALL:ALL)."""
        import re

        # Match patterns like: user ALL=(ALL) ALL or user ALL=(ALL:ALL) ALL
        pattern = r"ALL\s*=\s*\(ALL[^)]*\)\s*ALL"
        return bool(re.search(pattern, line, re.IGNORECASE))

    def _find_dangerous_commands(self, line: str) -> list[str]:
        """Return any shell-escapable commands found in the sudo rule."""
        _DANGEROUS = {
            "vim",
            "vi",
            "nano",
            "less",
            "more",
            "man",
            "find",
            "awk",
            "sed",
            "perl",
            "python",
            "python3",
            "ruby",
            "lua",
            "bash",
            "sh",
            "zsh",
            "ksh",
            "csh",
            "nmap",
            "tcpdump",
            "env",
            "ftp",
            "curl",
            "wget",
        }
        import re

        found: list[str] = []
        # Extract the commands portion (after the last closing paren)
        after_paren = re.split(r"\)", line, maxsplit=1)[-1]
        # Match full paths (/usr/bin/vim) and bare words
        all_tokens = re.findall(r"(/[^\s,]+)|(\b\w+\b)", after_paren)
        for path_token, word_token in all_tokens:
            token = path_token or word_token
            if not token:
                continue
            cmd = Path(token).name.lower()
            if cmd in _DANGEROUS and cmd not in found:
                found.append(cmd)
        return found
