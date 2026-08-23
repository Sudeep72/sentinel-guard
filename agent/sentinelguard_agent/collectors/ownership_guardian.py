"""Ownership Guardian — checks file/directory ownership.

Follows the same pattern as ``permission_guardian.py`` (the reference
implementation).  See that module's module-level docstring for the
full collector pattern description.
"""

from __future__ import annotations

import logging

from sentinelguard_contracts import Finding, GuardianCategory, Severity

from sentinelguard_agent.collectors.base import BaseGuardian
from sentinelguard_agent.collectors.utils import file_owner_ids, walk_directory

logger = logging.getLogger(__name__)

# (path, expected_uid, expected_gid, severity)
# uid/gid of None means "any value is accepted for that field"
_OwnerCheck = tuple[str, int | None, int | None, Severity]

OWNERSHIP_CHECKS: list[_OwnerCheck] = [
    ("/etc/shadow", 0, None, Severity.CRITICAL),
    ("/etc/gshadow", 0, None, Severity.CRITICAL),
    ("/etc/passwd", 0, 0, Severity.HIGH),
    ("/etc/group", 0, 0, Severity.HIGH),
    ("/etc/sudoers", 0, 0, Severity.HIGH),
    ("/etc/ssh/sshd_config", 0, 0, Severity.HIGH),
    ("/boot", 0, 0, Severity.HIGH),
    ("/root", 0, 0, Severity.HIGH),
    ("/var/log", 0, None, Severity.MEDIUM),
]

# Directories to scan for orphaned files (uid/gid with no matching account).
ORPHAN_SCAN_ROOTS: list[str] = ["/etc", "/var/log", "/home"]


class OwnershipGuardian(BaseGuardian):
    """Checks ownership of security-sensitive files and directories."""

    category = GuardianCategory.OWNERSHIP

    def _collect(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_sensitive_ownership())
        findings.extend(self._check_orphaned_files())
        return findings

    def _check_sensitive_ownership(self) -> list[Finding]:
        """Verify that each sensitive path is owned by the expected uid/gid."""
        findings: list[Finding] = []
        for path, expected_uid, expected_gid, severity in OWNERSHIP_CHECKS:
            ids = file_owner_ids(path)
            if ids is None:
                continue
            uid, gid = ids

            uid_wrong = expected_uid is not None and uid != expected_uid
            gid_wrong = expected_gid is not None and gid != expected_gid

            if uid_wrong or gid_wrong:
                expected_str = (
                    f"uid={expected_uid if expected_uid is not None else 'any'}, "
                    f"gid={expected_gid if expected_gid is not None else 'any'}"
                )
                current_str = f"uid={uid}, gid={gid}"
                findings.append(
                    Finding(
                        check_id="OWN-001",
                        module=GuardianCategory.OWNERSHIP,
                        title=f"Incorrect ownership on {path}",
                        severity=severity,
                        description=(
                            f"{path} is owned by {current_str}, "
                            f"but the expected ownership is {expected_str}."
                        ),
                        why_it_matters=(
                            f"Incorrect ownership of {path} may allow a non-root process "
                            "to read, write, or execute a security-critical file, "
                            "bypassing the protection that correct ownership provides."
                        ),
                        attack_scenario=(
                            f"A process running as uid={uid} has implicit access to "
                            f"{path} beyond what permissions alone indicate. If this uid "
                            "is associated with a service that can be exploited, an attacker "
                            "may leverage the incorrect ownership to access or modify "
                            "security-critical data."
                        ),
                        recommendation=(
                            f"Restore ownership: chown "
                            f"{expected_uid if expected_uid is not None else uid}:"
                            f"{expected_gid if expected_gid is not None else gid} {path}"
                        ),
                        current_value=current_str,
                        expected_value=expected_str,
                    )
                )
        return findings

    def _check_orphaned_files(self) -> list[Finding]:
        """Find files whose uid or gid no longer corresponds to any system account."""
        findings: list[Finding] = []
        import grp
        import pwd

        # Build lookup sets once — avoids repeated calls per file
        try:
            valid_uids = {e.pw_uid for e in pwd.getpwall()}
            valid_gids = {e.gr_gid for e in grp.getgrall()}
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to load passwd/group databases: %s", exc)
            return findings

        for root in ORPHAN_SCAN_ROOTS:
            for file_path in walk_directory(root, max_depth=1):
                ids = file_owner_ids(file_path)
                if ids is None:
                    continue
                uid, gid = ids
                uid_orphaned = uid not in valid_uids
                gid_orphaned = gid not in valid_gids

                if uid_orphaned or gid_orphaned:
                    issue = []
                    if uid_orphaned:
                        issue.append(f"uid={uid} has no matching user account")
                    if gid_orphaned:
                        issue.append(f"gid={gid} has no matching group")
                    findings.append(
                        Finding(
                            check_id="OWN-002",
                            module=GuardianCategory.OWNERSHIP,
                            title=f"Orphaned file ownership: {file_path}",
                            severity=Severity.MEDIUM,
                            description=(
                                f"{file_path} is owned by {'; '.join(issue)}. "
                                "This typically indicates a deleted user/group whose "
                                "files were not cleaned up."
                            ),
                            why_it_matters=(
                                "Orphaned files with numeric uid/gid can be claimed by "
                                "a future user or service assigned the same numeric id, "
                                "granting unintended access to potentially sensitive files."
                            ),
                            attack_scenario=(
                                "An attacker creates a new user account that happens to "
                                f"receive uid={uid} (e.g. the next available id). The new "
                                f"account silently gains ownership of {file_path} and any "
                                "other orphaned files with the same uid."
                            ),
                            recommendation=(
                                f"Determine whether {file_path} is still needed. "
                                "If yes, reassign ownership: chown root:root "
                                f"{file_path}. If not, remove it."
                            ),
                            current_value=f"uid={uid}, gid={gid}",
                            expected_value="valid uid and gid with existing accounts",
                        )
                    )
        return findings
