"""Secret Guardian — detects exposed credentials and secrets.

Scans common locations for:
- AWS, Azure, GCP credentials
- GitHub and generic API tokens
- SSH private keys
- .env files with credentials
- Hardcoded passwords and API keys in config files

Follows the same pattern as ``permission_guardian.py`` (reference).
All matched values are redacted before being stored as finding
``current_value`` — no live credential is persisted verbatim.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sentinelguard_contracts import Finding, GuardianCategory, Severity

from sentinelguard_agent.collectors.base import BaseGuardian
from sentinelguard_agent.collectors.utils import (
    read_file,
    scan_content_for_patterns,
    walk_directory,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scan targets
# ---------------------------------------------------------------------------

# Directories to recursively scan for secrets (limited depth to stay fast)
SECRET_SCAN_DIRS: list[tuple[str, int]] = [
    ("/root", 3),
    ("/home", 3),
    ("/etc", 2),
    ("/opt", 2),
    ("/var/www", 3),
    ("/srv", 3),
]

# File extensions to skip (binary/non-text formats unlikely to hold plaintext secrets)
_SKIP_EXTENSIONS: frozenset[str] = frozenset(
    [
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".ico",
        ".svg",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".so",
        ".a",
        ".o",
        ".pyc",
        ".pyo",
        ".class",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
    ]
)

# Maximum file size to scan (skip large files — most secrets are in small config files)
_MAX_FILE_SIZE_BYTES = 1024 * 512  # 512 KB

# ---------------------------------------------------------------------------
# Secret patterns
# Each tuple: (label, regex with one capture group for the value)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, str]] = [
    # AWS
    (
        "AWS Access Key ID",
        r"(?:AKIA|AIPA|AGPA|AROA|ASCA|AKIA)[0-9A-Z]{16}",
    ),
    (
        "AWS Secret Access Key",
        r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\"':\s=]+([A-Za-z0-9/+=]{40})",
    ),
    # Azure
    (
        "Azure Storage Key",
        r"AccountKey=([A-Za-z0-9+/=]{88})",
    ),
    (
        "Azure Client Secret",
        r"(?i)azure[_\-]?client[_\-]?secret[\"':\s=]+([A-Za-z0-9~._\-]{34,40})",
    ),
    # GCP
    (
        "GCP API Key",
        r"(?i)(?:gcp|google)[_\-]?api[_\-]?key[\"':\s=]+([A-Za-z0-9_\-]{39})",
    ),
    (
        "GCP Service Account JSON key",
        r'"private_key_id"\s*:\s*"([a-f0-9]{40})"',
    ),
    # GitHub
    (
        "GitHub Personal Access Token",
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
    ),
    (
        "GitHub OAuth Token",
        r"(?i)github[_\-\s]?(?:token|secret|key)[\"':\s=]+([A-Za-z0-9_]{40})",
    ),
    # Generic API tokens
    (
        "Generic API Key",
        r"(?i)api[_\-\s]?key[\"':\s=]+[\"']?([A-Za-z0-9_\-]{32,64})[\"']?",
    ),
    (
        "Generic Bearer Token",
        r"(?i)bearer\s+([A-Za-z0-9_\-\.=+/]{40,})",
    ),
    # Passwords
    (
        "Hardcoded Password",
        r"(?i)password[\"':\s=]+[\"']([^\"'\s]{8,64})[\"']",
    ),
    (
        "Hardcoded DB Password",
        r"(?i)db[_\-]?pass(?:word)?[\"':\s=]+[\"']([^\"'\s]{8,64})[\"']",
    ),
    # Slack
    (
        "Slack Token",
        r"xox[baprs]-(?:[0-9a-zA-Z]{10,48})",
    ),
    # SendGrid
    (
        "SendGrid API Key",
        r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    ),
    # Stripe
    (
        "Stripe Secret Key",
        r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
    ),
    # Private keys (PEM headers)
    (
        "RSA Private Key",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----",
    ),
    (
        "PGP Private Key",
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ),
]

# .env file detection — look for assignment patterns with secrets
_ENV_PATTERNS: list[tuple[str, str]] = [
    ("Env secret key", r"(?i)(?:secret|token|password|key|pass)[A-Z_]*\s*=\s*(.{8,128})"),
]

# SSH private key file indicators
_SSH_KEY_HEADERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
)


class SecretGuardian(BaseGuardian):
    """Scans the filesystem for exposed credentials and secrets."""

    category = GuardianCategory.SECRET

    def _collect(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_for_ssh_private_keys())
        findings.extend(self._scan_for_env_files())
        findings.extend(self._scan_for_secrets_in_files())
        return findings

    # ------------------------------------------------------------------
    # SSH private key detection
    # ------------------------------------------------------------------

    def _scan_for_ssh_private_keys(self) -> list[Finding]:
        """Find SSH private key files in home directories and /etc/ssh."""
        findings: list[Finding] = []
        scan_roots = ["/root/.ssh", "/etc/ssh"] + self._home_ssh_dirs()

        for root in scan_roots:
            for file_path in walk_directory(root, max_depth=1):
                content = read_file(file_path)
                if content is None:
                    continue
                for header in _SSH_KEY_HEADERS:
                    if header in content:
                        from sentinelguard_agent.collectors.utils import file_mode_octal

                        mode = file_mode_octal(str(file_path)) or "unknown"
                        findings.append(
                            Finding(
                                check_id="SECRET-001",
                                module=GuardianCategory.SECRET,
                                title=f"SSH private key file exposed: {file_path}",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"An unencrypted SSH private key was found at "
                                    f"{file_path} (mode {mode})."
                                ),
                                why_it_matters=(
                                    "An exposed SSH private key allows anyone who can "
                                    "read it to authenticate as the key's owner to any "
                                    "system that trusts the corresponding public key — "
                                    "without needing a password."
                                ),
                                attack_scenario=(
                                    f"An attacker with read access to {file_path} "
                                    "copies the private key and uses it to authenticate "
                                    "to every server that has the corresponding public "
                                    "key in its authorized_keys."
                                ),
                                recommendation=(
                                    f"Ensure {file_path} has mode 600 and is owned by "
                                    "the intended user only. Rotate the key if it may "
                                    "have been accessed by an unauthorized party. "
                                    "Consider passphrase-protecting private keys."
                                ),
                                current_value=f"unencrypted key found, mode={mode}",
                                expected_value="key accessible only by owner (mode 600)",
                            )
                        )
                        break  # one finding per file
        return findings

    # ------------------------------------------------------------------
    # .env file detection
    # ------------------------------------------------------------------

    def _scan_for_env_files(self) -> list[Finding]:
        """Find .env files that contain credential assignments."""
        findings: list[Finding] = []

        for root, max_depth in SECRET_SCAN_DIRS:
            for file_path in walk_directory(root, max_depth=max_depth):
                name = file_path.name.lower()
                if not (name == ".env" or name.startswith(".env.")):
                    continue

                content = read_file(file_path)
                if content is None:
                    continue

                matches = scan_content_for_patterns(content, _ENV_PATTERNS)
                if matches:
                    labels = [label for label, _, _ in matches]
                    redacted_samples = [red for _, _, red in matches[:3]]
                    findings.append(
                        Finding(
                            check_id="SECRET-002",
                            module=GuardianCategory.SECRET,
                            title=f".env file with secrets detected: {file_path}",
                            severity=Severity.HIGH,
                            description=(
                                f"{file_path} contains what appear to be credentials: "
                                f"{', '.join(set(labels))}."
                            ),
                            why_it_matters=(
                                ".env files commonly store database credentials, API "
                                "keys, and service tokens. If readable by unauthorized "
                                "users or committed to version control, they expose "
                                "all those credentials at once."
                            ),
                            attack_scenario=(
                                f"An attacker reads {file_path} and extracts database "
                                "credentials, API tokens, and encryption secrets, "
                                "gaining access to all connected services."
                            ),
                            recommendation=(
                                f"Restrict permissions: chmod 600 {file_path}. "
                                "Ensure .env is in .gitignore. Consider using a "
                                "secrets manager instead of plaintext .env files."
                            ),
                            current_value=f"found: {'; '.join(redacted_samples)}",
                            expected_value="no secrets in .env files, or files not readable",
                        )
                    )
        return findings

    # ------------------------------------------------------------------
    # General secret pattern scanning
    # ------------------------------------------------------------------

    def _scan_for_secrets_in_files(self) -> list[Finding]:
        """Scan config and script files for known secret patterns."""
        findings: list[Finding] = []

        for root, max_depth in SECRET_SCAN_DIRS:
            for file_path in walk_directory(root, max_depth=max_depth):
                if not self._should_scan_file(file_path):
                    continue

                content = read_file(file_path)
                if content is None:
                    continue

                matches = scan_content_for_patterns(content, SECRET_PATTERNS)
                for label, _raw, redacted in matches:
                    severity = self._severity_for_label(label)
                    findings.append(
                        Finding(
                            check_id="SECRET-003",
                            module=GuardianCategory.SECRET,
                            title=f"Potential {label} in {file_path}",
                            severity=severity,
                            description=(f"A pattern matching a {label} was found in {file_path}."),
                            why_it_matters=(
                                f"A {label} stored in a plaintext file on the host "
                                "can be read by any user or process with access to "
                                "that file, or captured in backups, logs, and "
                                "container images."
                            ),
                            attack_scenario=(
                                f"An attacker with read access to {file_path} "
                                f"extracts the {label} and uses it to access the "
                                "corresponding service, potentially leading to data "
                                "exfiltration, compute abuse (cloud keys), or "
                                "supply-chain attacks (GitHub tokens)."
                            ),
                            recommendation=(
                                "Remove the credential from the file immediately. "
                                "Rotate the compromised key/token/password. "
                                "Use a secrets manager or environment-variable "
                                "injection instead of plaintext files."
                            ),
                            current_value=redacted,
                            expected_value="no secrets in plaintext files",
                        )
                    )
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _home_ssh_dirs(self) -> list[str]:
        """Return ~/.ssh directories for all home users."""
        dirs = []
        home_root = Path("/home")
        if home_root.is_dir():
            try:
                for user_dir in home_root.iterdir():
                    ssh_dir = user_dir / ".ssh"
                    if ssh_dir.is_dir():
                        dirs.append(str(ssh_dir))
            except PermissionError:
                pass
        return dirs

    def _should_scan_file(self, file_path: Path) -> bool:
        """Return True if this file is worth scanning for secrets."""
        ext = file_path.suffix.lower()
        if ext in _SKIP_EXTENSIONS:
            return False
        try:
            size = file_path.stat().st_size
            if size > _MAX_FILE_SIZE_BYTES:
                return False
            if size == 0:
                return False
        except OSError:
            return False
        return True

    def _severity_for_label(self, label: str) -> Severity:
        """Map secret type to severity."""
        critical_labels = {
            "AWS Access Key ID",
            "AWS Secret Access Key",
            "Azure Storage Key",
            "Azure Client Secret",
            "GCP API Key",
            "GCP Service Account JSON key",
            "RSA Private Key",
            "PGP Private Key",
            "SSH Private Key",
        }
        high_labels = {
            "GitHub Personal Access Token",
            "GitHub OAuth Token",
            "Stripe Secret Key",
            "Hardcoded DB Password",
        }
        if label in critical_labels:
            return Severity.CRITICAL
        if label in high_labels:
            return Severity.HIGH
        return Severity.MEDIUM
