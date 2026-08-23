"""SSH Guardian — audits the OpenSSH server configuration.

Follows the same pattern as ``permission_guardian.py`` (the reference
implementation).  Reads and parses ``/etc/ssh/sshd_config`` (and any
``Include`` files on distros that use them) using the shared
``parse_key_value_config`` utility.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sentinelguard_contracts import Finding, GuardianCategory, Severity

from sentinelguard_agent.collectors.base import BaseGuardian
from sentinelguard_agent.collectors.utils import parse_key_value_config, read_file

logger = logging.getLogger(__name__)

SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
SSHD_CONFIG_D_PATH = "/etc/ssh/sshd_config.d"

# ---------------------------------------------------------------------------
# Weak cipher / MAC / key-exchange algorithm lists.
# We check for presence in the *configured* list, so even if only one weak
# algorithm is in a comma-separated Ciphers directive we flag it.
# ---------------------------------------------------------------------------
WEAK_CIPHERS: frozenset[str] = frozenset(
    [
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "blowfish-cbc",
        "cast128-cbc",
        "rijndael-cbc@lysator.liu.se",
    ]
)

WEAK_MACS: frozenset[str] = frozenset(
    [
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1",
        "hmac-sha1-96",
        "umac-64@openssh.com",
        "umac-64-etm@openssh.com",
        "hmac-ripemd160",
        "hmac-ripemd160@openssh.com",
    ]
)

WEAK_KEX: frozenset[str] = frozenset(
    [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "gss-gex-sha1-",
        "gss-group1-sha1-",
        "gss-group14-sha1-",
    ]
)


class SSHGuardian(BaseGuardian):
    """Audits the OpenSSH server daemon configuration."""

    category = GuardianCategory.SSH

    def _collect(self) -> list[Finding]:
        config = self._load_sshd_config()
        if config is None:
            logger.debug("sshd_config not readable — skipping SSH Guardian")
            return []

        findings: list[Finding] = []
        findings.extend(self._check_permit_root_login(config))
        findings.extend(self._check_password_authentication(config))
        findings.extend(self._check_empty_passwords(config))
        findings.extend(self._check_pubkey_authentication(config))
        findings.extend(self._check_weak_ciphers(config))
        findings.extend(self._check_weak_macs(config))
        findings.extend(self._check_protocol_version(config))
        findings.extend(self._check_allow_users_groups(config))
        return findings

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    def _load_sshd_config(self) -> dict[str, str] | None:
        """Load sshd_config, merging any drop-in files from sshd_config.d/."""
        content = read_file(SSHD_CONFIG_PATH)
        if content is None:
            return None

        merged_lines = list(content.splitlines())

        # Merge drop-in directory files (Debian/Ubuntu pattern)
        drop_in = Path(SSHD_CONFIG_D_PATH)
        if drop_in.is_dir():
            for conf_file in sorted(drop_in.glob("*.conf")):
                extra = read_file(conf_file)
                if extra:
                    merged_lines.extend(extra.splitlines())

        return parse_key_value_config("\n".join(merged_lines))

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_permit_root_login(self, config: dict[str, str]) -> list[Finding]:
        value = config.get("PermitRootLogin", "yes").lower()
        # "prohibit-password" and "forced-commands-only" are acceptable.
        if value in ("yes", "without-password"):
            return [
                Finding(
                    check_id="SSH-001",
                    module=GuardianCategory.SSH,
                    title="SSH root login is permitted",
                    severity=Severity.HIGH,
                    description=f"PermitRootLogin is set to '{value}' in sshd_config.",
                    why_it_matters=(
                        "Permitting direct root login over SSH eliminates the audit trail "
                        "provided by su/sudo and removes a key layer of defense — an "
                        "attacker who obtains or guesses the root credential gains "
                        "immediate unrestricted access."
                    ),
                    attack_scenario=(
                        "An attacker with access to a leaked or brute-forced root password "
                        "connects directly via SSH and obtains a root shell with no "
                        "further privilege escalation required."
                    ),
                    recommendation=(
                        "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then "
                        "restart sshd: systemctl restart sshd"
                    ),
                    current_value=value,
                    expected_value="no",
                )
            ]
        return []

    def _check_password_authentication(self, config: dict[str, str]) -> list[Finding]:
        value = config.get("PasswordAuthentication", "yes").lower()
        if value != "no":
            return [
                Finding(
                    check_id="SSH-002",
                    module=GuardianCategory.SSH,
                    title="SSH password authentication is enabled",
                    severity=Severity.HIGH,
                    description=(
                        f"PasswordAuthentication is '{value}'. "
                        "Key-based authentication only is not enforced."
                    ),
                    why_it_matters=(
                        "Password authentication exposes the SSH service to brute-force "
                        "and credential-stuffing attacks. Key-based authentication is "
                        "immune to these attack classes."
                    ),
                    attack_scenario=(
                        "An automated tool performs a credential-stuffing attack against "
                        "port 22 using leaked username/password pairs from data breaches. "
                        "Any user with a weak or reused password can be compromised."
                    ),
                    recommendation=(
                        "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config "
                        "after ensuring all users have SSH keys configured. "
                        "Restart sshd: systemctl restart sshd"
                    ),
                    current_value=value,
                    expected_value="no",
                )
            ]
        return []

    def _check_empty_passwords(self, config: dict[str, str]) -> list[Finding]:
        value = config.get("PermitEmptyPasswords", "no").lower()
        if value == "yes":
            return [
                Finding(
                    check_id="SSH-003",
                    module=GuardianCategory.SSH,
                    title="SSH empty passwords are permitted",
                    severity=Severity.CRITICAL,
                    description="PermitEmptyPasswords is set to 'yes' in sshd_config.",
                    why_it_matters=(
                        "Allowing empty passwords means any account without a password "
                        "set can be logged into over SSH with no credentials at all."
                    ),
                    attack_scenario=(
                        "An attacker attempts SSH logins against every username on the "
                        "system. Any account with an empty password (e.g. a service "
                        "account that was never given a password) is immediately accessible."
                    ),
                    recommendation=(
                        "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config "
                        "and restart sshd. Audit all accounts for empty passwords: "
                        "awk -F: '($2==\"\"){print $1}' /etc/shadow"
                    ),
                    current_value=value,
                    expected_value="no",
                )
            ]
        return []

    def _check_pubkey_authentication(self, config: dict[str, str]) -> list[Finding]:
        value = config.get("PubkeyAuthentication", "yes").lower()
        if value == "no":
            return [
                Finding(
                    check_id="SSH-004",
                    module=GuardianCategory.SSH,
                    title="SSH public key authentication is disabled",
                    severity=Severity.MEDIUM,
                    description="PubkeyAuthentication is set to 'no' in sshd_config.",
                    why_it_matters=(
                        "Disabling public key authentication removes the most secure "
                        "available SSH authentication method, forcing users to rely on "
                        "weaker password-based authentication."
                    ),
                    attack_scenario=(
                        "Without key-based auth, operators cannot migrate away from "
                        "password auth even if they want to. This keeps the service "
                        "exposed to brute-force attacks indefinitely."
                    ),
                    recommendation=(
                        "Set 'PubkeyAuthentication yes' in /etc/ssh/sshd_config "
                        "and restart sshd."
                    ),
                    current_value=value,
                    expected_value="yes",
                )
            ]
        return []

    def _check_weak_ciphers(self, config: dict[str, str]) -> list[Finding]:
        ciphers_str = config.get("Ciphers", "")
        if not ciphers_str:
            return []
        configured = {c.strip().lower() for c in ciphers_str.split(",")}
        found_weak = configured & WEAK_CIPHERS
        if found_weak:
            return [
                Finding(
                    check_id="SSH-005",
                    module=GuardianCategory.SSH,
                    title="SSH configuration includes weak ciphers",
                    severity=Severity.HIGH,
                    description=(
                        f"The following deprecated/weak ciphers are configured: "
                        f"{', '.join(sorted(found_weak))}"
                    ),
                    why_it_matters=(
                        "Weak ciphers such as 3DES-CBC and AES-CBC are vulnerable to "
                        "known attacks (SWEET32, BEAST, Lucky13). An active on-path "
                        "attacker may be able to decrypt SSH session traffic."
                    ),
                    attack_scenario=(
                        "An on-path attacker who can observe the SSH session negotiates "
                        "a weak cipher by manipulating the key exchange and subsequently "
                        "decrypts captured session data."
                    ),
                    recommendation=(
                        "Remove weak ciphers from /etc/ssh/sshd_config. "
                        "Recommended: Ciphers chacha20-poly1305@openssh.com,"
                        "aes128-gcm@openssh.com,aes256-gcm@openssh.com"
                    ),
                    current_value=ciphers_str,
                    expected_value="strong ciphers only (AES-GCM, ChaCha20-Poly1305)",
                )
            ]
        return []

    def _check_weak_macs(self, config: dict[str, str]) -> list[Finding]:
        macs_str = config.get("MACs", "")
        if not macs_str:
            return []
        configured = {m.strip().lower() for m in macs_str.split(",")}
        found_weak = configured & WEAK_MACS
        if found_weak:
            return [
                Finding(
                    check_id="SSH-006",
                    module=GuardianCategory.SSH,
                    title="SSH configuration includes weak MACs",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The following weak MAC algorithms are configured: "
                        f"{', '.join(sorted(found_weak))}"
                    ),
                    why_it_matters=(
                        "MD5 and SHA-1 based MACs are cryptographically broken. "
                        "Weak MACs can allow an active attacker to tamper with SSH "
                        "session data without detection."
                    ),
                    attack_scenario=(
                        "An attacker with the ability to intercept SSH traffic modifies "
                        "session data — including commands and their output — by exploiting "
                        "weaknesses in the integrity verification provided by a broken MAC."
                    ),
                    recommendation=(
                        "Remove weak MACs from sshd_config. "
                        "Recommended: MACs hmac-sha2-256-etm@openssh.com,"
                        "hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
                    ),
                    current_value=macs_str,
                    expected_value="ETM MACs with SHA-256 or SHA-512 only",
                )
            ]
        return []

    def _check_protocol_version(self, config: dict[str, str]) -> list[Finding]:
        protocol = config.get("Protocol", "2")
        if protocol.strip() != "2":
            return [
                Finding(
                    check_id="SSH-007",
                    module=GuardianCategory.SSH,
                    title="SSH Protocol 1 is enabled",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Protocol is set to '{protocol}'. "
                        "SSH Protocol 1 is cryptographically broken and must not be used."
                    ),
                    why_it_matters=(
                        "SSH Protocol 1 has known, exploitable cryptographic weaknesses "
                        "that allow session hijacking and man-in-the-middle attacks."
                    ),
                    attack_scenario=(
                        "An attacker exploits Protocol 1's weak key exchange to intercept "
                        "or hijack an active SSH session, gaining access to the authenticated "
                        "shell without knowing the user's credentials."
                    ),
                    recommendation=(
                        "Set 'Protocol 2' in /etc/ssh/sshd_config and restart sshd. "
                        "Protocol 1 should never be used on any modern system."
                    ),
                    current_value=protocol,
                    expected_value="2",
                )
            ]
        return []

    def _check_allow_users_groups(self, config: dict[str, str]) -> list[Finding]:
        """Flag if neither AllowUsers nor AllowGroups is configured."""
        has_allow_users = "AllowUsers" in config
        has_allow_groups = "AllowGroups" in config
        if not has_allow_users and not has_allow_groups:
            return [
                Finding(
                    check_id="SSH-008",
                    module=GuardianCategory.SSH,
                    title="No SSH user/group access restrictions configured",
                    severity=Severity.MEDIUM,
                    description=(
                        "Neither AllowUsers nor AllowGroups is set in sshd_config. "
                        "All system users (who have a valid shell and password/key) "
                        "can attempt SSH authentication."
                    ),
                    why_it_matters=(
                        "Without AllowUsers or AllowGroups, any account on the system "
                        "is a potential SSH entry point — including service accounts "
                        "that should never have interactive shell access."
                    ),
                    attack_scenario=(
                        "An attacker targets a service account (e.g. www-data, nobody) "
                        "whose password was set during a misconfigured deployment. "
                        "Without AllowUsers restrictions, the attacker can authenticate "
                        "via SSH and obtain a shell as that service account."
                    ),
                    recommendation=(
                        "Add 'AllowGroups ssh-users' to sshd_config and ensure only "
                        "authorized users are in that group. Or use 'AllowUsers user1 user2' "
                        "to explicitly whitelist SSH-capable accounts."
                    ),
                    current_value="not configured",
                    expected_value="AllowUsers or AllowGroups directive present",
                )
            ]
        return []
