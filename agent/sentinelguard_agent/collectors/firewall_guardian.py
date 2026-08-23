"""Firewall Guardian — checks firewall posture across multiple tools.

Supports UFW (Ubuntu/Debian), firewalld (Fedora/Rocky/CentOS),
nftables, and iptables — detected at runtime from what's available
on the host.  Uses the distro adapter to prefer the expected tool
for the detected OS, but also inspects other tools if present.

Checks:
- FIREWALL-001: No firewall active
- FIREWALL-002: Default INPUT policy not DROP/REJECT
- FIREWALL-003: Default FORWARD policy not DROP/REJECT
- FIREWALL-004: SSH (port 22) exposed to any source
- FIREWALL-005: Dangerous management ports open
- FIREWALL-006: UFW inactive (Ubuntu/Debian)
- FIREWALL-007: firewalld inactive (RHEL-family)
"""

from __future__ import annotations

import logging

from sentinelguard_contracts import Finding, GuardianCategory, Severity

from sentinelguard_agent.collectors.base import BaseGuardian
from sentinelguard_agent.collectors.utils import run_command

logger = logging.getLogger(__name__)

# Ports that should never be publicly accessible
_DANGEROUS_PORTS: dict[int, str] = {
    23: "Telnet",
    2375: "Docker API (unencrypted)",
    2376: "Docker API (TLS)",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    5601: "Kibana",
    8080: "HTTP alt",
    8443: "HTTPS alt",
    9090: "Prometheus",
    3000: "Grafana/dev server",
    5000: "Docker registry / Flask dev",
    8888: "Jupyter Notebook",
}

_SSH_PORT = 22


class FirewallGuardian(BaseGuardian):
    """Checks firewall posture using whichever tool is active on the host."""

    category = GuardianCategory.FIREWALL

    def _collect(self) -> list[Finding]:
        findings: list[Finding] = []

        ufw_active = self._is_ufw_active()
        firewalld_active = self._is_firewalld_active()
        iptables_rules = self._get_iptables_rules()
        nftables_rules = self._get_nftables_rules()

        any_firewall = (
            ufw_active or firewalld_active or bool(iptables_rules) or bool(nftables_rules)
        )

        # FIREWALL-001: No firewall active at all
        if not any_firewall:
            findings.append(
                Finding(
                    check_id="FIREWALL-001",
                    module=GuardianCategory.FIREWALL,
                    title="No active firewall detected",
                    severity=Severity.CRITICAL,
                    description=(
                        "No active firewall was detected. Neither UFW, firewalld, "
                        "iptables rules, nor nftables rules are configured."
                    ),
                    why_it_matters=(
                        "Without a firewall, all ports that have listening services "
                        "are directly accessible from any network interface. This "
                        "dramatically increases the attack surface."
                    ),
                    attack_scenario=(
                        "An attacker network-scans the host and connects directly "
                        "to database ports (MySQL 3306, Redis 6379) or management "
                        "interfaces with no firewall blocking the connection."
                    ),
                    recommendation=(
                        "Enable UFW: ufw enable && ufw default deny incoming && "
                        "ufw allow ssh. Or enable firewalld: systemctl enable --now "
                        "firewalld."
                    ),
                    current_value="no firewall active",
                    expected_value="active firewall with default-deny policy",
                )
            )
            return findings  # All other checks require a firewall to be present

        # UFW-specific checks
        if self._ufw_installed() and not ufw_active:
            findings.append(
                Finding(
                    check_id="FIREWALL-006",
                    module=GuardianCategory.FIREWALL,
                    title="UFW is installed but inactive",
                    severity=Severity.HIGH,
                    description="UFW (Uncomplicated Firewall) is installed but not active.",
                    why_it_matters=(
                        "An inactive UFW provides no protection. The binary being "
                        "present may give a false sense of security."
                    ),
                    attack_scenario=(
                        "An operator assumes UFW is blocking traffic because it is "
                        "installed. In reality, all ports are open and an attacker "
                        "can connect directly to any listening service."
                    ),
                    recommendation="sudo ufw enable",
                    current_value="inactive",
                    expected_value="active",
                )
            )

        # firewalld-specific checks
        if self._firewalld_installed() and not firewalld_active:
            findings.append(
                Finding(
                    check_id="FIREWALL-007",
                    module=GuardianCategory.FIREWALL,
                    title="firewalld is installed but inactive",
                    severity=Severity.HIGH,
                    description="firewalld is installed but not running.",
                    why_it_matters=(
                        "firewalld being stopped means no dynamic firewall rules "
                        "are applied, leaving all services directly reachable."
                    ),
                    attack_scenario=(
                        "A service restart or kernel update stops firewalld "
                        "unintentionally. Traffic that should be blocked flows "
                        "freely until someone notices."
                    ),
                    recommendation=("systemctl enable --now firewalld"),
                    current_value="inactive",
                    expected_value="active",
                )
            )

        # iptables policy checks
        if iptables_rules:
            findings.extend(self._check_iptables_policies(iptables_rules))
            findings.extend(self._check_dangerous_ports_iptables(iptables_rules))

        # UFW status checks
        if ufw_active:
            findings.extend(self._check_ufw_default_policies())
            findings.extend(self._check_ufw_ssh_exposure())

        return findings

    # ------------------------------------------------------------------
    # Firewall detection helpers
    # ------------------------------------------------------------------

    def _is_ufw_active(self) -> bool:
        output = run_command(["ufw", "status"])
        return output is not None and "Status: active" in output

    def _ufw_installed(self) -> bool:
        return bool(run_command(["which", "ufw"]))

    def _is_firewalld_active(self) -> bool:
        output = run_command(["firewall-cmd", "--state"])
        return output is not None and "running" in output.lower()

    def _firewalld_installed(self) -> bool:
        return bool(run_command(["which", "firewall-cmd"]))

    def _get_iptables_rules(self) -> str:
        output = run_command(["iptables", "-L", "-n", "--line-numbers"])
        return output or ""

    def _get_nftables_rules(self) -> str:
        output = run_command(["nft", "list", "ruleset"])
        return output or ""

    # ------------------------------------------------------------------
    # iptables policy checks
    # ------------------------------------------------------------------

    def _check_iptables_policies(self, rules: str) -> list[Finding]:
        findings: list[Finding] = []
        input_policy = self._extract_chain_policy(rules, "INPUT")
        forward_policy = self._extract_chain_policy(rules, "FORWARD")

        if input_policy and input_policy not in ("DROP", "REJECT"):
            findings.append(
                Finding(
                    check_id="FIREWALL-002",
                    module=GuardianCategory.FIREWALL,
                    title=f"iptables INPUT chain default policy is {input_policy}",
                    severity=Severity.HIGH,
                    description=(
                        f"The iptables INPUT chain has a default policy of {input_policy}. "
                        "Best practice is DROP or REJECT."
                    ),
                    why_it_matters=(
                        "An ACCEPT default policy means any traffic that doesn't "
                        "match an explicit REJECT/DROP rule is allowed through. "
                        "A single missing rule exposes a service to the network."
                    ),
                    attack_scenario=(
                        "An operator adds a firewall rule for a new service but "
                        "forgets to add a deny rule for an old one. With ACCEPT "
                        "as default, the old service is exposed immediately."
                    ),
                    recommendation=(
                        "Set default INPUT policy to DROP: iptables -P INPUT DROP. "
                        "Then explicitly allow required services."
                    ),
                    current_value=input_policy,
                    expected_value="DROP",
                )
            )

        if forward_policy and forward_policy not in ("DROP", "REJECT"):
            findings.append(
                Finding(
                    check_id="FIREWALL-003",
                    module=GuardianCategory.FIREWALL,
                    title=f"iptables FORWARD chain default policy is {forward_policy}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The iptables FORWARD chain has a default policy of {forward_policy}."
                    ),
                    why_it_matters=(
                        "A permissive FORWARD policy may allow unintended routing "
                        "of traffic between network segments, enabling attackers to "
                        "use this host as a pivot point."
                    ),
                    attack_scenario=(
                        "An attacker in one network segment uses this host as a "
                        "router to reach otherwise isolated internal services."
                    ),
                    recommendation=(
                        "Set default FORWARD policy to DROP: iptables -P FORWARD DROP."
                    ),
                    current_value=forward_policy,
                    expected_value="DROP",
                )
            )

        return findings

    def _check_dangerous_ports_iptables(self, rules: str) -> list[Finding]:
        """Detect ACCEPT rules for dangerous management ports."""
        findings: list[Finding] = []
        for port, service_name in _DANGEROUS_PORTS.items():
            if self._port_is_accepted_iptables(rules, port):
                findings.append(
                    Finding(
                        check_id="FIREWALL-005",
                        module=GuardianCategory.FIREWALL,
                        title=f"Firewall allows dangerous port {port} ({service_name})",
                        severity=Severity.HIGH,
                        description=(
                            f"iptables has an ACCEPT rule for port {port} "
                            f"({service_name}) with no apparent source restriction."
                        ),
                        why_it_matters=(
                            f"{service_name} on port {port} should not be "
                            "directly accessible from untrusted networks. "
                            "Many of these services have known exploits or "
                            "default credentials."
                        ),
                        attack_scenario=(
                            f"An attacker connects directly to {service_name} on port "
                            f"{port} and exploits default credentials, "
                            "unauthenticated access, or a known CVE."
                        ),
                        recommendation=(
                            f"Restrict access to port {port} to specific trusted "
                            "source IPs using: iptables -A INPUT -p tcp --dport "
                            f"{port} -s <trusted-ip> -j ACCEPT. "
                            "Or remove the rule if the service isn't needed."
                        ),
                        current_value=f"port {port} ACCEPT",
                        expected_value="port restricted or not exposed",
                    )
                )
        return findings

    def _extract_chain_policy(self, rules: str, chain: str) -> str | None:
        for line in rules.splitlines():
            if line.startswith(f"Chain {chain} ") and "policy" in line:
                parts = line.split("policy")
                if len(parts) > 1:
                    return parts[1].strip().split()[0].upper()
        return None

    def _port_is_accepted_iptables(self, rules: str, port: int) -> bool:
        port_str = str(port)
        for line in rules.splitlines():
            if "ACCEPT" in line and port_str in line:
                return True
        return False

    # ------------------------------------------------------------------
    # UFW-specific checks
    # ------------------------------------------------------------------

    def _check_ufw_default_policies(self) -> list[Finding]:
        findings: list[Finding] = []
        output = run_command(["ufw", "status", "verbose"])
        if not output:
            return findings

        lines_lower = output.lower()
        if "default: allow (incoming)" in lines_lower:
            findings.append(
                Finding(
                    check_id="FIREWALL-002",
                    module=GuardianCategory.FIREWALL,
                    title="UFW default incoming policy is ALLOW",
                    severity=Severity.HIGH,
                    description="UFW default incoming policy is set to ALLOW instead of DENY.",
                    why_it_matters=(
                        "A default ALLOW policy means traffic is permitted unless "
                        "explicitly blocked, which is the opposite of defense-in-depth."
                    ),
                    attack_scenario=(
                        "Any new service that starts listening (e.g. after a "
                        "software installation) is immediately accessible from the "
                        "network because no deny rule exists yet."
                    ),
                    recommendation=("ufw default deny incoming && ufw default allow outgoing"),
                    current_value="allow",
                    expected_value="deny",
                )
            )
        return findings

    def _check_ufw_ssh_exposure(self) -> list[Finding]:
        """Warn if SSH is open to any source (0.0.0.0/0) via UFW."""
        findings: list[Finding] = []
        output = run_command(["ufw", "status", "numbered"])
        if not output:
            return findings

        for line in output.splitlines():
            line_lower = line.lower()
            # Match lines like: [ 1] 22/tcp ALLOW IN Anywhere
            if ("22" in line or "ssh" in line_lower) and "allow" in line_lower:
                if "anywhere" in line_lower or "0.0.0.0/0" in line:
                    findings.append(
                        Finding(
                            check_id="FIREWALL-004",
                            module=GuardianCategory.FIREWALL,
                            title="SSH exposed to any source in UFW",
                            severity=Severity.MEDIUM,
                            description=(
                                "UFW allows SSH (port 22) from any source address (Anywhere). "
                                f"Rule: {line.strip()}"
                            ),
                            why_it_matters=(
                                "Exposing SSH to all source IPs invites automated "
                                "brute-force attacks. Restricting to known IPs "
                                "dramatically reduces the attack surface."
                            ),
                            attack_scenario=(
                                "Automated bots continuously probe port 22 and attempt "
                                "credential stuffing with leaked username/password lists."
                            ),
                            recommendation=(
                                "ufw delete the existing rule and replace with: "
                                "ufw allow from <your-ip> to any port 22. "
                                "Or use a non-standard SSH port and rate limiting."
                            ),
                            current_value="SSH allowed from Anywhere",
                            expected_value="SSH allowed only from trusted source IPs",
                        )
                    )
                    break
        return findings
