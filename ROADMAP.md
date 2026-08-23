# Roadmap

## Version 1.0 — Linux Hardening (current focus)

Goal: *"Secure Linux before vulnerability assessment."*

### Completed

- ✅ Phase 1: Repository structure
- ✅ Phase 2: Shared contracts (`sentinelguard-contracts`)
- ✅ Phase 3: Linux Agent framework (BaseGuardian, registry, aggregator, transport, CLI)
- ✅ Phase 4-6: Dashboard backend, database (SQLAlchemy + Alembic), authentication (JWT + API keys)
- ✅ Phase 7: MCP server (8 tools: `health`, `list_servers`, `scan_server`, `get_security_score`, `list_findings`, `explain_finding`, `compare_to_baseline`, `generate_report`)
- ✅ Phase 3A: Permission Guardian, Ownership Guardian, SSH Guardian + dashboard analyzers + YAML baselines + real baseline comparison
- ✅ Phase 3B: Sudo Guardian, Cron Guardian, Secret Guardian + dashboard analyzers + YAML baselines extended
- ✅ Phase 3C: Docker Guardian, Firewall Guardian, Kernel Guardian + dashboard analyzers + YAML baselines extended — **all nine v1 Guardians complete**
- ✅ Phase 17: Security Baseline Engine (YAML versioning, DB snapshotting, custom-override extension point)
- ✅ Phase 18: Security Scoring Engine (automatic per-scan scoring, severity-weighted, generic across all nine Guardians)
- ✅ Phase 19: Report Engine (Executive/Technical/Markdown/JSON, all nine required sections)
- ✅ Phase 20: Dashboard UI (Next.js — Dashboard, Servers, Server Detail, Findings, Reports, Settings)
- ✅ Phase 21: Integration testing, Docker validation, documentation, v1.0 release preparation

**SentinelGuard v1.0.0 is released.** See [RELEASE_NOTES.md](./RELEASE_NOTES.md).

## Explicitly out of scope for v1

These belong to future versions and are **not implemented** in v1. Where
the architecture calls for it, only interface stubs/placeholders exist
(e.g. `generate_fix_plan()`, `preview_fix()`, `apply_fix()`, `rollback()`
signatures with no logic behind them yet):

| Feature | Target version |
|---|---|
| Auto Remediation / One-Click Hardening | v2 |
| Tool Installation | v2 |
| Vulnerability Assessment (CVE scanning) | v2 |
| Threat Intelligence, EPSS, KEV | v2 |
| Attack Validation / Attack Simulation | v3 |
| Configuration Drift Detection | v2 |
| Event Engine / Policy Engine | v3 |
| Security Timeline | v2 |
| Plugin Marketplace | v3 |
| Fleet Analytics | v3 |
| Compliance Frameworks (CIS, PCI-DSS, etc.) | v3 |
| Background Workers / Job Scheduler | v2 (needed to support above) |
| AI Session History | v2 |
| Knowledge Graph | v4 |
| Enterprise features (SSO, multi-tenant, RBAC beyond admin/viewer) | v6+ |

This list exists so contributors and users know *why* something isn't
here yet — it's a deliberate sequencing decision, not an oversight. The
architecture (see ARCHITECTURE.md) is intentionally designed so each of
these can be added as an additive module later without a core rewrite.

## Contributing to the roadmap

Feature requests for anything in the "out of scope" table are welcome as
GitHub issues for discussion, but won't be implemented against v1's
codebase until the corresponding version's build phase begins.
