# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/)
once it reaches a stable release. Pre-1.0, versioning tracks
implementation phases.

## [1.0.1] - 2026-08

### Fixed

Five real bugs found and fixed after running v1.0.0 on a genuinely
unprivileged Linux user for the first time (all prior testing had
inadvertently run as root, which bypasses Unix permission checks
entirely and never exercised these code paths):

- **Agent crash on permission-denied paths** (`utils.py`): `path_exists()`
  and `walk_directory()` called `Path.exists()` without catching
  `PermissionError`, which is raised (not silently swallowed) when a
  non-root user checks a path under a directory they can't traverse,
  e.g. `/root/.ssh`. Both now catch `PermissionError`/`OSError` and
  return the same safe sentinel (`False`/`[]`) used everywhere else in
  the codebase. `sudo_guardian.py` had the identical bug inline and now
  reuses the fixed shared utility instead.
- **Agent logs corrupting stdout JSON** (`logging_config.py`): the
  logging handler wrote to stdout instead of stderr, so any ERROR-level
  log line (triggered by the bug above) got mixed into `sentinelguard-agent
  scan`'s supposedly pure-JSON stdout stream, breaking any pipeline
  parsing it (`| python3 -m json.tool`, `| jq`, etc). Logs now correctly
  go to stderr.
- **`alembic upgrade head` fails on a fresh clone** (`db/session.py`,
  `db/migrations/env.py`): SQLite creates the database *file* on first
  connection but never creates missing parent directories, and
  `dashboard/data/` is (correctly) gitignored — so it simply doesn't
  exist after extracting/cloning. Both the app's engine factory and
  Alembic's independent connection path now create the directory first.
- **KERNEL-013 false positives on Kali/Arch-style kernels**
  (`parse_kernel_version`): the parser only stripped content after the
  first `-`, so `"6.16.8+kali-amd64"` became `"6.16.8+kali"`, then
  failed to parse `"8+kali"` as an integer and silently fell back to
  `(0, 0, 0)` — reporting every such kernel as version "0.0.0" and
  therefore always EOL, regardless of the real version. Now uses a
  leading-digits regex that correctly extracts `6.16.8` regardless of
  what separator (`-`, `+`, or nothing) follows.
- **Duplicate server registrations** (`server_service.py`,
  `models/server.py`): `POST /api/v1/agents/register` unconditionally
  created a new `Server` row on every call, so re-running a setup
  script, losing an issued API key and re-registering, or any other
  repeat registration of the same hostname silently fragmented that
  machine's scan history and score across multiple `server_id`s.
  `register_server()` is now an idempotent upsert keyed on hostname —
  re-registering refreshes metadata and issues a fresh API key
  (invalidating the old one) rather than creating a duplicate row.
  `hostname` now also has a unique DB constraint as defense in depth.
  A migration (`582d74304304`) adds the constraint; a standalone
  `cleanup_duplicate_servers.py` script is included to merge any
  pre-existing duplicates (preserving their scan/finding history) for
  anyone upgrading a database that already has them.

**Tests:** 669 total (324 dashboard + 305 agent + 40 contracts), up
from 662. All new tests target the exact bugs above. Ruff, Black, MyPy
strict all pass across all three Python packages.

## [1.0.0] - 2026-07

### Added — Milestone Group 6: Release Preparation (Phase 21)

**Integration testing:**
- `dashboard/tests/test_e2e/test_full_lifecycle.py` — single comprehensive
  test covering the complete v1.0 lifecycle: health check, admin
  bootstrap, two-server fleet registration, multi-Guardian scan with
  realistic findings (SSH high + Secret critical + Kernel low), automatic
  scoring, baseline comparison, all 4 report formats, MCP/REST parity
  verified identical, multi-server data isolation confirmed.

**Docker validation and fixes:**
- `dashboard/Dockerfile` rewritten — now requires repo-root build context
  (docker-compose sets `context: .`, `dockerfile: dashboard/Dockerfile`)
  since the dashboard depends on the sibling `contracts/` package and
  Docker cannot COPY from outside its build context.
- `agent/Dockerfile` fully implemented — was still the Phase 1 placeholder
  echo command; now a real multi-stage build.
- `docker-compose.yml` updated — dashboard and agent services now use
  `context: .` with their respective `dockerfile: <pkg>/Dockerfile` paths.
- `.dockerignore` added at repo root for build performance and security.

**Version alignment:**
- All packages bumped to `1.0.0`: `contracts`, `agent`, `dashboard`,
  `frontend`. Dependency constraints updated (`sentinelguard-contracts
  >=1.0.0,<2.0.0`). Version assertion in `test_cli.py` updated. App
  `version=` field in `main.py` updated.

**Documentation:**
- `RELEASE_NOTES.md` — v1.0.0 highlights, performance benchmarks,
  known limitations, v1.5 roadmap.
- `QUICKSTART.md` — 10-minute path from zero to a scored server.
- `DEMO.md` — scripted walkthrough with synthetic findings, runnable.
- `docs/API.md` — REST API reference (auth model, all endpoints, error
  format, pagination, rate limiting status).
- `docs/MCP.md` — MCP tool reference (auth model, all 8 tools, error
  handling, example conversation).
- `docs/ARCHITECTURE_OVERVIEW.md` — condensed architecture summary
  with real performance benchmarks (agent scan timing per Guardian,
  API latency p50/p95 per endpoint, frontend bundle size).
- `docs/samples/` — real sample reports (executive, technical, JSON)
  generated by the actual `report_service` against the DEMO.md scenario,
  not fabricated.
- `README.md` — Status updated to v1.0.0 released, Architecture section
  links to all doc files.
- `ROADMAP.md` — Phase 21 marked complete.
- `CHANGELOG.md` — this entry.

**Test count:** 317 dashboard, 305 agent, 40 contracts = **662 total**.
Coverage: 98% dashboard, 96% agent, 99% contracts.
All quality gates pass: ruff, black, mypy strict.

### Added — Milestone Group 5: Report Engine + Dashboard UI (Phases 19–20)

**Phase 19 — Report Engine:**

- `report_service.py` substantially rewritten. Every report (Executive,
  Technical, Markdown, JSON) now includes all required sections: server
  information, security score with category breakdown, findings grouped
  by category (all nine categories always present as keys), a severity
  summary (all five severities always present, even at 0), baseline
  comparison (Technical/Markdown/JSON only — omitted from Executive to
  stay skimmable), metadata (report type, generation timestamp, baseline
  version), and per-finding recommendations.
- Executive vs. Technical is now a real level-of-detail distinction:
  Executive omits attack_scenario/current_value/expected_value per
  finding and the full baseline comparison section.
- JSON format restructured with explicit top-level sections
  (`metadata`, `server`, `scan`, `score`, `severity_summary`,
  `findings_by_category`, `baseline_comparison`) — this is what the
  Phase 20 frontend consumes directly.
- 18 tests (up from 8) covering every new section.

**Phase 20 — Dashboard UI:**

- Real, working Next.js 14 (App Router) + React 18 + TypeScript (strict)
  + Tailwind CSS frontend — `npm install`, `npm run build`, and
  `npm run lint` all verified clean before committing.
- Six required pages plus two detail views: `/login`, `/dashboard`
  (fleet overview), `/servers`, `/servers/[id]` (score gauge, category
  cards, tabbed findings/baseline/scans, report download),
  `/findings` (filterable table), `/findings/[id]`, `/reports`
  (generate/preview/download), `/settings`.
- `lib/api-client.ts` is the only file that talks to the REST API — no
  business logic duplicated in the frontend; scoring, baseline
  comparison, and report rendering all happen server-side.
- Dark operations-console design system (severity-driven color
  language, monospace for technical values, a circular arc score gauge
  as the signature visual element) — see `frontend/README.md`.
- Production Dockerfile (multi-stage build) replacing the Milestone
  Group 1 placeholder.

**Tests:** dashboard 316 tests (98% coverage), agent 305 (unaffected),
contracts 40 (unaffected). Frontend: `npm run build` and
`npm run lint` both clean (no automated frontend test suite requested
for this milestone — only lint/build cleanliness).

### Added — Milestone Group 4: Security Baseline Engine + Scoring Engine (Phases 17–18)

**Phase 17 — Baseline Engine:**

- `app/services/baseline_engine_service.py`: YAML files remain the
  canonical source of truth (unchanged, all nine analyzers still read
  them directly for live comparisons). New capabilities layered on top:
  - **Versioning**: every distro YAML now has a top-level `version` key
    (`"1.0.0"`); `get_baseline_version()` exposes it, and every computed
    score records which version produced it.
  - **DB snapshotting**: `sync_baselines_to_db()` persists YAML content
    into the `baselines` table (idempotent upsert, 45 rows for 5 distros
    × 9 categories), giving a durable historical record independent of
    the YAML files on disk. Runs automatically at dashboard startup.
  - **Custom organization baseline overrides** (extension point):
    `get_effective_rules()` / `set_custom_rule_override()` support a
    `source="custom"` layer on top of YAML defaults, fully implemented
    and tested at the service layer. Not yet wired into live Guardian
    analyzer calls (would require a `db` parameter across 18 analyzer
    methods in 9 files for a feature with no management UI/API yet) —
    documented as a deliberate, ready-to-activate boundary.
- `Baseline` model: added `source` column.

**Phase 18 — Scoring Engine:**

- `app/services/scoring_service.py`: computes and persists
  `SecurityScoreRecord` + `CategoryScoreRecord` automatically at
  scan-ingest time — no manual trigger, no per-Guardian scoring code.
  - Severity weights: critical=25, high=15, medium=7, low=3, info=0.
  - Category weights (sum to 1.0, validated at import time): SSH 20%,
    Sudo 15%, Permission 15%, Secret 15%, Firewall 15%, Docker 10%,
    Kernel 5%, Cron 3%, Ownership 2%.
  - `category_score = max(0, 100 - Σ severity penalties)`;
    `overall_score = Σ(category_score × weight)`.
  - Pass/fail counts derived from each category's Phase-17
    `analyzer.compare()` output — reuses the Baseline Engine instead of
    a separate check catalog.
  - Idempotent: recomputation replaces existing score rows rather than
    duplicating them.
  - A future tenth Guardian needs one `CATEGORY_WEIGHTS` entry, not new
    scoring logic.
- `CategoryScoreRecord`/`SecurityScoreRecord` models: added
  `passed_checks`, `failed_checks`, `total_checks`, `baseline_version`
  columns.
- `scan_service.ingest_scan()`: calls scoring automatically after every
  scan, wrapped defensively (a scoring bug never blocks scan ingestion).
- `SecurityScoreResponse` schema: extended with the new summary fields,
  following the same "extend, don't mutate the shared contract" pattern
  used elsewhere (`sentinelguard_contracts.SecurityScore` unchanged).
- REST (`GET /servers/{id}/score`) and MCP (`get_security_score`) both
  read through `score_service.get_security_score()` — verified
  byte-identical in an integration test.

**Tests:** 306 dashboard tests (up from 265), 97% coverage. Agent (305)
and contracts (40) unaffected. Ruff, Black, MyPy strict all pass.

### Added — Milestone Group 3C: Docker, Firewall, Kernel Guardians (v1 Guardian set complete)

This completes all nine v1 Guardian modules.

**Agent-side collectors:**

- `utils.py` extended: `read_sysctl`/`read_sysctl_all` (bulk sysctl reading),
  `run_command_json` (JSON command output parsing), `get_kernel_version`/
  `parse_kernel_version` (kernel version detection across Ubuntu and
  RHEL-family version string formats).
- `docker_guardian.py` — DOCKER-001..013: socket permissions (world-writable
  CRITICAL, group ownership), TCP exposure with TLS-aware severity, daemon
  config (no-new-privileges, userland-proxy), privileged containers
  (CRITICAL), host PID/network/IPC namespace sharing, 12-capability
  dangerous-capability blocklist, root-user containers, 12-path dangerous
  host mount blocklist (CRITICAL), unpinned `:latest` tags. Gracefully
  returns no findings (not an error) when Docker isn't installed.
- `firewall_guardian.py` — FIREWALL-001..007: no active firewall (CRITICAL,
  checked across UFW/firewalld/iptables/nftables), default INPUT/FORWARD
  policy, SSH exposed to any source, 14-port dangerous management port
  blocklist, UFW/firewalld installed-but-inactive. Fully distro-aware —
  works regardless of which firewall tool the host uses.
- `kernel_guardian.py` — KERNEL-001..013: 12 sysctl security settings
  (ASLR, ptrace_scope, suid_dumpable, dmesg_restrict, kexec_load_disabled,
  ip_forward, tcp_syncookies, accept_redirects, accept_source_route,
  accept_ra, kptr_restrict, unprivileged_bpf_disabled) read via a single
  bulk `sysctl -a` call, plus kernel version EOL detection.
- `GUARDIAN_REGISTRY` now contains all nine v1 Guardians.
- Fixed a real bug caught by testing: the UFW default-policy check matched
  "Default: allow" as a substring, which also matched the "(outgoing)"
  line — narrowed to match "(incoming)" specifically.

**Dashboard-side analyzers:**

- `docker/analyzer.py`, `firewall/analyzer.py`, `kernel/analyzer.py` —
  apply distro baseline severity overrides for all 33 combined 3C rules.
- YAML baselines: docker (13 rules), firewall (7 rules), kernel (13 rules)
  appended to all five distro files.
- `_register_analyzers()` now registers all nine analyzers — v1 Guardian
  set is architecturally complete.

**Tests:** 610 total (40 contracts + 305 agent + 265 dashboard), 96-98%
coverage per package. 151 new tests in this milestone. Ruff, Black, MyPy
strict all pass.

### Added — Milestone Group 3B: Sudo, Cron, Secret Guardians

**Agent-side collectors:**

- `utils.py` extended: `scan_content_for_patterns` (18-pattern regex
  scanner with deduplication and credential redaction), `parse_sudoers_lines`
  (backslash-continuation joining, comment/blank stripping), `is_world_writable`.
- `sudo_guardian.py` — SUDO-001 (sudoers file permissions, expected 0o440),
  SUDO-002 (world-writable sudoers — CRITICAL), SUDO-003 (NOPASSWD rules),
  SUDO-004 (ALL=(ALL) ALL unrestricted grants), SUDO-005 (18-command
  shell-escape blocklist: vim, python, bash, find, awk, perl, etc.).
  Reads `/etc/sudoers` and all `/etc/sudoers.d/` drop-ins.
- `cron_guardian.py` — CRON-001 (cron directory permission checks, 6 paths),
  CRON-002 (world-writable files in cron dirs — CRITICAL), CRON-003
  (world-writable scripts referenced in `/etc/crontab` — CRITICAL),
  CRON-004 (insecure cron/at spool directory permissions).
- `secret_guardian.py` — SECRET-001 (SSH private key detection in `.ssh`
  dirs, one finding per file), SECRET-002 (`.env`/`.env.*` files with
  credential assignments), SECRET-003 (18-pattern filesystem scan covering
  AWS, Azure, GCP, GitHub, Stripe, SendGrid, Slack, generic API keys,
  hardcoded passwords; skips 17 binary extensions and files >512 KB).
  All matched values are redacted before storage.
- Registry updated to 6 Guardians: Permission, Ownership, SSH, Sudo, Cron, Secret.

**Dashboard-side analyzers:**

- `sudo/analyzer.py`, `cron/analyzer.py`, `secret/analyzer.py` — apply
  distro baseline severity overrides. Sudo/Cron/Secret do not suppress
  findings (unlike Permission/Ownership) — any detected violation is always
  surfaced.
- YAML baselines: sudo (5 rules), cron (4 rules), secret (3 rules) appended
  to all five distro files. All distros share identical 3B rules.
- `compare_to_baseline` now covers all 6 active Guardian categories.

**Tests:** 459 total (40 contracts + 195 agent + 224 dashboard), 96-97%
coverage. 107 new tests in this milestone. Ruff, Black, MyPy strict all pass.

### Added — Milestone Group 3A: Permission, Ownership, SSH Guardians

**Agent-side collectors** (`agent/sentinelguard_agent/collectors/`):

- `utils.py` — shared utilities reused by all nine Guardian collectors:
  `file_stat`, `file_mode_octal`, `file_owner_ids`, `read_file`,
  `path_exists`, `walk_directory`, `run_command`, `parse_key_value_config`.
  Every function handles its own OS errors and returns a clear sentinel
  so Guardian check logic stays free of try/except noise.
- `permission_guardian.py` — **reference implementation** for all
  Guardians. Three check methods: PERM-001 (sensitive file permission
  modes, 9 paths), PERM-002 (world-writable files in /etc, /var/log,
  /tmp), PERM-003 (world-readable sensitive files). Every finding carries
  the full AI-copilot payload.
- `ownership_guardian.py` — OWN-001 (uid/gid on 8 sensitive paths, with
  `None` meaning "any value accepted"), OWN-002 (orphaned files whose
  uid/gid has no matching system account — classic uid-reuse attack vector).
- `ssh_guardian.py` — 8 checks: SSH-001 PermitRootLogin, SSH-002
  PasswordAuthentication, SSH-003 PermitEmptyPasswords (CRITICAL),
  SSH-004 PubkeyAuthentication, SSH-005 weak ciphers (10-entry
  blocklist), SSH-006 weak MACs (8-entry blocklist), SSH-007 Protocol
  version, SSH-008 no AllowUsers/AllowGroups restriction. Merges
  `sshd_config.d/` drop-in files (Debian/Ubuntu pattern).
- `registry.py` — updated with all three Phase 3A Guardians.

**Dashboard-side analyzers** (`dashboard/app/modules/`):

- `registry.py` — `BaseAnalyzer` interface + `register_analyzer` /
  `get_analyzer` / `all_analyzers` / `clear_registry` (test isolation).
  New Guardians add one `register_analyzer()` call in `app/main.py`.
- `baseline_loader.py` — loads and `lru_cache`s YAML baselines from
  `app/baselines/<distro>.yaml`.
- `permission/analyzer.py`, `ownership/analyzer.py`, `ssh/analyzer.py`
  — suppress baseline-correct findings, apply baseline severity overrides,
  produce `BaselineComparisonItem` lists with `matches_baseline` flag.

**Security baselines** (`dashboard/app/baselines/`):

- `ubuntu.yaml`, `debian.yaml` — shadow gid=42, sshd_config.d pattern.
- `fedora.yaml`, `rocky.yaml`, `centos.yaml` — shadow mode 0000, gid=0.
- Permission, ownership, and SSH rules for every supported distro.

**Wiring**:

- `compare_to_baseline` service and MCP tool now return real per-rule
  comparisons backed by the analyzer registry — no longer a placeholder.
- Analyzers registered at app startup via `_register_analyzers()` in
  `app/main.py`.

**Tests**: 352 total (40 contracts + 129 agent + 183 dashboard), 97%+
coverage. 129 new tests in this milestone. Ruff, Black, MyPy strict all
pass.

### Added — Milestone Group 2: Dashboard Backend, Database, Auth, MCP Server (Phases 4–7)

- **FastAPI dashboard backend** (`dashboard/app/`): app factory, CORS,
  auto-generated OpenAPI docs at `/docs` and `/redoc`.
- **Service layer** (`app/services/`): all business logic in one place,
  shared identically by the REST API and MCP server — the core
  architectural guarantee of the design.
- **14 REST endpoints** across 7 routers: `/health`, `/auth/register`,
  `/auth/token`, `/auth/me`, `/agents/register`, `/agents/scans`,
  `/servers`, `/servers/{id}`, `/servers/{id}/scans`,
  `/servers/{id}/score`, `/servers/{id}/baseline`,
  `/servers/{id}/report`, `/findings`, `/findings/{id}`.
- **Database** (Phase 5): 7 SQLAlchemy ORM models (Server, Scan,
  Finding, CategoryScoreRecord, SecurityScoreRecord, Baseline, User),
  Alembic with autogenerate, initial migration creating all tables.
- **Authentication** (Phase 6): bcrypt for user passwords, SHA-256 for
  agent API keys (deliberate choice — see `app/auth/security.py`).
  JWT user sessions, bootstrap-admin rule (first user always admin),
  scan attribution enforced by API key rather than payload claim.
- **MCP server** (Phase 7): 8 tools (`health`, `scan_server`,
  `get_security_score`, `list_findings`, `explain_finding`,
  `compare_to_baseline`, `generate_report`, `list_servers`) registered
  against FastMCP 1.28 via explicit registration (not in-place decoration)
  so tools remain directly callable for testing without a transport.
- **148 tests, 98% coverage**. Ruff, Black, MyPy (strict) all pass.

### Added — Phase 3: Linux Agent Framework

- `sentinelguard-agent` package: `AgentSettings` (env-driven config via
  pydantic-settings), structured JSON logging, distro detection
  (`/etc/os-release` parsing with `ID_LIKE` fallback for RHEL-family
  distros like AlmaLinux), per-distro adapters (package manager,
  firewall tool, standard paths) for Ubuntu/Debian/Fedora/Rocky/CentOS,
  `BaseGuardian` abstract collector class, an (currently empty)
  `GUARDIAN_REGISTRY` that Phases 8-16 populate, an aggregator that
  merges Guardian results into a `ScanPayload` with correct
  COMPLETED/PARTIAL/FAILED status derivation, and a `DashboardClient`
  HTTPS transport with retry/backoff and auth-error handling.
- Typer CLI (`sentinelguard-agent scan|register|version`) — `scan` runs
  end-to-end today (zero Guardians registered yet, so it produces an
  empty-but-valid COMPLETED payload), proving the collection ->
  aggregation -> submission pipeline ahead of Guardians landing.
- 59 unit tests, 98% line coverage. Ruff, Black, MyPy (strict) all pass.

### Added — Phase 2: Shared Contracts

- New `contracts/` package (`sentinelguard-contracts`): shared pydantic
  v2 models — `Finding`, `GuardianResult`, `ScanPayload`,
  `CategoryScore`/`SecurityScore`, `ServerRegistration`/`ServerInfo`,
  `ReportRequest`/`Report` — plus the enums they're built on.
- **Design change from the original sketch:** rather than a
  `transport/schemas.py` living under `agent/` and being hand-mirrored
  under `dashboard/app/schemas/`, both packages depend on this single
  shared package. See `contracts/README.md` and `ARCHITECTURE.md`
  section 2 for the rationale. ARCHITECTURE.md has been updated to
  reflect this.
- 40 unit tests, 99% line coverage. Ruff, Black, MyPy (strict) all pass.

### Added — Phase 1: Repository Structure

- Scaffolded repository layout: `agent/`, `dashboard/`, `frontend/`,
  `docs/`, each with per-directory README stubs describing intended
  contents and the implementation phase that will populate them.
- Added project governance docs: README, ARCHITECTURE, ROADMAP,
  CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, CHANGELOG, MIT LICENSE.
- Added tooling configuration: `.gitignore`, `.editorconfig`,
  `.pre-commit-config.yaml`.
- Added GitHub scaffolding: CI workflow (Ruff, Black, MyPy, Pytest),
  release workflow, issue templates (bug report, feature request), PR
  template, Dependabot config, CODEOWNERS.
- Added `docker-compose.yml` skeleton and placeholder Dockerfiles for
  agent, dashboard, and frontend (no build logic yet).

No application code yet — structure only, per Phase 1 scope.
