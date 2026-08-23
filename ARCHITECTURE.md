# SentinelGuard V1.0 — Architecture Design

## 1. Software Architecture

SentinelGuard V1 follows an **agent–orchestrator** model with four logical layers. Each layer only talks to its direct neighbor, which is what lets future modules (vuln scanning, threat intel, plugins) slot in later without touching the core.

```
┌─────────────────────────────────────────────────────────┐
│  AI Clients (Claude, ChatGPT, Cursor, Gemini)             │
└──────────────────────┬──────────────────────────────────┘
                        │ MCP (stdio / SSE / HTTP)
┌──────────────────────▼──────────────────────────────────┐
│  MCP Server Layer  (sentinelguard-dashboard/mcp/)         │
│  - Thin translation layer: MCP tool call → service call   │
│  - No business logic lives here                           │
└──────────────────────┬──────────────────────────────────┘
                        │ direct function calls (in-process)
┌──────────────────────▼──────────────────────────────────┐
│  Dashboard / Orchestrator (FastAPI)                        │
│  ┌───────────────┐ ┌───────────────┐ ┌─────────────────┐ │
│  │ Service Layer │ │ Scoring Engine│ │ Baseline Engine │ │
│  │ (business     │ │ (weighted     │ │ (distro-aware   │ │
│  │  logic)       │ │  scoring)     │ │  expected state)│ │
│  └───────┬───────┘ └───────────────┘ └─────────────────┘ │
│          │                                                │
│  ┌───────▼────────┐   ┌──────────────┐  ┌──────────────┐ │
│  │ Repository/ORM │   │ Report Gen   │  │ Auth (JWT)   │ │
│  │ (SQLAlchemy)   │   │ (MD/JSON/    │  │              │ │
│  │                │   │  exec/tech)  │  │              │ │
│  └───────┬────────┘   └──────────────┘  └──────────────┘ │
│          │                                                │
│  ┌───────▼────────┐                                       │
│  │ SQLite DB      │  ← REST API for Agents (ingest)       │
│  └────────────────┘  ← REST API for Frontend               │
└──────────────────────┬──────────────────────────────────┘
                        │ REST (HTTPS + API key / mTLS later)
┌──────────────────────▼──────────────────────────────────┐
│  SentinelGuard Linux Agent (per host)                     │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐            │
│  │ Guardian    │ │ Guardian    │ │ Guardian    │  ...9x   │
│  │ Modules     │ │ Modules     │ │ Modules     │          │
│  │ (collectors)│ │ (collectors)│ │ (collectors)│          │
│  └──────┬─────┘ └──────┬─────┘ └──────┬─────┘            │
│         └──────────────┼──────────────┘                   │
│                  Result Aggregator                        │
│                  (builds one JSON payload)                │
│                  Transport Client (HTTPS POST)             │
└─────────────────────────────────────────────────────────┘
```

**Key design principle:** the Agent is a *collector*, not a *decision-maker*. It gathers raw facts (permission bits, config values, process state) and ships structured JSON. All scoring, baseline comparison, and severity judgment happen in the Dashboard. This keeps the agent auditable/lightweight and means scoring logic can evolve without redeploying agents fleet-wide.

Two separate deployable units, two separate repos-in-a-monorepo (or two repos):
- `sentinelguard-agent` — Python, minimal deps, runs on the monitored host.
- `sentinelguard-dashboard` — FastAPI backend + MCP server + Next.js frontend.

---

## 2. Folder Structure

> **Updated after Phase 2/Phase 3 implementation:** the sketch below
> originally showed a `transport/schemas.py` living only under `agent/`,
> mirrored by hand under `dashboard/app/schemas/`. During implementation
> this was replaced with a single shared `contracts/` package that both
> `agent/` and `dashboard/` depend on — see `contracts/README.md` for
> the rationale (avoiding two hand-synced copies of the same wire
> format). The structure below reflects what was actually built.

```
sentinelguard/
├── contracts/                        # NEW — shared wire-format models (Phase 2)
│   ├── sentinelguard_contracts/
│   │   ├── __init__.py
│   │   ├── enums.py                  # Severity, GuardianCategory, ScanStatus, etc.
│   │   ├── finding.py                # Finding
│   │   ├── guardian.py               # GuardianResult
│   │   ├── scan.py                   # ScanPayload
│   │   ├── score.py                  # CategoryScore, SecurityScore
│   │   ├── server.py                 # ServerRegistration, ServerInfo
│   │   └── report.py                 # ReportRequest, Report
│   ├── tests/
│   └── pyproject.toml
├── agent/
│   ├── sentinelguard_agent/
│   │   ├── __init__.py
│   │   ├── main.py                 # CLI entrypoint (scan, daemon, register)
│   │   ├── config.py                # agent config (dashboard URL, API key, interval)
│   │   ├── transport/
│   │   │   └── client.py            # HTTPS client, retry/backoff (depends on contracts/)
│   │   ├── collectors/
│   │   │   ├── base.py              # BaseGuardian abstract class
│   │   │   ├── permission_guardian.py
│   │   │   ├── ownership_guardian.py
│   │   │   ├── ssh_guardian.py
│   │   │   ├── sudo_guardian.py
│   │   │   ├── cron_guardian.py
│   │   │   ├── secret_guardian.py
│   │   │   ├── docker_guardian.py
│   │   │   ├── firewall_guardian.py
│   │   │   └── kernel_guardian.py
│   │   ├── distro/
│   │   │   ├── detect.py            # /etc/os-release parsing
│   │   │   └── adapters.py          # per-distro path/command differences
│   │   ├── aggregator.py            # merges collector outputs → ScanPayload
│   │   └── logging_config.py
│   ├── tests/
│   ├── pyproject.toml
│   └── Dockerfile
│
├── dashboard/
│   ├── app/
│   │   ├── main.py                  # FastAPI app factory
│   │   ├── config.py                 # settings via pydantic-settings
│   │   ├── api/
│   │   │   ├── v1/
│   │   │   │   ├── agents.py         # agent registration + ingest endpoints
│   │   │   │   ├── servers.py
│   │   │   │   ├── findings.py
│   │   │   │   ├── scores.py
│   │   │   │   ├── reports.py
│   │   │   │   └── auth.py
│   │   ├── mcp/
│   │   │   ├── server.py             # MCP server bootstrap
│   │   │   └── tools/
│   │   │       ├── scan_system.py
│   │   │       ├── get_security_score.py
│   │   │       ├── list_findings.py
│   │   │       ├── explain_finding.py
│   │   │       ├── compare_to_baseline.py
│   │   │       ├── generate_report.py
│   │   │       └── health.py
│   │   ├── services/                 # business logic, no HTTP/MCP concerns
│   │   │   ├── scan_service.py
│   │   │   ├── scoring_service.py
│   │   │   ├── baseline_service.py
│   │   │   ├── finding_service.py
│   │   │   └── report_service.py
│   │   ├── modules/                  # pluggable "Guardian analyzers" (server-side interpretation)
│   │   │   ├── registry.py           # module registration for future plugin system
│   │   │   ├── permission/
│   │   │   ├── ownership/
│   │   │   ├── ssh/
│   │   │   ├── sudo/
│   │   │   ├── cron/
│   │   │   ├── secret/
│   │   │   ├── docker/
│   │   │   ├── firewall/
│   │   │   └── kernel/
│   │   ├── baselines/
│   │   │   ├── ubuntu.yaml
│   │   │   ├── debian.yaml
│   │   │   ├── fedora.yaml
│   │   │   ├── rocky.yaml
│   │   │   └── centos.yaml
│   │   ├── models/                   # SQLAlchemy ORM models
│   │   │   ├── server.py
│   │   │   ├── scan.py
│   │   │   ├── finding.py
│   │   │   ├── score.py
│   │   │   ├── baseline.py
│   │   │   └── user.py
│   │   ├── schemas/                  # REST-only request/response DTOs (imports shared types from contracts/ where applicable)
│   │   ├── db/
│   │   │   ├── session.py
│   │   │   └── migrations/ (alembic)
│   │   ├── auth/
│   │   │   ├── jwt.py
│   │   │   └── dependencies.py
│   │   └── core/
│   │       ├── logging.py
│   │       └── exceptions.py
│   ├── tests/
│   ├── alembic.ini
│   ├── pyproject.toml
│   └── Dockerfile
│
├── frontend/
│   ├── app/                          # Next.js app router
│   │   ├── dashboard/page.tsx
│   │   ├── servers/page.tsx
│   │   ├── servers/[id]/page.tsx
│   │   ├── findings/page.tsx
│   │   ├── reports/page.tsx
│   │   └── settings/page.tsx
│   ├── components/
│   ├── lib/api-client.ts
│   ├── package.json
│   └── Dockerfile
│
├── docker-compose.yml
├── docs/
│   ├── architecture.md               # this document, versioned
│   ├── mcp-tools.md
│   └── baselines.md
└── README.md
```

The `modules/registry.py` on the dashboard side is the one piece of forward-looking scaffolding: future modules (vuln scanning, compliance, threat intel) register themselves the same way the nine V1 Guardians do, so V2 is additive, not a rewrite.

---

## 3. Database Schema (SQLite via SQLAlchemy, Alembic-migrated)

```
servers
├── id (PK, uuid)
├── hostname
├── ip_address
├── distro                 # ubuntu/debian/fedora/rocky/centos
├── distro_version
├── agent_version
├── api_key_hash            # hashed, agent auth
├── status                  # online/offline/stale
├── last_seen_at
└── created_at

scans
├── id (PK, uuid)
├── server_id (FK → servers.id)
├── started_at
├── completed_at
├── status                  # running/completed/failed
├── raw_payload_ref          # optional: pointer to stored raw JSON
└── agent_version

findings
├── id (PK, uuid)
├── scan_id (FK → scans.id)
├── server_id (FK → servers.id, denormalized for query speed)
├── module                   # permission/ssh/sudo/... (maps to Guardian)
├── check_id                  # stable rule identifier, e.g. SSH-001
├── title
├── severity                  # critical/high/medium/low/info
├── description
├── why_it_matters
├── attack_scenario
├── recommendation
├── current_value              # raw observed value
├── expected_value              # baseline value
├── status                       # open/resolved/accepted_risk/false_positive
└── created_at

category_scores
├── id (PK)
├── scan_id (FK → scans.id)
├── category                  # permissions/ssh/sudo/cron/secrets/docker/firewall/kernel/ownership
├── score                       # 0-100
└── weight_used

security_scores
├── id (PK)
├── scan_id (FK → scans.id, unique)
├── overall_score
└── computed_at

baselines
├── id (PK)
├── distro
├── distro_version
├── category
├── rules_json                 # expected config as structured data
└── version

users
├── id (PK)
├── email
├── hashed_password
├── role                        # admin/viewer
└── created_at
```

`findings.check_id` is deliberately a stable string (not just a DB id) — future versions (and the AI copilot) can reference "SSH-001" consistently across scans for trend tracking, even though this version doesn't build trend analysis yet.

---

## 4. MCP Design

The MCP server is a thin adapter over the service layer — every tool call maps 1:1 to a service function and returns structured JSON, never freeform text (the AI client does the natural-language explanation).

| Tool | Input | Output |
|---|---|---|
| `scan_system(server_id)` | server_id (or "all") | triggers scan, returns scan_id + status |
| `get_security_score(server_id, scan_id?)` | server_id, optional scan_id (defaults latest) | overall + per-category scores |
| `list_findings(server_id, severity?, category?, status?)` | filters | array of finding summaries |
| `explain_finding(finding_id)` | finding_id | full finding detail: why it matters, attack scenario, recommendation |
| `compare_to_baseline(server_id, category?)` | server_id, optional category | current vs. expected, per rule |
| `generate_report(server_id, format)` | format: executive/technical/json/markdown | report content or download URL |
| `health()` | — | dashboard + agent fleet health summary |

Auth: MCP endpoint sits behind the same JWT/API-key scheme as the REST API; each AI client session is scoped to the servers the authenticated user can see.

---

## 5. Linux Agent Architecture

- **BaseGuardian** abstract class: every collector implements `collect() -> GuardianResult` (raw facts only, no severity judgment — that's the dashboard's job in V1's design, though for V1 simplicity the agent *may* emit its own preliminary severity tags that the dashboard can override via baseline comparison).
- **Distro adapter layer**: resolves paths/commands that differ across Ubuntu/Debian/Fedora/Rocky/CentOS (e.g., `ufw` vs `firewalld`, apt vs dnf-managed paths) so collectors stay distro-agnostic.
- **Aggregator**: merges all nine collector outputs into a single `ScanPayload` (pydantic model shared with the dashboard as the wire contract).
- **Transport client**: authenticated HTTPS POST to `/api/v1/agents/{server_id}/scans`, with retry/backoff; agent never needs inbound ports open.
- **Execution modes**: one-shot CLI scan (`sentinelguard-agent scan`) and a lightweight daemon mode (cron-driven or systemd timer) for scheduled scans — no persistent background service required for V1.
- **Privilege model**: agent needs read access to sensitive paths (shadow, sudoers, ssh keys) — documented to run via a restricted sudoers entry or as root via systemd service, never storing credentials itself.

---

## 6. Dashboard Architecture

- **API layer** (`api/v1/`): REST endpoints split by resource (agents, servers, findings, scores, reports, auth). Agents POST scan payloads; frontend GETs everything else.
- **Service layer**: all business logic (scan ingestion, triggering, scoring, report generation) lives here — both the REST layer and MCP layer call into it, so behavior is identical whether triggered by a human or an AI.
- **Server-side modules** (`modules/`): interpret the raw facts an agent sends — e.g., `ssh/` module takes raw sshd_config key-values and turns them into findings by comparing against `baselines/<distro>.yaml`. This is where "chmod 777 detected" becomes a full finding with severity, why-it-matters, attack scenario, and recommendation (templated text, filled with the specific file/value).
- **Baseline engine**: loads distro-specific YAML baselines, exposes `compare(current, expected) -> diff` used by both scoring and `compare_to_baseline` MCP tool.
- **Scoring engine**: consumes findings + baseline diff, described in §7.
- **Frontend** (Next.js + Tailwind + Recharts): six pages as specified — Dashboard (overview + score gauges), Servers (fleet list + health), Findings (filterable table), Reports (generate/download), Settings (agents, API keys, users), Server Details (per-host score breakdown + finding list + scan history).

---

## 7. Security Score Algorithm

Two-level weighted scoring: per-category, then overall.

**Per-finding penalty weight by severity:**
```
critical = 25
high     = 15
medium   = 7
low      = 3
info     = 0
```

**Category score:**
```
category_score = max(0, 100 - Σ(penalty_weight for each open finding in category))
```
(Capped at 0 floor; a category with zero findings scores 100.)

**Category weights (overall score = weighted average):**
```
SSH          : 20%
Sudo         : 15%
Permissions  : 15%
Secrets      : 15%
Firewall     : 15%
Docker       : 10%
Kernel       : 5%
Cron         : 3%
Ownership    : 2%
```
Weights reflect typical real-world exploitation impact (e.g., SSH misconfig and leaked secrets are disproportionately dangerous vs. cron hygiene) and are stored in config so they're tunable, not hardcoded.

```
overall_score = Σ(category_score_i × category_weight_i)
```

Every score response includes the weight table and the finding list that drove each category's deduction, so the number is always explainable — not a black box.

---

## 8. Inter-Component Communication

1. **Agent → Dashboard**: outbound-only HTTPS POST, API-key authenticated (per-server key issued at registration), JSON payload matching the shared `ScanPayload` pydantic schema. No inbound ports needed on monitored hosts.
2. **Dashboard internal**: REST routes and MCP tools both call the **same service layer** functions — this is the key discipline that prevents logic drift between "the AI asked" and "the human clicked a button."
3. **Dashboard → Frontend**: standard REST + JWT, polling or simple refresh (no websockets needed for V1 given scan cadence is not sub-second).
4. **AI Clients → Dashboard**: MCP protocol (stdio for local dev, SSE/HTTP for hosted dashboard), scoped by the same auth as REST.
5. **Future modules → Core**: any V2+ module registers into `modules/registry.py` (dashboard side) and, if it needs host data, adds a new Guardian under `agent/collectors/` following `BaseGuardian`. Neither the scoring engine's weighting scheme nor the MCP tool surface needs to change shape to accommodate this — new categories just add entries to the weight table and new MCP tools follow the existing thin-adapter pattern.

---

This is the full V1 design. Nothing here implements auto-remediation (`generate_fix_plan`, `preview_fix`, `apply_fix`, `rollback` are stubbed as documented interfaces only, per your spec) — those are V2+ surface area we're deliberately not building yet.

**Next step, once you approve this:** I'd start with the shared payload contract (`ScanPayload` schemas) since both agent and dashboard depend on it, then build outward — Permission Guardian end-to-end (agent collector → dashboard module → finding → score) as the first vertical slice, then replicate the pattern for the remaining eight Guardians.
