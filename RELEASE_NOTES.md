# SentinelGuard v1.0.0 — Release Notes

**Release date:** July 2026
**Codename:** none — this is the first stable release.

SentinelGuard is an AI-native Linux hardening platform. A lightweight
agent audits nine areas of Linux security posture, a FastAPI dashboard
orchestrates fleet-wide scoring and reporting, and both a REST API and
an MCP server expose the same data to humans and AI assistants alike.

This is the first release where every planned v1.0 capability is
implemented, tested, and documented.

## Highlights

- **Nine security Guardians**, 58 distinct checks: Permission, Ownership,
  SSH, Sudo, Cron, Secret, Docker, Firewall, Kernel — covering
  everything from world-writable `/etc/shadow` to privileged Docker
  containers to missing SYN-flood protection.
- **Automatic, severity-weighted scoring** (0–100, overall + 9 category
  scores) computed the instant a scan is submitted — no manual trigger.
- **Distro-aware baselines** (Ubuntu, Debian, Fedora, Rocky, CentOS)
  with a versioned, DB-snapshotted Baseline Engine and a tested
  extension point for future custom organization baselines.
- **Four report formats** (Executive, Technical, Markdown, JSON), each
  including server info, score, severity summary, findings grouped by
  category, baseline comparison, and generation metadata.
- **A web dashboard** (Next.js) — fleet overview, per-server drill-down,
  filterable findings, report generation, all backed by the same REST
  API a script or `curl` command would use.
- **An MCP server** with 8 tools, so Claude (or any MCP-compatible AI
  client) can answer "is my server secure?" using the exact same
  service layer as the REST API and the web UI — verified identical in
  an automated end-to-end test, not just assumed.
- **Multi-server fleet support** from day one, with API-key-authenticated
  agents and strict per-server data isolation (one compromised agent
  key cannot see or affect another server's data) — proven in an
  automated test with two servers, one attacked, one clean.

## What's included

| Component | Description |
|---|---|
| `contracts/` | Shared pydantic wire-format models (agent <-> dashboard) |
| `agent/` | Linux Agent — 9 Guardian collectors, CLI, HTTPS transport |
| `dashboard/` | FastAPI backend — REST API, MCP server, scoring, reports |
| `frontend/` | Next.js web dashboard |

## Installation

See [QUICKSTART.md](./QUICKSTART.md) for a 10-minute path from zero to
a scored server. See [DEMO.md](./DEMO.md) for a scripted walkthrough
using synthetic findings if you don't have a spare Linux box handy.

## Upgrade notes

This is the first stable release — there is no prior version to
upgrade from. Package versions across `contracts`, `agent`, and
`dashboard` are aligned at `1.0.0`; the frontend is versioned
independently at `1.0.0` as well.

## Performance

Benchmarked on the development host (details and methodology in
[docs/ARCHITECTURE_OVERVIEW.md](./docs/ARCHITECTURE_OVERVIEW.md)):

- Full 9-Guardian scan: **~2.5 seconds** (dominated by the Secret
  Guardian's recursive filesystem scan — see Known Limitations)
- Agent peak memory during a scan: **~30 MB**
- REST API request latency (in-process, excludes network transport):
  **2–10 ms** across all endpoints, including the full scan-ingest +
  automatic-scoring path
- Frontend production bundle: **87.3 KB** shared JS, 90–103 KB per page

## Known limitations

The most operationally relevant v1.0 limitations:

- **No rate limiting** on the REST API — appropriate for a
  single-organization internal dashboard, not for exposing the API
  directly to the public internet without a reverse-proxy rate limiter
  in front of it.
- **Secret Guardian performance** scales with the number/size of files
  under its scan roots (`/root`, `/home`, `/etc`, `/opt`, `/var/www`,
  `/srv`); it is the dominant cost in a full scan (~2.2s of the ~2.5s
  total in our benchmark). Consider this when scheduling scan frequency
  on hosts with very large home directories.
- **No on-demand remote scan triggering** — agents push scans on their
  own schedule (cron/systemd timer); the dashboard cannot command an
  agent to scan immediately. This is a deliberate v1 scope boundary
  (Background Workers / Job Scheduler are v2), not an oversight.
- **Custom organization baseline overrides** are implemented and tested
  at the service layer (`baseline_engine_service.py`) but not yet wired
  into the nine Guardian analyzers' live comparison calls, and have no
  REST/MCP management surface yet.
- **Single JWT secret, no key rotation** — `SENTINELGUARD_JWT_SECRET_KEY`
  must be set to a real secret in any non-local deployment (the default
  is a placeholder that PyJWT will warn about if too short, but will
  not stop you from running with it).

## What's next — v1.5 roadmap

See [ROADMAP.md](./ROADMAP.md) for the full picture. Near-term
candidates for v1.5/v2:

- Vulnerability scanning (CVE/EPSS/KEV correlation)
- Auto-remediation (`generate_fix_plan`, `preview_fix`, `apply_fix`,
  `rollback` — interfaces already sketched, no implementation yet)
- Background job scheduler enabling on-demand remote scan triggering
- Custom baseline management REST/MCP surface (the service-layer
  mechanism already exists)
- Compliance framework mappings (CIS, PCI-DSS)
- Fleet analytics and historical trend dashboards

## Thanks

SentinelGuard v1.0 represents six milestone groups of incremental,
test-driven development — every phase built on a green test suite, and
every milestone group ended with 95%+ coverage and clean Ruff/Black/
MyPy strict gates maintained throughout.
