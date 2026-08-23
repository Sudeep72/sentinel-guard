# SentinelGuard

**An AI-native Linux hardening platform.**

SentinelGuard audits Linux systems against secure-configuration baselines
and exposes the results through a REST API, a web dashboard, and the
Model Context Protocol (MCP) — so AI assistants like Claude, ChatGPT,
Cursor, and Gemini can answer "is my server secure?" with real,
structured data instead of guesswork.

> **Version 1 scope:** Linux hardening only. SentinelGuard v1 is **not**
> a vulnerability scanner, EDR, or SIEM, and does not perform
> auto-remediation. See [ROADMAP.md](./ROADMAP.md) for what's deliberately
> out of scope and why.

## What it does

A lightweight agent runs on each monitored host and audits nine areas of
Linux security posture. **All nine are implemented as of v1.0-dev (Phases 3A-3C):**

- **Permission Guardian** — world-writable/readable sensitive files, dangerous chmod bits
- **Ownership Guardian** — incorrect uid/gid, orphaned file ownership
- **SSH Guardian** — root login, password auth, empty passwords, weak ciphers/MACs, Protocol version, access restrictions
- **Sudo Guardian** — NOPASSWD rules, ALL=(ALL) ALL grants, shell-escapable commands, insecure permissions
- **Cron Guardian** — world-writable cron files/scripts, insecure directory/spool permissions
- **Secret Guardian** — SSH private keys, .env credentials, AWS/Azure/GCP keys, GitHub tokens, 18 secret patterns
- **Docker Guardian** — privileged containers, host namespace sharing, dangerous capabilities, root containers, dangerous host mounts, TCP socket exposure, unpinned image tags
- **Firewall Guardian** — no active firewall, default policy checks, SSH exposure, dangerous management ports — works across UFW, firewalld, iptables, and nftables
- **Kernel Guardian** — ASLR, ptrace restrictions, core dump restrictions, dmesg/kexec restrictions, IPv4/IPv6 hardening, kernel EOL version detection

The Guardian set for SentinelGuard v1.0 is complete, every scan is
automatically scored (0-100, overall + per-category, severity-weighted)
the moment it's submitted, and full reports (Executive/Technical/
Markdown/JSON) plus a web dashboard are available. Only release
preparation (Phase 21) remains — see [ROADMAP.md](./ROADMAP.md).

Every finding includes *why it matters*, a realistic *attack scenario*, and a
concrete *recommendation* — not just a raw config diff.

## Getting started

### Agent

```bash
pip install -e ./contracts
pip install -e "./agent[dev]"

# Run a real security scan (Permission, Ownership, SSH checked live)
sentinelguard-agent scan

# Output includes guardian_results with real findings
sentinelguard-agent scan | python3 -m json.tool | head -60
```

### Dashboard

```bash
pip install -e ./contracts
pip install -e "./dashboard[dev]"

cd dashboard && alembic upgrade head && cd ..
uvicorn app.main:app --reload --app-dir dashboard

# Create first admin user
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "changeme123", "role": "admin"}'

# Register an agent and get its API key
curl -X POST http://localhost:8000/api/v1/agents/register \
  -H "Content-Type: application/json" \
  -d '{"hostname": "myserver", "distro": "ubuntu", "distro_version": "24.04", "agent_version": "0.1.0"}'

# Submit a real scan from the agent
SENTINELGUARD_DASHBOARD_URL=http://localhost:8000 \
SENTINELGUARD_API_KEY=<key-from-registration> \
  sentinelguard-agent scan --submit

# View findings
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -d "username=admin@example.com&password=changeme123" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -s http://localhost:8000/api/v1/findings -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Compare against Ubuntu security baseline
curl -s "http://localhost:8000/api/v1/servers/<server-id>/baseline" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Get the security score — computed automatically the moment the scan
# above was submitted, no separate trigger needed
curl -s "http://localhost:8000/api/v1/servers/<server-id>/score" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### MCP server (Claude Desktop / Claude Code)

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -d "username=admin@example.com&password=changeme123" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

SENTINELGUARD_MCP_TOKEN=$TOKEN sentinelguard-mcp
```

Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "sentinelguard": {
      "command": "sentinelguard-mcp",
      "env": { "SENTINELGUARD_MCP_TOKEN": "<your-token>" }
    }
  }
}
```

Then ask Claude: *"Is my Ubuntu server secure?"*, *"List all critical findings"*,
*"Compare my server against the Ubuntu baseline"*.

### Web Dashboard

```bash
cd frontend
npm install
cp .env.example .env.local   # points at http://localhost:8000 by default
npm run dev
```

Open http://localhost:3000, sign in with the admin account created
above, and you'll land on the fleet Dashboard — score gauge, category
breakdown, severity chart, recent scans, with Servers/Findings/Reports/
Settings in the sidebar. See [frontend/README.md](./frontend/README.md)
for the design system and page-by-page breakdown.

## Architecture

Agent (collects facts) → Dashboard (orchestrates, scores, stores) → REST
API + MCP endpoint → AI clients / web UI.

Full design rationale, folder structure, database schema, MCP tool
contracts, and the scoring algorithm live in [ARCHITECTURE.md](./ARCHITECTURE.md)
and [docs/ARCHITECTURE_OVERVIEW.md](./docs/ARCHITECTURE_OVERVIEW.md)
(condensed, with real performance benchmarks).

More docs: [docs/API.md](./docs/API.md) (REST reference),
[docs/MCP.md](./docs/MCP.md) (MCP tool reference),
[DEMO.md](./DEMO.md) (scripted walkthrough with synthetic data),
[RELEASE_NOTES.md](./RELEASE_NOTES.md) (v1.0.0 highlights, known
limitations, v1.5 roadmap).

## Status

✅ **v1.0.0 released.** All nine Guardians, automatic scoring, baseline
comparison, four report formats, REST API, MCP server, and web
dashboard are implemented and tested (661+ automated tests across
`contracts`/`agent`/`dashboard`, 96–99% coverage per package). See
[CHANGELOG.md](./CHANGELOG.md) for the full history and
[ROADMAP.md](./ROADMAP.md) for what's planned beyond v1.0.

## License

MIT — see [LICENSE](./LICENSE).

## Security

Found a security issue in SentinelGuard itself? Please see
[SECURITY.md](./SECURITY.md) for responsible disclosure instructions —
do not open a public issue.
