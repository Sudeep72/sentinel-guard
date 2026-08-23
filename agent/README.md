# SentinelGuard Linux Agent

Collects Linux security posture data and submits it to the SentinelGuard
Dashboard. See [ARCHITECTURE.md](../ARCHITECTURE.md) section 5 for the
full design.

## Local development setup

This package depends on `sentinelguard-contracts` (the shared models
package). Install both as editable, contracts first:

```bash
pip install -e ../contracts
pip install -e ".[dev]"
```

## Running

```bash
# Run a scan and print the payload as JSON (no guardians registered yet
# as of Phase 3 — this is the framework; Guardians land in Phases 8-16)
sentinelguard-agent scan

# Configure via environment variables (see sentinelguard_agent/config.py)
export SENTINELGUARD_DASHBOARD_URL="https://dashboard.example.com"
export SENTINELGUARD_API_KEY="..."
sentinelguard-agent scan --submit

sentinelguard-agent version
```

## Testing

```bash
pytest --cov=sentinelguard_agent --cov-report=term-missing
```

## Package layout

```
sentinelguard_agent/
├── config.py            # AgentSettings (env-var driven, pydantic-settings)
├── logging_config.py     # structured JSON logging setup
├── main.py                # Typer CLI (scan, register, version)
├── aggregator.py           # merges Guardian results into a ScanPayload
├── collectors/
│   ├── base.py              # BaseGuardian abstract class
│   └── registry.py           # GUARDIAN_REGISTRY — Guardians register here (Phase 8+)
├── distro/
│   ├── detect.py              # /etc/os-release parsing
│   └── adapters.py             # per-distro path/command differences
└── transport/
    └── client.py                # DashboardClient (HTTPS, retry/backoff)
```
