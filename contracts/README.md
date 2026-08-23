# sentinelguard-contracts

Shared pydantic models defining the wire-format contract between the
SentinelGuard Linux Agent and the SentinelGuard Dashboard.

## Why this package exists

Both the Agent and the Dashboard need to agree, byte-for-byte, on the
shape of a scan payload, a finding, a score, and a server record. Rather
than maintaining two hand-synced copies of these models (one in
`agent/`, one in `dashboard/`) and risking drift, both packages depend
on this single package as a local editable dependency.

This is a deliberate addition to the originally sketched folder layout
(which showed `schemas.py` living directly under the agent's
`transport/` directory) — see the Milestone Group 1 report in
`CHANGELOG.md` for the rationale.

## Contents

| Module | Contents |
|---|---|
| `enums.py` | `Severity`, `GuardianCategory`, `FindingStatus`, `ScanStatus`, `ServerStatus`, `Distro`, `ReportFormat` |
| `server.py` | `ServerRegistration`, `ServerInfo` |
| `finding.py` | `Finding` |
| `guardian.py` | `GuardianResult` |
| `scan.py` | `ScanPayload` |
| `score.py` | `CategoryScore`, `SecurityScore` |
| `report.py` | `ReportRequest`, `Report` |

## Versioning

This package is versioned independently. Both `agent` and `dashboard`
pin a compatible range in their `pyproject.toml`. Breaking changes to
any model bump the minor version pre-1.0.

## Installing (local development)

From the repo root:

```bash
pip install -e ./contracts
```

`agent/pyproject.toml` and `dashboard/pyproject.toml` both declare this
as a path dependency, so `pip install -e .` in either of those
directories pulls it in automatically.
