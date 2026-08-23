# SentinelGuard v1.0 — Architecture Overview

A condensed companion to the full [ARCHITECTURE.md](../ARCHITECTURE.md)
design doc, updated to reflect what was actually built across six
milestone groups, plus real performance data gathered during release
validation.

## The shape of the system

```
Linux Agent  --(HTTPS, API key)-->  Dashboard  <--(REST, JWT)-->  Web UI
   (9 Guardians)                  (FastAPI)     <--(MCP, JWT)-->  AI clients
                                        |
                                   SQLite (via SQLAlchemy + Alembic)
```

Four packages, one shared contract:

- **`contracts/`** -- pydantic wire-format models every other package
  imports. The single source of truth for what a `Finding`, a
  `ScanPayload`, a `SecurityScore` looks like.
- **`agent/`** -- runs on each monitored host. Nine `BaseGuardian`
  subclasses collect raw facts and emit `Finding` objects with
  preliminary severities. Pushes scans to the dashboard; never receives
  inbound connections.
- **`dashboard/`** -- the orchestrator. REST API and MCP server both
  call the **same service layer** (`app/services/`) -- this is the
  architectural guarantee that a human clicking a button and an AI
  calling a tool always get identical results, verified in an
  automated test, not just asserted in a docstring.
- **`frontend/`** -- Next.js web UI, consumes the REST API exclusively.
  No business logic duplicated client-side.

## Request flow: from scan to score

1. Agent detects distro, runs all 9 registered Guardians, aggregates
   results into a `ScanPayload`.
2. `POST /api/v1/agents/scans` (API-key auth) -- `scan_service.ingest_scan()`
   persists the `Scan` and `Finding` rows.
3. **Automatically**, in the same request, `scoring_service.compute_security_score()`
   runs: iterates all 9 `GuardianCategory` values generically (no
   per-Guardian code), sums severity penalties per category, computes
   the weighted overall score, and persists `CategoryScoreRecord` +
   `SecurityScoreRecord`. A scoring failure is caught and logged, never
   propagated -- the scan itself always succeeds independently.
4. Any subsequent `GET /score` (REST) or `get_security_score` (MCP)
   call reads the same persisted rows via `score_service.get_security_score()`.

## The service-layer guarantee

Every REST route and every MCP tool is a thin adapter. Business logic
lives exactly once, in `app/services/`:

| Service | Owns |
|---|---|
| `server_service.py` | Fleet registration, lookup |
| `scan_service.py` | Scan ingestion, triggers scoring |
| `finding_service.py` | Finding queries/filters |
| `baseline_service.py` | Baseline comparison (delegates to analyzer registry) |
| `baseline_engine_service.py` | Baseline versioning, DB snapshotting, custom overrides |
| `scoring_service.py` | Severity-weighted score computation |
| `score_service.py` | Score lookup (the READ half of scoring) |
| `report_service.py` | Report rendering (all 4 formats) |
| `auth_service.py` | User auth, bootstrap-admin rule |

## The Guardian pattern

Every Guardian follows the same shape (Permission Guardian is the
documented reference implementation):

```
agent/collectors/<name>_guardian.py   -- BaseGuardian subclass, emits Finding objects
dashboard/modules/<name>/analyzer.py  -- BaseAnalyzer subclass, applies baseline severity
dashboard/baselines/<distro>.yaml     -- expected values per rule, per distro
```

Nine Guardians, 58 distinct checks, zero per-Guardian scoring code --
the scoring engine iterates `GuardianCategory` generically.

## Performance characteristics

Measured on the development host during release validation (Python
3.12, SQLite, in-process where noted).

### Agent scan time (real host, all 9 Guardians)

| Guardian | Duration | Findings |
|---|---|---|
| Secret | 2170.8 ms | 6 |
| Permission | 304.7 ms | 7 |
| Kernel | 27.1 ms | 7 |
| Ownership | 3.5 ms | 0 |
| Firewall | 0.9 ms | 1 |
| Docker | 0.8 ms | 0 |
| Cron | 0.3 ms | 0 |
| SSH | 0.1 ms | 0 |
| Sudo | 0.1 ms | 0 |
| **Total** | **~2509 ms** | **21** |

Secret Guardian dominates because it recursively scans multiple
filesystem roots (`/root`, `/home`, `/etc`, `/opt`, `/var/www`, `/srv`)
looking for credential patterns -- cost scales with file count/size
under those paths, not with host complexity generally.

**Peak agent memory during a scan: ~30 MB RSS.**

### REST API latency (in-process ASGI, excludes network transport)

50 requests per endpoint, warm SQLite in-memory DB:

| Endpoint | p50 | p95 |
|---|---|---|
| `GET /health` | 2.7 ms | 3.4 ms |
| `GET /servers` | 4.5 ms | 5.1 ms |
| `GET /servers/{id}` | 4.3 ms | 5.4 ms |
| `GET /findings` | 4.3 ms | 5.6 ms |
| `GET /servers/{id}/score` | 5.2 ms | 6.2 ms |
| `GET /servers/{id}/baseline` | 5.7 ms | 7.3 ms |
| `GET /servers/{id}/report?format=json` | 8.2 ms | 9.4 ms |
| `POST /agents/scans` (ingest + auto-score) | 9.4 ms | 10.1 ms |

**Caveat:** these numbers are measured via Starlette's ASGI `TestClient`
transport (in-process, no real TCP socket, no TLS, no reverse proxy).
They isolate application-layer cost but exclude real network latency --
treat them as a lower bound / relative comparison between endpoints,
not a promise about production wall-clock response time.

### Frontend bundle size (production build)

```
+ First Load JS shared by all     87.3 kB
  - chunks/117-...js              31.7 kB
  - chunks/fd9d1056-...js         53.6 kB
Per-page First Load JS:           90-103 kB
```

All 10 routes build and prerender successfully; `npm run lint` reports
zero warnings.

## Database

SQLite via SQLAlchemy 2.0 + Alembic, synchronous engine (FastAPI runs
sync path functions in a threadpool -- a deliberate v1 choice, revisit
if request volume ever demands an async driver). Seven tables:
`servers`, `scans`, `findings`, `category_scores`, `security_scores`,
`baselines`, `users`. Two Alembic migrations track the schema from
initial creation through the Phase 17/18 additions (baseline
versioning/source, score pass/fail/total/baseline_version tracking).

## Security posture (v1)

- User passwords: bcrypt (adaptive hashing, appropriate for low-entropy
  human credentials).
- Agent API keys: SHA-256 (deterministic, appropriate for 256-bit
  random tokens -- enables O(1) lookup, which bcrypt's per-call salt
  would prevent).
- CORS defaults to `http://localhost:3000` only, not a wildcard.
- No raw SQL string interpolation anywhere -- SQLAlchemy ORM throughout.
- No hardcoded secrets in source; the JWT secret placeholder is
  documented as requiring override, and PyJWT itself warns if the
  configured key is under 32 bytes.
- No rate limiting (see Known Limitations in RELEASE_NOTES.md).
