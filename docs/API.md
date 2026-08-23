# SentinelGuard REST API Reference

Base URL: `http://localhost:8000` (default local dev). Interactive
OpenAPI docs are auto-generated at `/docs` (Swagger UI) and `/redoc`
whenever the dashboard is running -- this document is a narrative
companion, not a replacement.

All request/response bodies use the shared `sentinelguard-contracts`
models where applicable (see `contracts/README.md`), so the agent, the
REST API, and the MCP server all agree on shape.

## Authentication

Two independent schemes:

| Who | Scheme | Header |
|---|---|---|
| Human users | JWT bearer | `Authorization: Bearer <jwt>` |
| Agents | API key bearer | `Authorization: Bearer <api-key>` |

A user JWT never works on agent-only endpoints and vice versa --
enforced by two separate FastAPI dependencies (`get_current_user`,
`get_current_server`), not just documentation convention.

### Get a user JWT

```
POST /api/v1/auth/token
Content-Type: application/x-www-form-urlencoded

username=admin@example.com&password=yourpassword
```

Returns `{"access_token": "...", "token_type": "bearer"}`.

### Bootstrap the first admin

```
POST /api/v1/auth/register
Content-Type: application/json

{"email": "admin@example.com", "password": "changeme123", "role": "admin"}
```

The **first** user ever created is always granted `admin`, regardless
of the `role` field. Every subsequent call to this endpoint requires an
authenticated admin.

## Endpoints

### Health

`GET /api/v1/health` -- no auth. Returns `{"status": "ok", "database": "ok"}`.

### Agents (called by the agent CLI, not humans)

`POST /api/v1/agents/register` -- no auth (an agent has no credentials
yet). Body: `ServerRegistration` (hostname, distro, distro_version,
agent_version, optional ip_address). Returns the assigned `ServerInfo`
plus a plaintext `api_key` shown **exactly once** -- store it, it
cannot be retrieved again.

`POST /api/v1/agents/scans` -- API key auth. Body: `ScanPayload`. The
scan is always attributed to whichever server the API key belongs to,
**never** to whatever `server_id` the payload claims -- one agent
cannot submit data for another server. Triggers automatic scoring.
Returns `{"scan_id": "...", "status": "accepted"}` with `202 Accepted`.

### Servers

`GET /api/v1/servers` -- JWT auth. Lists the whole fleet.

`GET /api/v1/servers/{id}` -- JWT auth. Single server detail.

`GET /api/v1/servers/{id}/scans` -- JWT auth. Scan history, most recent first.

`GET /api/v1/servers/{id}/score` -- JWT auth. Optional `?scan_id=` (defaults to
latest). Returns `SecurityScoreResponse`: `available`, `score` (overall +
9 category scores), `total_checks`/`passed_checks`/`failed_checks`,
`baseline_version`.

`GET /api/v1/servers/{id}/baseline` -- JWT auth. Optional `?category=` to
scope to one Guardian category. Returns per-rule current-vs-expected
comparisons with a `matches_baseline` flag per rule.

`GET /api/v1/servers/{id}/report` -- JWT auth. Query params: `format`
(`executive` | `technical` | `markdown` | `json`, default `executive`),
optional `scan_id`. Returns a `Report` object whose `content` field
holds the rendered report body.

### Findings

`GET /api/v1/findings` -- JWT auth. Query filters (all optional,
combine with AND): `server_id`, `severity`, `category`, `status`.

`GET /api/v1/findings/{id}` -- JWT auth. Full detail for one finding
(why it matters, attack scenario, recommendation, current/expected
values).

## Error format

Non-2xx responses return `{"detail": "human-readable message"}`.
`404` for missing resources, `401` for missing/invalid credentials,
`403` for insufficient role, `422` for request validation failures
(FastAPI's standard pydantic validation error shape).

## Pagination

Not implemented in v1 -- `list_findings`/`list_servers` return
everything matching the filter. Acceptable at v1 fleet scale; revisit
if a deployment's finding count grows large enough to matter.

## Rate limiting

Not implemented in v1 -- see RELEASE_NOTES.md Known Limitations.
