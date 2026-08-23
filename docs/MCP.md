# SentinelGuard MCP Reference

SentinelGuard exposes 8 MCP tools, backed by the exact same
`app/services/` functions the REST API calls -- verified identical in
an automated end-to-end test
(`dashboard/tests/test_e2e/test_full_lifecycle.py`), not just assumed
by convention.

## Running the MCP server

```bash
# Get a JWT the same way a human user would
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -d "username=admin@example.com&password=yourpassword" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

SENTINELGUARD_MCP_TOKEN=$TOKEN sentinelguard-mcp
```

**Auth model:** unlike the REST API (a shared multi-client HTTP surface
authenticating every request independently), the MCP server
authenticates **once at process startup** by validating
`SENTINELGUARD_MCP_TOKEN` against the same `decode_access_token` REST
uses, then refuses to start if it's missing or invalid. This matches
the trust model of a locally-launched subprocess (the standard Claude
Desktop / Claude Code integration pattern) rather than a remote
multi-tenant service.

### Claude Desktop configuration

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

## Tools

### `health()`

Dashboard + database health. No arguments.

```json
{"status": "ok", "database": "ok"}
```

### `list_servers()`

Every server in the fleet. No arguments.

```json
{"servers": [{"id": "...", "hostname": "prod-web-01", "distro": "ubuntu", ...}]}
```

### `scan_server(server_id)`

Returns the **most recent known scan** for a server -- v1 has no
reverse channel to command an agent to scan on demand (Background
Workers / Job Scheduler are explicitly deferred to v2). This tool
honestly reports the latest push rather than pretending to trigger a
live one.

```json
{"available": true, "server": {...}, "scan": {"id": "...", "status": "completed", ...}}
```

### `get_security_score(server_id, scan_id=None)`

The same `SecurityScoreResponse` shape the REST `/score` endpoint
returns: overall score, 9 category scores, pass/fail counts, baseline
version.

### `list_findings(server_id=None, severity=None, category=None, status=None)`

Same filters as `GET /api/v1/findings`. All arguments optional.

### `explain_finding(finding_id)`

Full detail for one finding: description, why it matters, attack
scenario, current/expected values, recommendation.

### `compare_to_baseline(server_id, category=None)`

Per-rule current-vs-expected comparison against the server's distro
baseline, same shape as `GET /servers/{id}/baseline`.

### `generate_report(server_id, format="executive", scan_id=None)`

`format` is one of `executive`/`technical`/`json`/`markdown`. Returns
`{"available": true, "report": {...}}` with the rendered content.

## Error handling

Every tool catches `NotFoundError` and returns
`{"available": false, "message": "..."}` rather than raising an
exception through the MCP transport -- an AI client always gets a
structured, explainable answer instead of a stack trace.

## Example conversation

> **You:** Is my prod-web-01 server secure?
> **Claude:** *(calls `list_servers`, finds prod-web-01, calls
> `get_security_score`)* Its overall score is 93.1/100. The SSH
> category is at 85/100 due to one high-severity finding...
>
> **You:** What's the critical one?
> **Claude:** *(calls `list_findings` filtered to critical, then
> `explain_finding`)* SECRET-001: an unencrypted SSH private key at
> /root/.ssh/id_rsa with mode 0644...
