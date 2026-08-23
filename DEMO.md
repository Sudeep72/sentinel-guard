# SentinelGuard Demo Walkthrough

A scripted tour using synthetic findings, for when you want to see the
full picture (multiple servers, a mix of severities, a real score
below 100, real baseline deviations) without waiting on a real scan or
needing a spare Linux box.

This script is genuinely runnable -- it's a trimmed version of the
project's own end-to-end release-validation test
(`dashboard/tests/test_e2e/test_full_lifecycle.py`), which is part of
the tested codebase, not a documentation-only sketch.

## Setup

```bash
pip install -e ./contracts
pip install -e "./dashboard[dev]"
cd dashboard && alembic upgrade head && uvicorn app.main:app &
cd ..
```

## 1. Bootstrap an admin and log in

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "DemoPass123!", "role": "admin"}'

TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -d "username=admin@example.com&password=DemoPass123!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

## 2. Register two servers -- a fleet, not just one host

```bash
WEB=$(curl -s -X POST http://localhost:8000/api/v1/agents/register \
  -H "Content-Type: application/json" \
  -d '{"hostname": "prod-web-01", "ip_address": "10.0.1.5", "distro": "ubuntu", "distro_version": "24.04", "agent_version": "1.0.0"}')
WEB_KEY=$(echo "$WEB" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
WEB_ID=$(echo "$WEB" | python3 -c "import sys,json; print(json.load(sys.stdin)['server']['id'])")

DB=$(curl -s -X POST http://localhost:8000/api/v1/agents/register \
  -H "Content-Type: application/json" \
  -d '{"hostname": "prod-db-01", "distro": "rocky", "distro_version": "9.4", "agent_version": "1.0.0"}')
DB_KEY=$(echo "$DB" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
DB_ID=$(echo "$DB" | python3 -c "import sys,json; print(json.load(sys.stdin)['server']['id'])")
```

## 3. Submit a scan for `prod-web-01` with realistic findings

Three findings across three Guardians: an exposed SSH root login
(high), an unprotected SSH private key (critical), and disabled ASLR
(low) -- the exact scenario exercised by the automated E2E test.

```bash
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
curl -s -X POST http://localhost:8000/api/v1/agents/scans \
  -H "Authorization: Bearer $WEB_KEY" -H "Content-Type: application/json" -d "{
  \"server_id\": \"$WEB_ID\", \"hostname\": \"prod-web-01\", \"distro\": \"ubuntu\",
  \"distro_version\": \"24.04\", \"agent_version\": \"1.0.0\",
  \"started_at\": \"$NOW\", \"completed_at\": \"$NOW\", \"status\": \"completed\",
  \"guardian_results\": [
    {\"module\": \"ssh\", \"status\": \"ok\", \"collected_at\": \"$NOW\", \"findings\": [
      {\"check_id\": \"SSH-001\", \"module\": \"ssh\", \"title\": \"SSH root login is permitted\",
       \"severity\": \"high\", \"description\": \"PermitRootLogin is set to yes.\",
       \"why_it_matters\": \"Eliminates the audit trail from su/sudo.\",
       \"attack_scenario\": \"Attacker with leaked root password gets a shell directly.\",
       \"recommendation\": \"Set PermitRootLogin no.\", \"current_value\": \"yes\", \"expected_value\": \"no\"}
    ]},
    {\"module\": \"secret\", \"status\": \"ok\", \"collected_at\": \"$NOW\", \"findings\": [
      {\"check_id\": \"SECRET-001\", \"module\": \"secret\", \"title\": \"SSH private key file exposed\",
       \"severity\": \"critical\", \"description\": \"Unencrypted key at /root/.ssh/id_rsa.\",
       \"why_it_matters\": \"Anyone with read access can authenticate as root.\",
       \"attack_scenario\": \"Attacker copies the key and authenticates elsewhere.\",
       \"recommendation\": \"chmod 600, rotate the key.\", \"current_value\": \"mode=0644\", \"expected_value\": \"mode=0600\"}
    ]},
    {\"module\": \"kernel\", \"status\": \"ok\", \"collected_at\": \"$NOW\", \"findings\": [
      {\"check_id\": \"KERNEL-001\", \"module\": \"kernel\", \"title\": \"ASLR is not fully enabled\",
       \"severity\": \"low\", \"description\": \"kernel.randomize_va_space=1\",
       \"why_it_matters\": \"Reduces exploit mitigation effectiveness.\",
       \"attack_scenario\": \"Predictable memory layout aids overflow exploits.\",
       \"recommendation\": \"sysctl -w kernel.randomize_va_space=2\", \"current_value\": \"1\", \"expected_value\": \"2\"}
    ]}
  ]
}"
```

## 4. Submit a clean scan for `prod-db-01`

```bash
curl -s -X POST http://localhost:8000/api/v1/agents/scans \
  -H "Authorization: Bearer $DB_KEY" -H "Content-Type: application/json" -d "{
  \"server_id\": \"$DB_ID\", \"hostname\": \"prod-db-01\", \"distro\": \"rocky\",
  \"distro_version\": \"9.4\", \"agent_version\": \"1.0.0\",
  \"started_at\": \"$NOW\", \"completed_at\": \"$NOW\", \"status\": \"completed\",
  \"guardian_results\": []
}"
```

## 5. See the fleet split

```bash
# prod-web-01: 3 findings, score below 100
curl -s "http://localhost:8000/api/v1/servers/$WEB_ID/score" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# prod-db-01: clean, score exactly 100
curl -s "http://localhost:8000/api/v1/servers/$DB_ID/score" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Only critical findings, fleet-wide
curl -s "http://localhost:8000/api/v1/findings?severity=critical" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

## 6. Generate all four report formats

```bash
for FORMAT in executive technical markdown json; do
  curl -s "http://localhost:8000/api/v1/servers/$WEB_ID/report?format=$FORMAT" \
    -H "Authorization: Bearer $TOKEN" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['content'])" \
    > "sample-report-$FORMAT.$([ $FORMAT = json ] && echo json || echo md)"
done
```

Sample outputs from exactly this scenario are checked into
[`docs/samples/`](./docs/samples/) for reference without running
anything.

## 7. Ask an AI assistant about it

With `sentinelguard-mcp` running and pointed at this same dashboard
(see [QUICKSTART.md](./QUICKSTART.md) step 8):

> "Compare my fleet -- which server needs attention?"
> "Show me the critical finding on prod-web-01 in detail."
> "Generate an executive report for prod-web-01."

Claude will call `list_servers`, `list_findings`, `explain_finding`,
and `generate_report` -- the exact same service-layer functions the
`curl` commands above hit via REST.
