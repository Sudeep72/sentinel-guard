# SentinelGuard Quickstart

Zero to a scored server in about 10 minutes. Every command below is
real and has been run as part of this project's own test suite -- this
isn't aspirational documentation.

## Prerequisites

- Python 3.11+
- Node.js 18+ (for the web dashboard)
- A Linux host to scan (the agent runs natively; it can scan the
  machine you're already on)

## 1. Install the shared contracts package

Both the agent and dashboard depend on this -- install it first.

```bash
git clone <this-repo-url> sentinelguard && cd sentinelguard
pip install -e ./contracts
```

## 2. Start the dashboard

```bash
pip install -e "./dashboard[dev]"
cd dashboard
alembic upgrade head
uvicorn app.main:app --reload &
cd ..
```

The API is now live at `http://localhost:8000`. Interactive docs at
`http://localhost:8000/docs`.

## 3. Create your admin account

The first user ever registered is automatically granted admin -- no
separate bootstrap step:

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "changeme123", "role": "admin"}'
```

## 4. Install and run the agent

```bash
pip install -e "./agent[dev]"
sentinelguard-agent scan
```

You'll see a JSON `ScanPayload` printed with real findings from
whatever host you ran this on -- the agent detects your distro
automatically and runs all nine Guardians.

## 5. Register the agent and submit a real scan

```bash
REG=$(curl -s -X POST http://localhost:8000/api/v1/agents/register \
  -H "Content-Type: application/json" \
  -d '{"hostname": "'"$(hostname)"'", "distro": "ubuntu", "distro_version": "24.04", "agent_version": "1.0.0"}')

API_KEY=$(echo "$REG" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
SERVER_ID=$(echo "$REG" | python3 -c "import sys,json; print(json.load(sys.stdin)['server']['id'])")

SENTINELGUARD_DASHBOARD_URL=http://localhost:8000 \
SENTINELGUARD_API_KEY=$API_KEY \
  sentinelguard-agent scan --submit
```

The scan is now stored, and its security score was **computed
automatically** -- no separate step.

## 6. Look at the results

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -d "username=admin@example.com&password=changeme123" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s "http://localhost:8000/api/v1/servers/$SERVER_ID/score" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

curl -s "http://localhost:8000/api/v1/findings?server_id=$SERVER_ID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

curl -s "http://localhost:8000/api/v1/servers/$SERVER_ID/baseline" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

curl -s "http://localhost:8000/api/v1/servers/$SERVER_ID/report?format=executive" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['content'])"
```

## 7. Open the web dashboard

```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
```

Open `http://localhost:3000`, sign in with the admin account from step
3, and you'll see your server's score, findings, and baseline
comparison rendered -- all from the same data you just queried by hand.

## 8. Connect an AI assistant via MCP

```bash
SENTINELGUARD_MCP_TOKEN=$TOKEN sentinelguard-mcp
```

Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "sentinelguard": {
      "command": "sentinelguard-mcp",
      "env": { "SENTINELGUARD_MCP_TOKEN": "<token-from-step-6>" }
    }
  }
}
```

Then ask: *"Is my server secure?"* or *"What are my critical findings?"*

## What's next

- [DEMO.md](./DEMO.md) -- a scripted walkthrough with synthetic
  findings, useful if you don't want to scan a real machine yet.
- [docs/API.md](./docs/API.md) -- full REST API reference.
- [docs/MCP.md](./docs/MCP.md) -- MCP tool reference.
- [docs/ARCHITECTURE_OVERVIEW.md](./docs/ARCHITECTURE_OVERVIEW.md) --
  how it all fits together.
- [ARCHITECTURE.md](./ARCHITECTURE.md) -- the original detailed design doc.

## Troubleshooting

**"No module named sentinelguard_contracts"** -- install `contracts/`
before `agent/` or `dashboard/`; both depend on it as a local package.

**JWT key length warning** -- the default `JWT_SECRET_KEY` is a
placeholder under 32 bytes for HS256's recommended minimum. Generate a
real one: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`
and set it via `SENTINELGUARD_JWT_SECRET_KEY`.

**Score shows "not yet computed"** -- this should not happen in normal
operation (scoring is automatic). If you see it, check the dashboard
logs -- scoring failures are caught and logged rather than blocking scan
ingestion, so the scan itself will have succeeded even if scoring
didn't; see [RELEASE_NOTES.md](./RELEASE_NOTES.md) known limitations.
