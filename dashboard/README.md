# SentinelGuard Dashboard

The orchestrator: REST API, database, authentication, and MCP server
for the SentinelGuard platform. See [ARCHITECTURE.md](../ARCHITECTURE.md)
section 6 for the full design.

## Local development setup

Depends on `sentinelguard-contracts`. Install both, contracts first:

```bash
pip install -e ../contracts
pip install -e ".[dev]"
```

## Running

```bash
# Apply database migrations
alembic upgrade head

# Start the REST API (http://localhost:8000, docs at /docs)
uvicorn app.main:app --reload

# Or via the console script (creates tables directly if migrations
# haven't been run — dev convenience only, see app/main.py run())
sentinelguard-dashboard
```

### First-time setup: create an admin user

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "changeme123", "role": "admin"}'
```

The very first user created is always granted `admin`, regardless of
the requested role — see `app/services/auth_service.py`.

### Running the MCP server

```bash
# Get a token first
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -d "username=admin@example.com&password=changeme123" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

SENTINELGUARD_MCP_TOKEN=$TOKEN sentinelguard-mcp
```

## Testing

```bash
pytest --cov=app --cov-report=term-missing
```

## Package layout

```
app/
├── main.py             # FastAPI app factory
├── config.py             # Settings (env-driven)
├── api/v1/                 # REST routes — thin, delegate to services/
├── services/                 # Business logic — REST and MCP both call this
├── mcp/                        # MCP server + tools (thin adapters over services/)
├── models/                       # SQLAlchemy ORM models
├── schemas/                        # REST-only DTOs (auth, list wrappers)
├── auth/                             # JWT (users) + API-key (agents)
├── db/                                 # Engine, session, Alembic migrations
└── core/                                # Logging, shared exception types
```
