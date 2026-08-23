# api/

REST API layer, versioned under `v1/`. Routes are thin — they validate
input via pydantic schemas and delegate to `app/services/`. No business
logic lives in this layer. Populated starting Phase 4.

Endpoints (Phase 4+):
- agents.py    — agent registration + scan ingest
- servers.py   — server CRUD/listing
- findings.py  — finding queries
- scores.py    — score retrieval
- reports.py   — report generation/download
- auth.py      — login/token issuance (Phase 6)
