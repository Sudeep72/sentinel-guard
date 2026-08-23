# mcp/

MCP server bootstrap (`server.py`) and tool implementations under `tools/`.
Every tool is a thin adapter that calls into `app/services/` — identical
business logic whether a request comes from the REST API or an AI client.
Populated in Phase 7.

Tools: scan_system, get_security_score, list_findings, explain_finding,
compare_to_baseline, generate_report, health.
