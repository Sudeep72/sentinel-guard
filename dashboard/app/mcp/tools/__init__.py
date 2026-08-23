"""MCP tool implementations.

Every tool here is a thin adapter: open a DB session, call the same
`app/services/` function the REST API calls, translate the result (or
a `ServiceError`) into a plain JSON-serializable dict. No business
logic lives in this package.
"""
