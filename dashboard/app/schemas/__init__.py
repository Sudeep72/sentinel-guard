"""REST-only request/response DTOs.

Shared wire-format objects (Finding, ScanPayload, ServerInfo, etc.) come
from the `sentinelguard_contracts` package, not from here — this
package only holds shapes specific to the REST layer (auth tokens,
paginated list wrappers) that have no reason to exist in the shared
contract used by the Agent and MCP tools.
"""
