"""Business logic layer.

Both app/api/v1/ (REST) and app/mcp/tools/ (MCP) call into these
services exclusively — neither layer contains business logic of its
own. This is the mechanism that keeps "a human clicked a button" and
"an AI called a tool" behaviorally identical.
"""
