"""Structured (JSON) logging setup for the agent.

Using JSON logs rather than free-text means agent logs can be shipped
and parsed by whatever the operator already uses (journald forwarding,
a log aggregator, etc.) without a custom parser.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class JsonFormatter(logging.Formatter):
    """Renders each log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(level: str = "INFO") -> None:
    """Configure the root logger to emit JSON lines to stderr.

    Deliberately stderr, not stdout: `sentinelguard-agent scan` promises
    that stdout contains ONLY the ScanPayload JSON (so it's safe to pipe
    into `jq`/`python3 -m json.tool`/a file). Any ERROR-level log line
    from a Guardian encountering a real permission-denied path (which
    only happens when running as a non-root user, e.g. scanning /root/.ssh)
    must not corrupt that stdout stream.

    Idempotent — safe to call multiple times (e.g. once from the CLI
    entrypoint, and again from tests) without duplicating handlers.
    """
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
