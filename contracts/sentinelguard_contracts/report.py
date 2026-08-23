"""Report request/response models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from sentinelguard_contracts.enums import ReportFormat


class ReportRequest(BaseModel):
    """Input to the ``generate_report`` MCP tool / REST endpoint."""

    model_config = ConfigDict(str_strip_whitespace=True)

    server_id: str
    format: ReportFormat
    scan_id: str | None = None
    """If omitted, the dashboard uses the server's most recent completed scan."""


class Report(BaseModel):
    """A generated report."""

    model_config = ConfigDict(str_strip_whitespace=True)

    server_id: str
    scan_id: str
    format: ReportFormat
    generated_at: datetime
    content: str = Field(min_length=1)
    """Rendered report body. For JSON format this is a JSON-encoded string;
    for executive/technical/markdown it is the rendered document text."""
