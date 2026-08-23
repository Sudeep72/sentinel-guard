"""Finding queries — list/filter and single-finding lookup.

Both the REST ``findings`` endpoints and the MCP ``list_findings`` /
``explain_finding`` tools call these two functions exclusively.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.finding import Finding as FindingModel
from app.schemas.findings import FindingRecord


def _to_record(row: FindingModel) -> FindingRecord:
    return FindingRecord.model_validate(row)


def list_findings(
    db: Session,
    server_id: str | None = None,
    scan_id: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
) -> list[FindingRecord]:
    """List findings, optionally filtered by server, scan, severity, category, or status.

    All filters are optional and combine with AND semantics.
    """
    query = db.query(FindingModel)
    if server_id is not None:
        query = query.filter(FindingModel.server_id == server_id)
    if scan_id is not None:
        query = query.filter(FindingModel.scan_id == scan_id)
    if severity is not None:
        query = query.filter(FindingModel.severity == severity)
    if category is not None:
        query = query.filter(FindingModel.module == category)
    if status is not None:
        query = query.filter(FindingModel.status == status)

    rows = query.order_by(FindingModel.created_at.desc()).all()
    return [_to_record(row) for row in rows]


def explain_finding(db: Session, finding_id: str) -> FindingRecord:
    """Fetch full detail for one finding.

    Raises:
        NotFoundError: If no finding with this id exists.
    """
    row = db.get(FindingModel, finding_id)
    if row is None:
        raise NotFoundError(f"No finding found with id {finding_id!r}")
    return _to_record(row)
