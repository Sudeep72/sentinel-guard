"""Baseline comparison.

Delegates to the registered dashboard-side Guardian analyzers
(``app/modules/registry.py``).  Each analyzer's ``compare()`` method
returns ``BaselineComparisonItem`` objects for its category.  If no
analyzer is registered for a given category (future Guardians before
their analyzer lands), falls back to an empty result rather than
erroring.
"""

from __future__ import annotations

from sentinelguard_contracts import GuardianCategory
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.modules.registry import all_analyzers, get_analyzer
from app.schemas.baselines import BaselineComparisonResponse
from app.schemas.findings import FindingRecord
from app.services.finding_service import list_findings
from app.services.scan_service import get_latest_scan
from app.services.server_service import get_server_orm_or_none


def compare_to_baseline(
    db: Session, server_id: str, category: str | None = None
) -> BaselineComparisonResponse:
    """Compare a server's current findings against its distro's baseline.

    Raises:
        NotFoundError: If the server doesn't exist.
    """
    server = get_server_orm_or_none(db, server_id)
    if server is None:
        raise NotFoundError(f"No server registered with id {server_id!r}")

    latest_scan = get_latest_scan(db, server_id)
    if latest_scan is None:
        return BaselineComparisonResponse(
            available=False,
            server_id=server_id,
            distro=server.distro,
            message="No scans found for this server yet.",
        )

    all_findings = list_findings(db, server_id=server_id, scan_id=latest_scan.id)
    comparisons = []

    analyzers = all_analyzers()
    if category is not None:
        try:
            cat_enum = GuardianCategory(category)
            analyzer = get_analyzer(cat_enum)
            analyzers = [analyzer] if analyzer else []
        except ValueError:
            analyzers = []

    for analyzer in analyzers:
        cat_findings: list[FindingRecord] = [
            f for f in all_findings if f.module == analyzer.category
        ]
        items = analyzer.compare(cat_findings, server.distro, server.distro_version)
        comparisons.extend(items)

    if not comparisons:
        return BaselineComparisonResponse(
            available=False,
            server_id=server_id,
            distro=server.distro,
            message=(
                "No baseline rules found. This may mean no scan has been "
                "submitted yet, or no baseline is loaded for this distro/category."
            ),
        )

    return BaselineComparisonResponse(
        available=True,
        server_id=server_id,
        distro=server.distro,
        comparisons=comparisons,
    )
