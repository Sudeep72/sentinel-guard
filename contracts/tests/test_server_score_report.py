from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sentinelguard_contracts import (
    CategoryScore,
    Distro,
    GuardianCategory,
    Report,
    ReportFormat,
    ReportRequest,
    SecurityScore,
    ServerInfo,
    ServerRegistration,
    ServerStatus,
)


def test_server_registration_minimal():
    reg = ServerRegistration(
        hostname="db01",
        distro=Distro.ROCKY,
        agent_version="0.1.0",
    )
    assert reg.ip_address is None
    assert reg.distro_version is None


def test_server_registration_rejects_empty_hostname():
    with pytest.raises(ValidationError):
        ServerRegistration(hostname="", distro=Distro.ROCKY, agent_version="0.1.0")


def test_server_info_full():
    info = ServerInfo(
        id="srv-1",
        hostname="db01",
        ip_address="10.0.0.5",
        distro=Distro.ROCKY,
        distro_version="9.4",
        agent_version="0.1.0",
        status=ServerStatus.ONLINE,
        last_seen_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
    )
    assert info.status == ServerStatus.ONLINE


def test_category_score_bounds():
    score = CategoryScore(category=GuardianCategory.SSH, score=72.5, weight=0.20)
    assert 0 <= score.score <= 100


@pytest.mark.parametrize("bad_score", [-1, 100.01, 150])
def test_category_score_rejects_out_of_bounds(bad_score):
    with pytest.raises(ValidationError):
        CategoryScore(category=GuardianCategory.SSH, score=bad_score, weight=0.2)


def test_category_score_rejects_zero_weight():
    with pytest.raises(ValidationError):
        CategoryScore(category=GuardianCategory.SSH, score=90, weight=0)


def test_security_score_aggregate():
    score = SecurityScore(
        scan_id="scan-1",
        overall_score=87.3,
        category_scores=[
            CategoryScore(category=GuardianCategory.SSH, score=72, weight=0.20),
            CategoryScore(category=GuardianCategory.FIREWALL, score=95, weight=0.15),
        ],
        computed_at=datetime.now(UTC),
    )
    assert len(score.category_scores) == 2


def test_report_request_defaults_scan_id_none():
    req = ReportRequest(server_id="srv-1", format=ReportFormat.EXECUTIVE)
    assert req.scan_id is None


def test_report_content_required():
    with pytest.raises(ValidationError):
        Report(
            server_id="srv-1",
            scan_id="scan-1",
            format=ReportFormat.JSON,
            generated_at=datetime.now(UTC),
            content="",
        )


def test_report_valid():
    report = Report(
        server_id="srv-1",
        scan_id="scan-1",
        format=ReportFormat.MARKDOWN,
        generated_at=datetime.now(UTC),
        content="# Report\n\nAll good.",
    )
    assert report.format == ReportFormat.MARKDOWN
