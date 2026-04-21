from app.schemas.scan import (
    ScanCreateRequest,
    ScanCreateResponse,
    ScanStatusResponse,
    ScoreBreakdown,
    ScanResultResponse,
    HistoryItem,
    HistoryResponse,
    ExportArtifactResponse,
    FindingResponse,
    RecommendationResponse,
)


def test_scan_create_request():
    req = ScanCreateRequest(mode="agentless", target_name="localhost")
    assert req.mode == "agentless"
    assert req.target_name == "localhost"


def test_scan_create_request_defaults():
    req = ScanCreateRequest()
    assert req.mode == "agentless"
    assert req.target_name is None


def test_scan_create_response():
    from datetime import datetime
    resp = ScanCreateResponse(
        scan_id="test-123",
        status="queued",
        mode="agentless",
        created_at=datetime.now()
    )
    assert resp.scan_id == "test-123"
    assert resp.status == "queued"


def test_scan_status_response():
    from datetime import datetime
    resp = ScanStatusResponse(
        scan_id="test-123",
        status="completed",
        mode="agentless",
        started_at=datetime.now()
    )
    assert resp.scan_id == "test-123"
    assert resp.status == "completed"


def test_score_breakdown():
    score = ScoreBreakdown(
        security=85.0,
        performance=90.0,
        overall=87.0,
        explanation={"test": "value"}
    )
    assert score.security == 85.0
    assert score.overall == 87.0


def test_history_item():
    from datetime import datetime
    item = HistoryItem(
        scan_id="test-123",
        status="completed",
        mode="agentless",
        machine_hostname="test-host",
        machine_id="id-123",
        overall_score=85.0,
        security_score=80.0,
        performance_score=90.0,
        started_at=datetime.now()
    )
    assert item.scan_id == "test-123"


def test_history_response():
    resp = HistoryResponse(items=[])
    assert resp.items == []


def test_export_artifact_response():
    resp = ExportArtifactResponse(
        scan_id="test-123",
        artifact_type="json",
        file_name="test.json",
        file_path="/exports/test.json",
        content_type="application/json"
    )
    assert resp.artifact_type == "json"


def test_finding_response():
    finding = FindingResponse(
        id=1,
        check_id="TEST_001",
        domain="security",
        category="access",
        severity="HIGH",
        title="Test Finding",
        evidence="evidence",
        recommendation="recommendation",
        reference="reference",
        rationale="rationale",
        weight=1
    )
    assert finding.check_id == "TEST_001"


def test_recommendation_response():
    rec = RecommendationResponse(
        id=1,
        title="Test Rec",
        priority="high",
        risk="medium",
        impact="medium",
        effort="low",
        domain="security",
        action="action",
        reason="reason"
    )
    assert rec.title == "Test Rec"


def test_scan_result_response():
    from datetime import datetime
    resp = ScanResultResponse(
        scan_id="test-123",
        status="completed",
        mode="agentless",
        machine_hostname="test-host",
        machine_id="id-123",
        distro="Ubuntu 22.04",
        started_at=datetime.now(),
        completed_at=datetime.now(),
        summary={},
        scores=None,
        findings=[],
        recommendations=[],
        raw_payload={}
    )
    assert resp.scan_id == "test-123"
    assert resp.distro == "Ubuntu 22.04"