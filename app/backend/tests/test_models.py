from app.db import models


def test_scan_model_creation():
    scan = models.Scan(
        id="test-123",
        mode="agentless",
        target_name="localhost",
        status="queued"
    )
    assert scan.id == "test-123"
    assert scan.mode == "agentless"
    assert scan.status == "queued"


def test_finding_model_creation():
    finding = models.Finding(
        scan_id="test-123",
        check_id="TEST_001",
        domain="security",
        category="access",
        severity="high",
        title="Test Finding",
        evidence="evidence",
        recommendation="recommendation",
        reference="reference",
        rationale="rationale",
        weight=1.0,
    )
    assert finding.check_id == "TEST_001"
    assert finding.severity == "high"


def test_recommendation_model_creation():
    recommendation = models.Recommendation(
        scan_id="test-123",
        title="Test Recommendation",
        priority="high",
        risk="medium",
        impact="medium",
        effort="low",
        domain="security",
        action="action",
        reason="reason",
        source_check_id="TEST_001",
    )
    assert recommendation.title == "Test Recommendation"
    assert recommendation.priority == "high"


def test_artifact_model_creation():
    artifact = models.Artifact(
        scan_id="test-123",
        artifact_type="json",
        file_name="test.json",
        file_path="/exports/test.json",
        content_type="application/json",
    )
    assert artifact.artifact_type == "json"
    assert artifact.file_name == "test.json"


def test_scan_relationship_with_findings():
    scan = models.Scan(id="test-123", mode="agentless", target_name="localhost", status="queued")
    finding = models.Finding(
        scan_id="test-123",
        check_id="TEST_001",
        domain="security",
        category="access",
        severity="high",
        title="Test",
        evidence="evidence",
        recommendation="recommendation",
        reference="reference",
        rationale="rationale",
        weight=1.0,
    )
    assert finding.scan_id == scan.id