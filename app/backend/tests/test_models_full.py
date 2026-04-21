import pytest
from unittest.mock import patch, MagicMock, mock_open
from app.db import models


def test_scan_model_full():
    scan = models.Scan(
        id="test-scan-full",
        mode="agent",
        target_name="remote-host",
        status="running",
        machine_hostname="test-host",
        machine_id="machine-123",
        distro="Ubuntu 22.04",
        security_score=85.5,
        performance_score=90.0,
        overall_score=87.5,
        summary={"key": "value"},
        raw_payload={"data": "test"},
    )
    assert scan.id == "test-scan-full"
    assert scan.mode == "agent"
    assert scan.security_score == 85.5


def test_finding_with_all_fields():
    finding = models.Finding(
        scan_id="test-123",
        check_id="FULL_CHECK",
        domain="security",
        category="network",
        severity="CRIT",
        title="Complete Finding",
        evidence="full evidence",
        recommendation="full recommendation",
        reference="https://example.com",
        rationale="full rationale",
        weight=2.5,
        extra_data={"metadata": "data"},
    )
    assert finding.check_id == "FULL_CHECK"
    assert finding.extra_data == {"metadata": "data"}


def test_recommendation_with_all_fields():
    rec = models.Recommendation(
        scan_id="test-123",
        title="Complete Rec",
        priority="critical",
        risk="high",
        impact="high",
        effort="medium",
        domain="security",
        action="complete action",
        reason="complete reason",
        source_check_id="CHECK_FULL",
        extra_data={"steps": ["step1", "step2"]},
    )
    assert rec.source_check_id == "CHECK_FULL"
    assert rec.extra_data == {"steps": ["step1", "step2"]}


def test_artifact_all_types():
    for artifact_type in ["json", "pdf", "html"]:
        artifact = models.Artifact(
            scan_id="test-123",
            artifact_type=artifact_type,
            file_name=f"test.{artifact_type}",
            file_path=f"/exports/test.{artifact_type}",
            content_type=f"application/{artifact_type}",
        )
        assert artifact.artifact_type == artifact_type


def test_scan_relationships():
    scan = models.Scan(
        id="test-rel-123",
        mode="agentless",
        target_name="localhost",
        status="completed"
    )
    findings = [
        models.Finding(
            scan_id="test-rel-123",
            check_id=f"CHECK_{i}",
            domain="test",
            category="test",
            severity="HIGH",
            title=f"Finding {i}",
            evidence="evidence",
            recommendation="rec",
            reference="ref",
            rationale="rationale",
            weight=1.0,
        )
        for i in range(3)
    ]
    assert len(findings) == 3
    assert all(f.scan_id == scan.id for f in findings)


def test_scan_with_recommendations():
    scan = models.Scan(
        id="test-rec-123",
        mode="agentless",
        target_name="localhost",
        status="completed"
    )
    recommendations = [
        models.Recommendation(
            scan_id="test-rec-123",
            title=f"Recommendation {i}",
            priority="high",
            risk="medium",
            impact="low",
            effort="low",
            domain="test",
            action="action",
            reason="reason",
            source_check_id=f"CHECK_{i}",
        )
        for i in range(2)
    ]
    assert len(recommendations) == 2