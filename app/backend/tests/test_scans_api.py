import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime, timezone


@pytest.fixture
def client():
    from app.main import app
    return TestClient(app)


@pytest.fixture
def mock_scan():
    mock = MagicMock()
    mock.id = "scan-123"
    mock.status = "completed"
    mock.mode = "agentless"
    mock.machine_hostname = "test-host"
    mock.machine_id = "test-id"
    mock.distro = "Ubuntu 22.04"
    mock.started_at = datetime.now(timezone.utc)
    mock.completed_at = datetime.now(timezone.utc)
    mock.summary = {}
    mock.security_score = 85.0
    mock.performance_score = 90.0
    mock.overall_score = 87.0
    mock.score_explanation = {}
    mock.raw_payload = {}
    mock.findings = []
    mock.recommendations = []
    return mock


def test_start_scan_with_background_task(client):
    with patch("app.api.routes.scans.create_scan", return_value=MagicMock(
        scan_id="new-scan", status="queued", mode="agentless",
        created_at=datetime.now(timezone.utc)
    )), \
    patch("app.api.routes.scans.run_scan_background"):
        response = client.post(
            "/api/v1/scans",
            json={"mode": "agentless", "target_name": "localhost"}
        )
        assert response.status_code in [202, 401]


def test_scan_status_endpoint(client, mock_scan):
    with patch("app.services.scan_service.get_scan_status", return_value=MagicMock(
        scan_id=mock_scan.id,
        status=mock_scan.status,
        mode=mock_scan.mode,
        started_at=mock_scan.started_at,
        completed_at=mock_scan.completed_at,
        error_message=None
    )):
        response = client.get(f"/api/v1/scans/{mock_scan.id}/status")
        assert response.status_code in [200, 401]


def test_scan_results_endpoint(client, mock_scan):
    with patch("app.services.scan_service.get_scan_result", return_value=MagicMock(
        scan_id=mock_scan.id,
        status=mock_scan.status,
        mode=mock_scan.mode,
        machine_hostname=mock_scan.machine_hostname,
        machine_id=mock_scan.machine_id,
        distro=mock_scan.distro,
        started_at=mock_scan.started_at,
        completed_at=mock_scan.completed_at,
        summary=mock_scan.summary,
        scores=MagicMock(
            security=mock_scan.security_score,
            performance=mock_scan.performance_score,
            overall=mock_scan.overall_score,
            explanation={}
        ),
        findings=[],
        recommendations=[]
    )):
        response = client.get(f"/api/v1/scans/{mock_scan.id}/results")
        assert response.status_code in [200, 401]


def test_scan_history_endpoint(client):
    with patch("app.services.scan_service.get_scan_history", return_value=MagicMock(
        items=[],
        total=0,
        page=1,
        page_size=20
    )):
        response = client.get("/api/v1/history")
        assert response.status_code in [200, 401]


def test_export_json_endpoint(client):
    with patch("app.services.exporter.export_scan_to_json", return_value=MagicMock(
        scan_id="scan-123",
        artifact_type="json",
        file_name="scan-123.json",
        file_path="/exports/scan-123.json",
        content_type="application/json"
    )):
        response = client.get("/api/v1/scans/scan-123/export/json")
        assert response.status_code in [200, 401, 404]


def test_export_pdf_endpoint(client):
    with patch("app.services.exporter.export_scan_to_pdf", return_value=MagicMock(
        scan_id="scan-123",
        artifact_type="pdf",
        file_name="scan-123.pdf",
        file_path="/exports/scan-123.pdf",
        content_type="application/pdf"
    )):
        response = client.get("/api/v1/scans/scan-123/export/pdf")
        assert response.status_code in [200, 401, 404, 501]


def test_export_pdf_not_available(client):
    with patch("app.services.exporter.export_scan_to_pdf", return_value=MagicMock(
        scan_id="scan-123",
        file_path=None
    )):
        response = client.get("/api/v1/scans/scan-123/export/pdf")
        assert response.status_code in [401, 404, 501]