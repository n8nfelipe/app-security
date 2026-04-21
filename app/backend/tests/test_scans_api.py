from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_scans_endpoint_no_auth():
    response = client.post("/api/v1/scans", json={"mode": "agentless"})
    assert response.status_code == 401


def test_history_endpoint_no_auth():
    response = client.get("/api/v1/history")
    assert response.status_code == 401


def test_scan_status_endpoint_no_auth():
    response = client.get("/api/v1/scans/test-123/status")
    assert response.status_code == 401


def test_scan_results_endpoint_no_auth():
    response = client.get("/api/v1/scans/test-123/results")
    assert response.status_code == 401


def test_export_json_endpoint_no_auth():
    response = client.get("/api/v1/scans/test-123/export/json")
    assert response.status_code == 401


def test_export_pdf_endpoint_no_auth():
    response = client.get("/api/v1/scans/test-123/export/pdf")
    assert response.status_code == 401


@patch("app.services.scan_service.get_scan_history")
def test_history_endpoint_with_limit(mock_history):
    mock_history.return_value = MagicMock(items=[])
    
    response = client.get("/api/v1/history?limit=50", headers={"X-API-Token": "changeme-token"})
    assert response.status_code == 200


@patch("app.services.scan_service.get_scan_history")
def test_history_endpoint_with_hostname(mock_history):
    mock_history.return_value = MagicMock(items=[])
    
    response = client.get("/api/v1/history?hostname=test-host", headers={"X-API-Token": "changeme-token"})
    assert response.status_code == 200


@patch("app.services.scan_service.get_scan_history")
def test_history_endpoint_with_machine_id(mock_history):
    mock_history.return_value = MagicMock(items=[])
    
    response = client.get("/api/v1/history?machine_id=id-123", headers={"X-API-Token": "changeme-token"})
    assert response.status_code == 200