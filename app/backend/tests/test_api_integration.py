from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint_direct():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_root_endpoint_direct():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "service" in data
    assert "status" in data


def test_containers_endpoint_no_auth():
    response = client.get("/api/v1/containers")
    assert response.status_code == 401


def test_containers_endpoint_with_auth():
    response = client.get("/api/v1/containers", headers={"X-API-Token": "changeme-token"})
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "containers" in data


def test_network_devices_no_auth():
    response = client.get("/api/v1/network/devices")
    assert response.status_code == 401


@patch("app.api.routes.network.nmap.PortScanner")
def test_network_devices_with_auth(mock_scanner):
    mock_nm = MagicMock()
    mock_nm.scan.return_value = {"scan": {}}
    mock_scanner.return_value = mock_nm
    
    response = client.get("/api/v1/network/devices", headers={"X-API-Token": "changeme-token"})
    assert response.status_code == 200
    data = response.json()
    assert "devices" in data
    assert "total" in data
    assert isinstance(data["devices"], list)