import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.api.routes.network import NetworkDevice, NetworkSummary

client = TestClient(app)


def test_network_device_model():
    device = NetworkDevice(
        ip="192.168.1.1",
        mac="AA:BB:CC:DD:EE:FF",
        hostname="router.local",
        vendor="Cisco",
        state="up"
    )
    assert device.ip == "192.168.1.1"
    assert device.mac == "AA:BB:CC:DD:EE:FF"
    assert device.hostname == "router.local"
    assert device.vendor == "Cisco"
    assert device.state == "up"

def test_network_device_model_optionals():
    device = NetworkDevice(ip="192.168.1.100", state="up")
    assert device.ip == "192.168.1.100"
    assert device.mac is None
    assert device.hostname is None
    assert device.vendor is None

def test_network_device_model_down():
    device = NetworkDevice(ip="192.168.1.50", state="down")
    assert device.state == "down"

def test_network_summary_model():
    summary = NetworkSummary(total=5, devices=[])
    assert summary.total == 5
    assert summary.devices == []

@patch("app.api.routes.network.nmap.PortScanner")
def test_network_devices_endpoint(mock_scanner):
    mock_nm = MagicMock()
    mock_nm.scan.return_value = {
        "scan": {
            "192.168.1.1": {
                "status": {"state": "up"},
                "hostnames": [{"name": "router.local"}],
                "addresses": {"mac": "AA:BB:CC:DD:EE:FF"},
                "vendor": {"AA:BB:CC:DD:EE:FF": "Cisco"}
            },
            "192.168.1.10": {
                "status": {"state": "up"},
                "hostnames": [],
                "addresses": {},
                "vendor": {}
            }
        }
    }
    mock_scanner.return_value = mock_nm

    response = client.get("/api/v1/network/devices", headers={"X-API-Token": "changeme-token"})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["devices"]) == 2
    assert data["devices"][0]["ip"] == "192.168.1.1"
    assert data["devices"][0]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert data["devices"][0]["hostname"] == "router.local"
    assert data["devices"][0]["vendor"] == "Cisco"
    assert data["devices"][0]["state"] == "up"
    assert data["devices"][1]["ip"] == "192.168.1.10"
    assert data["devices"][1]["mac"] is None

@patch("app.api.routes.network.nmap.PortScanner")
def test_network_devices_empty_scan(mock_scanner):
    mock_nm = MagicMock()
    mock_nm.scan.return_value = {"scan": {}}
    mock_scanner.return_value = mock_nm

    response = client.get("/api/v1/network/devices", headers={"X-API-Token": "changeme-token"})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["devices"] == []

@patch("app.api.routes.network.nmap.PortScanner")
def test_network_devices_partial_data(mock_scanner):
    mock_nm = MagicMock()
    mock_nm.scan.return_value = {
        "scan": {
            "192.168.1.5": {
                "status": {"state": "up"},
                "hostnames": [],
                "addresses": {},
                "vendor": {}
            }
        }
    }
    mock_scanner.return_value = mock_nm

    response = client.get("/api/v1/network/devices", headers={"X-API-Token": "changeme-token"})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["devices"][0]["ip"] == "192.168.1.5"
    assert data["devices"][0]["mac"] is None
    assert data["devices"][0]["hostname"] is None
    assert data["devices"][0]["vendor"] is None
    assert data["devices"][0]["state"] == "up"

@patch("app.api.routes.network.nmap.PortScanner")
def test_network_devices_scan_error(mock_scanner):
    mock_nm = MagicMock()
    mock_nm.scan.side_effect = Exception("Network error")
    mock_scanner.return_value = mock_nm

    response = client.get("/api/v1/network/devices", headers={"X-API-Token": "changeme-token"})
    assert response.status_code == 500
    assert "Scan failed" in response.json()["detail"]