import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

@pytest.fixture
def mock_auth():
    with patch("app.core.auth.require_api_token"):
        yield

def test_health_endpoint(mock_auth):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_root_endpoint(mock_auth):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "service" in data
    assert "status" in data

def test_root_health_in_docs(mock_auth):
    response = client.get("/docs")
    assert response.status_code == 200