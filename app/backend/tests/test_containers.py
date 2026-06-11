import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.api.routes.containers import list_running_containers
from app.core.config import settings
from docker.errors import DockerException

client = TestClient(app)


def test_containers_endpoint():
    response = client.get("/api/v1/containers", headers={"X-API-Token": settings.api_token})
    assert response.status_code == 200
    data = response.json()
    assert "containers" in data


def test_containers_endpoint_unauthorized():
    response = client.get("/api/v1/containers")
    assert response.status_code == 401


def test_list_running_containers_success():
    with patch("app.api.routes.containers.docker.DockerClient") as mock_docker:
        mock_container = MagicMock()
        mock_container.id = "abc123"
        mock_container.name = "test-container"
        mock_container.image.tags = ["nginx:latest"]
        mock_container.status = "running"
        mock_container.attrs = {"NetworkSettings": {"Ports": {}}}
        
        mock_client = MagicMock()
        mock_client.containers.list.return_value = [mock_container]
        mock_docker.return_value = mock_client
        
        result, available = list_running_containers()

        assert available is True
        assert len(result) == 1
        assert result[0]["id"] == "abc123"
        assert result[0]["name"] == "test-container"


def test_list_running_containers_no_tags():
    with patch("app.api.routes.containers.docker.DockerClient") as mock_docker:
        mock_container = MagicMock()
        mock_container.id = "abc123"
        mock_container.name = "test-container"
        mock_container.image.tags = []
        mock_container.image.short_id = "abc"
        mock_container.status = "running"
        mock_container.attrs = {"NetworkSettings": {"Ports": {}}}

        mock_client = MagicMock()
        mock_client.containers.list.return_value = [mock_container]
        mock_docker.return_value = mock_client

        result, available = list_running_containers()

        assert available is True
        assert result[0]["image"] == "abc"


def test_list_running_containers_with_ports():
    with patch("app.api.routes.containers.docker.DockerClient") as mock_docker:
        mock_container = MagicMock()
        mock_container.id = "abc123"
        mock_container.name = "test-container"
        mock_container.image.tags = ["nginx:latest"]
        mock_container.status = "running"
        mock_container.attrs = {
            "NetworkSettings": {
                "Ports": {"80/tcp": [{"HostPort": "8080"}]}
            }
        }

        mock_client = MagicMock()
        mock_client.containers.list.return_value = [mock_container]
        mock_docker.return_value = mock_client

        result, available = list_running_containers()

        assert available is True
        assert "80/tcp" in result[0]["ports"]


def test_list_running_containers_docker_unavailable():
    with patch("app.api.routes.containers.docker.DockerClient") as mock_docker:
        mock_docker.side_effect = DockerException("Connection refused")

        result, available = list_running_containers()

        assert available is False
        assert result == []