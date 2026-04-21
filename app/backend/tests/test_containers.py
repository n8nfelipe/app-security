import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.api.routes.containers import list_running_containers
from docker.errors import DockerException

client = TestClient(app)


def test_containers_endpoint():
    response = client.get("/api/v1/containers", headers={"X-API-Token": "changeme-token"})
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
        
        result = list_running_containers()
        
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
        
        result = list_running_containers()
        
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
        
        result = list_running_containers()
        
        assert "80/tcp" in result[0]["ports"]


def test_list_running_containers_docker_exception():
    with patch("app.api.routes.containers.docker.DockerClient") as mock_docker:
        from fastapi import HTTPException
        mock_docker.side_effect = DockerException("Connection refused")
        
        with pytest.raises(HTTPException) as exc_info:
            list_running_containers()
        assert exc_info.value.status_code == 500
        assert "Docker" in str(exc_info.value.detail)