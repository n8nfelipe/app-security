import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.api.routes.users import UserAccount, UsersSummary

client = TestClient(app)


def test_user_account_model():
    user = UserAccount(
        username="root",
        uid=0,
        gid=0,
        gecos="root",
        home="/root",
        shell="/bin/bash"
    )
    assert user.username == "root"
    assert user.uid == 0


def test_user_account_model_optionals():
    user = UserAccount(
        username="nobody",
        uid=65534,
        gid=65534,
        home="/nonexistent",
        shell="/usr/sbin/nologin"
    )
    assert user.gecos is None


def test_users_summary_model():
    summary = UsersSummary(total=10, human_users=3, users=[])
    assert summary.total == 10
    assert summary.human_users == 3


@patch("pathlib.Path.read_text")
def test_get_users_success(mock_read_text):
    mock_read_text.return_value = "root:x:0:0:root:/root:/bin/bash\nuser1:x:1000:1000:User1:/home/user1:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    
    response = client.get("/api/v1/users", headers={"X-API-Token": "changeme-token"})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert data["human_users"] == 1
    assert len(data["users"]) == 3


@patch("pathlib.Path.read_text")
def test_get_users_empty(mock_read_text):
    mock_read_text.return_value = ""
    
    response = client.get("/api/v1/users", headers={"X-API-Token": "changeme-token"})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["human_users"] == 0


def test_get_users_unauthorized():
    response = client.get("/api/v1/users")
    assert response.status_code == 401