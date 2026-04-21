import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from fastapi import HTTPException


@pytest.fixture
def mock_get_db():
    with patch("app.services.scan_service.get_db") as mock:
        mock_session = MagicMock()
        mock.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock.return_value.__exit__ = MagicMock(return_value=None)
        yield mock_session


@pytest.fixture
def mock_settings():
    with patch("app.services.scan_service.settings") as mock:
        mock.rules_file = MagicMock()
        mock.rules_file.resolve.return_value = "rules.json"
        yield mock


def test_create_scan(mock_get_db, mock_settings):
    from app.schemas.scan import ScanCreateRequest
    from app.services.scan_service import create_scan
    
    payload = ScanCreateRequest(mode="agentless", target_name="localhost")
    result = create_scan(payload)
    assert result.scan_id is not None
    assert result.status == "queued"
    mock_get_db.add.assert_called_once()
    mock_get_db.commit.assert_called_once()


def test_get_scan_status_not_found(mock_get_db):
    from app.services.scan_service import get_scan_status
    
    mock_get_db.get.return_value = None
    with pytest.raises(HTTPException) as exc_info:
        get_scan_status("nonexistent-id")
    assert exc_info.value.status_code == 404


def test_get_scan_result_not_found(mock_get_db):
    from app.services.scan_service import get_scan_result
    
    mock_get_db.get.return_value = None
    with pytest.raises(HTTPException) as exc_info:
        get_scan_result("nonexistent-id")
    assert exc_info.value.status_code == 404


def test_get_scan_history_empty(mock_get_db):
    from app.services.scan_service import get_scan_history
    
    mock_query = MagicMock()
    mock_query.order_by.return_value = mock_query
    mock_query.filter.return_value = mock_query
    mock_query.limit.return_value = mock_query
    mock_query.limit.return_value.all.return_value = []
    mock_get_db.query.return_value = mock_query
    
    result = get_scan_history(hostname=None, machine_id=None, limit=20)
    assert result.items == []


def test_get_scan_history_with_scans(mock_get_db):
    from app.services.scan_service import get_scan_history
    
    mock_scan = MagicMock()
    mock_scan.id = "scan-1"
    mock_scan.status = "completed"
    mock_scan.mode = "agentless"
    mock_scan.machine_hostname = "host1"
    mock_scan.machine_id = "id-1"
    mock_scan.overall_score = 80
    mock_scan.security_score = 85
    mock_scan.performance_score = 75
    mock_scan.started_at = datetime.now(timezone.utc)
    mock_scan.completed_at = datetime.now(timezone.utc)
    
    mock_query = MagicMock()
    mock_query.order_by.return_value = mock_query
    mock_query.filter.return_value = mock_query
    mock_query.limit.return_value = mock_query
    mock_query.limit.return_value.all.return_value = [mock_scan]
    mock_get_db.query.return_value = mock_query
    
    result = get_scan_history(hostname="host1", machine_id=None, limit=10)
    assert len(result.items) == 1


def test_mark_scan_failed(mock_get_db):
    from app.services.scan_service import _mark_scan_failed
    
    mock_scan = MagicMock()
    mock_scan.status = "queued"
    mock_get_db.get.return_value = mock_scan
    
    _mark_scan_failed(mock_get_db, "scan-fail-123", "Test error")
    assert mock_scan.status == "failed"
    mock_get_db.commit.assert_called_once()


def test_mark_scan_failed_not_found(mock_get_db):
    from app.services.scan_service import _mark_scan_failed
    
    mock_get_db.get.return_value = None
    _mark_scan_failed(mock_get_db, "nonexistent", "Error")
    mock_get_db.commit.assert_not_called()