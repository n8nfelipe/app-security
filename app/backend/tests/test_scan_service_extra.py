import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from app.services.scan_service import _mark_scan_failed


def test_mark_scan_failed_with_message():
    from app.db.models import Scan
    from app.services.scan_service import _mark_scan_failed
    
    mock_db = MagicMock()
    mock_scan = MagicMock()
    mock_db.get.return_value = mock_scan
    
    _mark_scan_failed(mock_db, "test-123", "Test error message")
    
    assert mock_scan.status == "failed"
    mock_scan.completed_at = datetime.now(timezone.utc)
    mock_scan.error_message == "Test error message"
    mock_db.commit.assert_called_once()


def test_mark_scan_failed_nonexistent():
    from app.services.scan_service import _mark_scan_failed
    
    mock_db = MagicMock()
    mock_db.get.return_value = None
    
    _mark_scan_failed(mock_db, "nonexistent", "Error")
    
    mock_db.commit.assert_not_called()