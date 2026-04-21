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


def test_run_scan_background_with_scan(mock_get_db, mock_settings):
    from app.services.scan_service import run_scan_background

    mock_scan = MagicMock()
    mock_scan.id = "scan-123"
    mock_scan.mode = "agentless"
    mock_scan.status = "queued"
    mock_scan.target_name = "localhost"
    mock_scan.machine_hostname = None
    mock_scan.machine_id = None
    mock_scan.distro = None
    mock_scan.security_score = None
    mock_scan.performance_score = None
    mock_scan.overall_score = None
    mock_scan.score_explanation = None
    mock_scan.summary = None
    mock_scan.raw_payload = {}
    mock_scan.completed_at = None
    mock_scan.started_at = datetime.now(timezone.utc)
    mock_scan.findings = []
    mock_scan.recommendations = []

    mock_get_db.get.return_value = mock_scan

    mock_snapshot = {
        "metadata": {"hostname": "test-host"},
        "files": {
            "os_release": {"content": 'PRETTY_NAME="Ubuntu 22.04"'},
            "machine_id": {"content": "machine-123"}
        },
        "commands": {}
    }
    mock_rules = {
        "security_weights": {"low": 5, "medium": 15, "high": 30, "critical": 50},
        "score_weights": {"security": 0.6, "performance": 0.4}
    }

    with patch("app.services.scan_service.load_rules", return_value=mock_rules), \
         patch("app.services.scan_service.collect_local_snapshot", return_value=mock_snapshot), \
         patch("app.services.scan_service.build_findings", return_value=[]), \
         patch("app.services.scan_service.calculate_scores", return_value={
             "security": 100.0, "performance": 100.0, "overall": 100.0, "explanation": {}
         }), \
         patch("app.services.scan_service.build_recommendations", return_value=[]), \
         patch("app.services.scan_service.summarize_snapshot", return_value={}):

        run_scan_background("scan-123")

        assert mock_scan.status == "completed"
        assert mock_scan.machine_hostname == "test-host"
        assert mock_scan.distro == "Ubuntu 22.04"


def test_run_scan_background_scan_not_found(mock_get_db):
    from app.services.scan_service import run_scan_background

    mock_get_db.get.return_value = None
    run_scan_background("nonexistent-scan")


def test_run_scan_background_with_agent_mode(mock_get_db, mock_settings):
    from app.services.scan_service import run_scan_background

    mock_scan = MagicMock()
    mock_scan.id = "scan-agent"
    mock_scan.mode = "agent"
    mock_scan.status = "queued"
    mock_scan.target_name = "remote-host"
    mock_scan.machine_hostname = None
    mock_scan.machine_id = None
    mock_scan.distro = None
    mock_scan.security_score = None
    mock_scan.performance_score = None
    mock_scan.overall_score = None
    mock_scan.score_explanation = None
    mock_scan.summary = None
    mock_scan.raw_payload = {}
    mock_scan.completed_at = None
    mock_scan.started_at = datetime.now(timezone.utc)
    mock_scan.findings = []
    mock_scan.recommendations = []

    mock_get_db.get.return_value = mock_scan

    mock_snapshot = {
        "metadata": {"hostname": "agent-host"},
        "files": {
            "os_release": {"content": 'PRETTY_NAME="Debian 12"'},
            "machine_id": {"content": "agent-machine-id"}
        },
        "commands": {}
    }
    mock_rules = {
        "security_weights": {"low": 5, "medium": 15, "high": 30, "critical": 50},
        "score_weights": {"security": 0.6, "performance": 0.4}
    }

    with patch("app.services.scan_service.load_rules", return_value=mock_rules), \
         patch("app.services.scan_service.collect_via_agent", return_value=mock_snapshot), \
         patch("app.services.scan_service.build_findings", return_value=[]), \
         patch("app.services.scan_service.calculate_scores", return_value={
             "security": 90.0, "performance": 95.0, "overall": 92.0, "explanation": {}
         }), \
         patch("app.services.scan_service.build_recommendations", return_value=[]), \
         patch("app.services.scan_service.summarize_snapshot", return_value={}):

        run_scan_background("scan-agent")

        assert mock_scan.status == "completed"


def test_get_scan_status_with_completed_scan(mock_get_db):
    from app.services.scan_service import get_scan_status

    mock_scan = MagicMock()
    mock_scan.id = "completed-scan"
    mock_scan.status = "completed"
    mock_scan.mode = "agentless"
    mock_scan.started_at = datetime.now(timezone.utc)
    mock_scan.completed_at = datetime.now(timezone.utc)
    mock_scan.error_message = None

    mock_get_db.get.return_value = mock_scan

    result = get_scan_status("completed-scan")
    assert result.scan_id == "completed-scan"
    assert result.status == "completed"


def test_get_scan_result_with_findings_and_recommendations(mock_get_db):
    from app.services.scan_service import get_scan_result

    mock_scan = MagicMock()
    mock_scan.id = "scan-full"
    mock_scan.status = "completed"
    mock_scan.mode = "agentless"
    mock_scan.machine_hostname = "full-host"
    mock_scan.machine_id = "full-id"
    mock_scan.distro = "Ubuntu 24.04"
    mock_scan.started_at = datetime.now(timezone.utc)
    mock_scan.completed_at = datetime.now(timezone.utc)
    mock_scan.summary = {"total_containers": 5}
    mock_scan.security_score = 85.0
    mock_scan.performance_score = 90.0
    mock_scan.overall_score = 87.0
    mock_scan.score_explanation = {"severity_counts": {}}
    mock_scan.raw_payload = {}

    mock_finding = MagicMock()
    mock_finding.id = 1
    mock_finding.check_id = "check-001"
    mock_finding.domain = "security"
    mock_finding.category = "network"
    mock_finding.severity = "HIGH"
    mock_finding.title = "Open Port"
    mock_finding.evidence = "port: 22"
    mock_finding.recommendation = "Close port"
    mock_finding.reference = "CIS Benchmark"
    mock_finding.rationale = "Security risk"
    mock_finding.weight = 30
    mock_finding.extra_data = {}

    mock_recommendation = MagicMock()
    mock_recommendation.id = 1
    mock_recommendation.title = "Close port 22"
    mock_recommendation.priority = "high"
    mock_recommendation.risk = "high"
    mock_recommendation.impact = "medium"
    mock_recommendation.effort = "low"
    mock_recommendation.domain = "security"
    mock_recommendation.action = "close_port"
    mock_recommendation.reason = "Security hardening"
    mock_recommendation.source_check_id = "check-001"
    mock_recommendation.extra_data = {}

    mock_scan.findings = [mock_finding]
    mock_scan.recommendations = [mock_recommendation]

    mock_get_db.get.return_value = mock_scan

    result = get_scan_result("scan-full")
    assert result.scan_id == "scan-full"
    assert len(result.findings) == 1
    assert len(result.recommendations) == 1
    assert result.scores is not None
    assert result.scores.security == 85.0


def test_get_scan_result_without_scores(mock_get_db):
    from app.services.scan_service import get_scan_result

    mock_scan = MagicMock()
    mock_scan.id = "scan-no-scores"
    mock_scan.status = "queued"
    mock_scan.mode = "agentless"
    mock_scan.machine_hostname = None
    mock_scan.machine_id = None
    mock_scan.distro = None
    mock_scan.started_at = datetime.now(timezone.utc)
    mock_scan.completed_at = None
    mock_scan.summary = None
    mock_scan.security_score = None
    mock_scan.performance_score = None
    mock_scan.overall_score = None
    mock_scan.score_explanation = None
    mock_scan.raw_payload = {}
    mock_scan.findings = []
    mock_scan.recommendations = []

    mock_get_db.get.return_value = mock_scan

    result = get_scan_result("scan-no-scores")
    assert result.scores is None
    assert result.findings == []
    assert result.recommendations == []