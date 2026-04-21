import pytest
from unittest.mock import patch
from app.services.scoring import load_rules, calculate_scores
import json
import tempfile
from pathlib import Path


@pytest.fixture
def full_rules():
    return {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "critical_services": ["sshd", "docker"],
        "security_weights": {"CRIT": 50, "HIGH": 25, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.7, "performance": 0.3},
    }


@patch("app.services.scoring.parser")
def test_summarize_snapshot_cpu(mock_parser, full_rules):
    from app.services.scoring import summarize_snapshot
    
    mock_parser.parse_passwd.return_value = []
    mock_parser.parse_key_value_file.return_value = {}
    mock_parser.parse_ss_listening.return_value = []
    mock_parser.parse_df.return_value = []
    
    snapshot = {
        "files": {"passwd": {"content": ""}, "os_release": {"content": ""}},
        "commands": {
            "listening_ports": {"stdout": ""},
            "disk_usage": {"stdout": ""},
            "cpu_processes": {"stdout": ""},
        },
        "metadata": {
            "hostname": "test",
            "psutil": {"cpu_count": 4, "cpu_percent": 90, "memory": {"percent": 90}}
        }
    }
    
    result = summarize_snapshot(snapshot, [])
    assert isinstance(result, dict)


@patch("app.services.scoring.parser")
def test_summarize_snapshot_with_ports(mock_parser, full_rules):
    from app.services.scoring import summarize_snapshot
    
    mock_parser.parse_passwd.return_value = []
    mock_parser.parse_key_value_file.return_value = {"PRETTY_NAME": "Ubuntu"}
    mock_parser.parse_ss_listening.return_value = [
        {"local_address": "0.0.0.0:22"},
        {"local_address": "0.0.0.0:80"},
    ]
    mock_parser.parse_df.return_value = []
    
    snapshot = {
        "files": {"passwd": {"content": ""}, "os_release": {"content": ""}},
        "commands": {
            "listening_ports": {"stdout": ""},
            "established_connections": {"stdout": ""},
            "disk_usage": {"stdout": ""},
            "cpu_processes": {"stdout": ""},
        },
        "metadata": {
            "hostname": "test",
            "psutil": {"cpu_count": 4, "cpu_percent": 50}
        }
    }
    
    result = summarize_snapshot(snapshot, [])
    assert isinstance(result, dict)


def test_rules_with_special_thresholds():
    rules_data = {
        "performance_thresholds": {"cpu": 90, "memory": 95},
        "critical_services": ["systemd"],
        "security_weights": {"CRIT": 60, "HIGH": 30, "MED": 15, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.5, "performance": 0.5},
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(rules_data, f)
        f.flush()
        result = load_rules(Path(f.name))
    
    assert result["performance_thresholds"]["cpu"] == 90


def test_score_bounds_zero_penalty():
    rules = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "security_weights": {"CRIT": 50, "HIGH": 25, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.7, "performance": 0.3},
    }
    findings = [
        {"severity": "CRIT", "check_id": "C1", "domain": "security", "weight": 10},
        {"severity": "CRIT", "check_id": "C2", "domain": "security", "weight": 10},
    ]
    
    result = calculate_scores(findings, rules)
    assert result["security"] >= 0


def test_score_bounds_exceed():
    rules = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "security_weights": {"CRIT": 50, "HIGH": 25, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.7, "performance": 0.3},
    }
    findings = [
        {"severity": "CRIT", "check_id": "C1", "domain": "security", "weight": 10},
        {"severity": "CRIT", "check_id": "C2", "domain": "security", "weight": 10},
        {"severity": "CRIT", "check_id": "C3", "domain": "security", "weight": 10},
    ]
    
    result = calculate_scores(findings, rules)
    assert result["security"] >= 0


def test_load_rules_full_structure():
    rules_data = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "critical_services": ["sshd"],
        "security_weights": {"CRIT": 50, "HIGH": 25},
        "score_weights": {"security": 0.7},
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(rules_data, f)
        f.flush()
        result = load_rules(Path(f.name))
        assert "security_weights" in result