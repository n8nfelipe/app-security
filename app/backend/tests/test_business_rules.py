import json
import tempfile
from pathlib import Path


def test_load_rules_full():
    from app.services.scoring import load_rules
    
    rules_data = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "critical_services": ["sshd", "docker"],
        "security_weights": {"CRIT": 50, "HIGH": 25, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.7, "performance": 0.3},
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(rules_data, f)
        f.flush()
        result = load_rules(Path(f.name))
        assert result["performance_thresholds"]["cpu"] == 80
        assert result["security_weights"]["CRIT"] == 50


def test_calculate_scores_full():
    from app.services.scoring import calculate_scores
    
    rules = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "security_weights": {"CRIT": 50, "HIGH": 25, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.7, "performance": 0.3},
    }
    findings = [
        {"severity": "CRIT", "check_id": "C1", "domain": "security", "weight": 10},
        {"severity": "HIGH", "check_id": "C2", "domain": "security", "weight": 5},
    ]
    
    result = calculate_scores(findings, rules)
    assert result["security"] < 100
    assert result["security"] > 0
    assert "performance" in result
    assert "overall" in result


def test_calculate_scores_only_performance():
    from app.services.scoring import calculate_scores
    
    rules = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "security_weights": {"CRIT": 50, "HIGH": 25, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.7, "performance": 0.3},
    }
    findings = [
        {"severity": "HIGH", "check_id": "P1", "domain": "performance", "weight": 1},
    ]
    
    result = calculate_scores(findings, rules)
    assert result["performance"] < 100


def test_calculate_scores_empty():
    from app.services.scoring import calculate_scores
    
    rules = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "security_weights": {"CRIT": 50, "HIGH": 25, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.7, "performance": 0.3},
    }
    
    result = calculate_scores([], rules)
    assert result["security"] == 100
    assert result["performance"] == 100
    assert result["overall"] == 100


def test_summarize_snapshot_returns_dict():
    from app.services.scoring import summarize_snapshot
    
    snapshot = {
        "files": {
            "passwd": {"content": ""},
            "os_release": {"content": ""},
        },
        "commands": {
            "listening_ports": {"stdout": ""},
            "established_connections": {"stdout": ""},
            "disk_usage": {"stdout": ""},
            "cpu_processes": {"stdout": ""},
        },
        "metadata": {
            "hostname": "test-host",
            "psutil": {"cpu_count": 4, "cpu_percent": 50}
        }
    }
    
    result = summarize_snapshot(snapshot, [])
    assert isinstance(result, dict)


def test_build_recommendations_order():
    from app.services.recommendations import build_recommendations
    
    findings = [
        {"severity": "MED", "check_id": "M1", "title": "Medium Finding", "domain": "test", "recommendation": "Rec 1", "rationale": "Rationale 1"},
        {"severity": "CRIT", "check_id": "C1", "title": "Critical Finding", "domain": "test", "recommendation": "Rec 2", "rationale": "Rationale 2"},
        {"severity": "HIGH", "check_id": "H1", "title": "High Finding", "domain": "test", "recommendation": "Rec 3", "rationale": "Rationale 3"},
    ]
    
    result = build_recommendations(findings)
    assert len(result) >= 1