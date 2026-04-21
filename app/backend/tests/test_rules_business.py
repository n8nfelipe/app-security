import pytest
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


def test_load_rules_with_all_fields():
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
        assert result["security_weights"]["CRIT"] == 50
        assert result["score_weights"]["security"] == 0.7


def test_calculate_scores_empty_findings(full_rules):
    from app.services.scoring import calculate_scores
    
    result = calculate_scores([], full_rules)
    assert result["security"] == 100
    assert result["performance"] == 100
    assert result["overall"] == 100


def test_calculate_scores_critical_finding(full_rules):
    from app.services.scoring import calculate_scores
    
    findings = [{"severity": "CRIT", "check_id": "C1", "domain": "security", "weight": 10}]
    result = calculate_scores(findings, full_rules)
    assert result["security"] == 50


def test_calculate_scores_high_finding(full_rules):
    from app.services.scoring import calculate_scores
    
    findings = [{"severity": "HIGH", "check_id": "C1", "domain": "security", "weight": 5}]
    result = calculate_scores(findings, full_rules)
    assert result["security"] == 75


def test_calculate_scores_medium_finding(full_rules):
    from app.services.scoring import calculate_scores
    
    findings = [{"severity": "MED", "check_id": "C1", "domain": "security", "weight": 1}]
    result = calculate_scores(findings, full_rules)
    assert result["security"] == 90


def test_calculate_scores_low_finding(full_rules):
    from app.services.scoring import calculate_scores
    
    findings = [{"severity": "LOW", "check_id": "C1", "domain": "security", "weight": 1}]
    result = calculate_scores(findings, full_rules)
    assert result["security"] == 95


def test_calculate_scores_info_finding(full_rules):
    from app.services.scoring import calculate_scores
    
    findings = [{"severity": "INFO", "check_id": "C1", "domain": "security", "weight": 0}]
    result = calculate_scores(findings, full_rules)
    assert result["security"] == 100


def test_calculate_scores_mixed_findings(full_rules):
    from app.services.scoring import calculate_scores
    
    findings = [
        {"severity": "CRIT", "check_id": "C1", "domain": "security", "weight": 10},
        {"severity": "HIGH", "check_id": "C2", "domain": "security", "weight": 5},
    ]
    result = calculate_scores(findings, full_rules)
    assert result["security"] == 25


def test_calculate_scores_performance_domain(full_rules):
    from app.services.scoring import calculate_scores
    
    findings = [{"severity": "HIGH", "check_id": "P1", "domain": "performance", "weight": 5}]
    result = calculate_scores(findings, full_rules)
    assert result["performance"] == 75


def test_score_explanation(full_rules):
    from app.services.scoring import calculate_scores
    
    findings = [
        {"severity": "CRIT", "check_id": "C1", "domain": "security", "weight": 10},
    ]
    result = calculate_scores(findings, full_rules)
    assert "explanation" in result
    assert "weights" in result["explanation"]
    assert "severity_counts" in result["explanation"]


def test_build_recommendations_returns_list():
    from app.services.recommendations import build_recommendations
    
    findings = [
        {"severity": "MED", "check_id": "M1", "title": "Medium", "domain": "test", "recommendation": "Rec", "rationale": "Rat"},
        {"severity": "CRIT", "check_id": "C1", "title": "Critical", "domain": "test", "recommendation": "Rec", "rationale": "Rat"},
    ]
    result = build_recommendations(findings)
    assert isinstance(result, list)


def test_build_recommendations_not_empty():
    from app.services.recommendations import build_recommendations
    
    findings = [
        {"severity": "HIGH", "check_id": "H1", "title": "High", "domain": "test", "recommendation": "Rec", "rationale": "Rat"},
    ]
    result = build_recommendations(findings)
    assert len(result) > 0