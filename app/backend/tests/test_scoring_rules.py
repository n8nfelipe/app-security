import pytest
from unittest.mock import patch, MagicMock
from app.services.scoring import load_rules, calculate_scores
import json
import tempfile
from pathlib import Path


def test_rules_with_custom_thresholds():
    rules_data = {
        "performance_thresholds": {"cpu": 50, "memory": 70},
        "critical_services": ["nginx"],
        "security_weights": {"CRIT": 40, "HIGH": 20, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.6, "performance": 0.4},
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(rules_data, f)
        f.flush()
        result = load_rules(Path(f.name))
    
    assert result["performance_thresholds"]["cpu"] == 50


def test_scores_with_custom_weights():
    rules = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "security_weights": {"CRIT": 40, "HIGH": 20, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.6, "performance": 0.4},
    }
    findings = [{"severity": "HIGH", "check_id": "C1", "domain": "security", "weight": 5}]
    
    result = calculate_scores(findings, rules)
    assert result["security"] == 80
    expected_overall = (80 * 0.6) + (100 * 0.4)
    assert result["overall"] == expected_overall


def test_multiple_security_findings():
    rules = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "security_weights": {"CRIT": 50, "HIGH": 25, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.7, "performance": 0.3},
    }
    findings = [
        {"severity": "CRIT", "check_id": "C1", "domain": "security", "weight": 10},
        {"severity": "HIGH", "check_id": "C2", "domain": "security", "weight": 5},
        {"severity": "MED", "check_id": "C3", "domain": "security", "weight": 1},
    ]
    
    result = calculate_scores(findings, rules)
    assert result["security"] == 15


def test_performance_penalty():
    rules = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "security_weights": {"CRIT": 50, "HIGH": 25, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.7, "performance": 0.3},
    }
    findings = [
        {"severity": "HIGH", "check_id": "P1", "domain": "performance", "weight": 10},
    ]
    
    result = calculate_scores(findings, rules)
    assert result["performance"] == 75


def test_mixed_domain_findings():
    rules = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "security_weights": {"CRIT": 50, "HIGH": 25, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.7, "performance": 0.3},
    }
    findings = [
        {"severity": "HIGH", "check_id": "S1", "domain": "security", "weight": 5},
        {"severity": "MED", "check_id": "P1", "domain": "performance", "weight": 3},
    ]
    
    result = calculate_scores(findings, rules)
    security_expected = 100 - 25
    perf_expected = 100 - 10
    overall_expected = (security_expected * 0.7) + (perf_expected * 0.3)
    assert result["overall"] == overall_expected


def test_severity_counts():
    rules = {
        "performance_thresholds": {"cpu": 80, "memory": 90},
        "security_weights": {"CRIT": 50, "HIGH": 25, "MED": 10, "LOW": 5, "INFO": 0},
        "score_weights": {"security": 0.7, "performance": 0.3},
    }
    findings = [
        {"severity": "HIGH", "check_id": "S1", "domain": "security", "weight": 5},
        {"severity": "HIGH", "check_id": "S2", "domain": "security", "weight": 5},
        {"severity": "MED", "check_id": "P1", "domain": "performance", "weight": 3},
    ]
    
    result = calculate_scores(findings, rules)
    assert result["explanation"]["severity_counts"]["security"]["HIGH"] == 2
    assert result["explanation"]["severity_counts"]["performance"]["MED"] == 1