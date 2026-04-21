import pytest
from unittest.mock import patch, MagicMock
from app.services.recommendations import (
    build_recommendations,
    PRIORITY_MAP,
    SEVERITY_ORDER,
)


def test_build_recommendations_empty():
    result = build_recommendations([])
    assert result == []


def test_build_recommendations_single_finding():
    findings = [
        {
            "check_id": "TEST_001",
            "title": "Test Finding",
            "severity": "HIGH",
            "category": "security",
            "domain": "identity",
            "recommendation": "Test recommendation text",
            "rationale": "Test rationale",
            "evidence": "Test evidence",
        }
    ]
    result = build_recommendations(findings)
    assert len(result) == 1


def test_build_recommendations_multiple_findings():
    findings = [
        {
            "check_id": "TEST_001",
            "title": "High Severity Finding",
            "severity": "HIGH",
            "category": "security",
            "domain": "identity",
            "recommendation": "Rec 1",
            "rationale": "Rationale 1",
            "evidence": "Evidence 1",
        },
        {
            "check_id": "TEST_002",
            "title": "Medium Severity Finding",
            "severity": "MED",
            "category": "security",
            "domain": "network",
            "recommendation": "Rec 2",
            "rationale": "Rationale 2",
            "evidence": "Evidence 2",
        }
    ]
    result = build_recommendations(findings)
    assert len(result) >= 1


def test_build_recommendations_with_critical():
    findings = [
        {
            "check_id": "TEST_001",
            "title": "Critical Finding",
            "severity": "CRIT",
            "category": "security",
            "domain": "identity",
            "recommendation": "Critical rec",
            "rationale": "Critical rationale",
            "evidence": "Critical evidence",
        }
    ]
    result = build_recommendations(findings)
    assert len(result) == 1


def test_build_recommendations_duplicate_check_id_and_rec():
    findings = [
        {
            "check_id": "TEST_001",
            "title": "Test Finding 1",
            "severity": "HIGH",
            "domain": "security",
            "recommendation": "Same Rec",
            "rationale": "Rationale",
            "evidence": "Evidence",
        },
        {
            "check_id": "TEST_001",
            "title": "Test Finding 2",
            "severity": "MED",
            "domain": "security",
            "recommendation": "Same Rec",
            "rationale": "Rationale",
            "evidence": "Evidence",
        },
    ]
    result = build_recommendations(findings)
    assert len(result) == 1


def test_build_recommendations_with_reference():
    findings = [
        {
            "check_id": "TEST_001",
            "title": "Test Finding",
            "severity": "HIGH",
            "domain": "security",
            "recommendation": "Rec",
            "rationale": "Rationale",
            "reference": "CIS-5.2",
            "evidence": "Evidence",
        }
    ]
    result = build_recommendations(findings)
    assert result[0]["extra_data"]["reference"] == "CIS-5.2"


def test_build_recommendations_with_extra_data():
    findings = [
        {
            "check_id": "TEST_001",
            "title": "Test Finding",
            "severity": "HIGH",
            "domain": "security",
            "recommendation": "Rec",
            "rationale": "Rationale",
            "evidence": "Evidence",
            "extra_data": {"remediation": "steps here"},
        }
    ]
    result = build_recommendations(findings)
    assert result[0]["extra_data"]["remediation"] == "steps here"


def test_priority_map_crit():
    assert PRIORITY_MAP["CRIT"] == ("P0", "low", "high", "medium")


def test_priority_map_high():
    assert PRIORITY_MAP["HIGH"] == ("P1", "low", "high", "medium")


def test_priority_map_med():
    assert PRIORITY_MAP["MED"] == ("P2", "medium", "medium", "low")


def test_priority_map_low():
    assert PRIORITY_MAP["LOW"] == ("P3", "low", "medium", "low")


def test_priority_map_info():
    assert PRIORITY_MAP["INFO"] == ("P4", "low", "low", "low")


def test_severity_order():
    assert SEVERITY_ORDER["CRIT"] == 0
    assert SEVERITY_ORDER["HIGH"] == 1
    assert SEVERITY_ORDER["MED"] == 2
    assert SEVERITY_ORDER["LOW"] == 3
    assert SEVERITY_ORDER["INFO"] == 4


def test_build_recommendations_sorted_by_severity():
    findings = [
        {
            "check_id": "TEST_LOW",
            "title": "Low Finding",
            "severity": "LOW",
            "domain": "security",
            "recommendation": "Rec",
            "rationale": "Rationale",
            "evidence": "Evidence",
        },
        {
            "check_id": "TEST_CRIT",
            "title": "Crit Finding",
            "severity": "CRIT",
            "domain": "security",
            "recommendation": "Rec",
            "rationale": "Rationale",
            "evidence": "Evidence",
        },
        {
            "check_id": "TEST_HIGH",
            "title": "High Finding",
            "severity": "HIGH",
            "domain": "security",
            "recommendation": "Rec",
            "rationale": "Rationale",
            "evidence": "Evidence",
        },
    ]
    result = build_recommendations(findings)
    assert result[0]["source_check_id"] == "TEST_CRIT"
    assert result[1]["source_check_id"] == "TEST_HIGH"
    assert result[2]["source_check_id"] == "TEST_LOW"