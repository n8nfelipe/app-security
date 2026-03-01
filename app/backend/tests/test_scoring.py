from app.services.scoring import calculate_scores


def test_calculate_scores_applies_weighted_penalties():
    findings = [
        {"domain": "security", "severity": "CRIT"},
        {"domain": "security", "severity": "HIGH"},
        {"domain": "performance", "severity": "MED"},
    ]
    rules = {
        "security_weights": {"CRIT": 25, "HIGH": 15, "MED": 8, "LOW": 3, "INFO": 0},
        "score_weights": {"security": 0.6, "performance": 0.4},
    }
    scores = calculate_scores(findings, rules)
    assert scores["security"] == 60.0
    assert scores["performance"] == 92.0
    assert scores["overall"] == 72.8
