from __future__ import annotations


PRIORITY_MAP = {
    "CRIT": ("P0", "low", "high", "medium"),
    "HIGH": ("P1", "low", "high", "medium"),
    "MED": ("P2", "medium", "medium", "low"),
    "LOW": ("P3", "low", "medium", "low"),
    "INFO": ("P4", "low", "low", "low"),
}

SEVERITY_ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3, "INFO": 4}


def build_recommendations(findings: list[dict]) -> list[dict]:
    recommendations: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for finding in sorted(findings, key=lambda item: (SEVERITY_ORDER[item["severity"]], item["domain"])):
        key = (finding["check_id"], finding["recommendation"])
        if key in seen:
            continue
        seen.add(key)
        priority, risk, impact, effort = PRIORITY_MAP[finding["severity"]]
        recommendations.append(
            {
                "title": finding["title"],
                "priority": priority,
                "risk": risk,
                "impact": impact,
                "effort": effort,
                "domain": finding["domain"],
                "action": finding["recommendation"],
                "reason": finding["rationale"],
                "source_check_id": finding["check_id"],
                "extra_data": {
                    "severity": finding["severity"],
                    "reference": finding.get("reference"),
                    "remediation": finding.get("extra_data", {}).get("remediation"),
                },
            }
        )
    return recommendations
