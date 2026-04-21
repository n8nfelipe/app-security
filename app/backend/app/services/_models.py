from dataclasses import dataclass, field


@dataclass
class Finding:
    check_id: str
    domain: str
    category: str
    severity: str
    title: str
    rationale: str
    evidence: str
    recommendation: str
    reference: str
    weight: float = 0.0
    extra_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "domain": self.domain,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "rationale": self.rationale,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "reference": self.reference,
            "weight": self.weight,
            "extra_data": self.extra_data,
        }


@dataclass
class Checker:
    check_id: str
    domain: str
    category: str
    severity: str
    title: str
    rationale: str
    recommendation: str
    reference: str

    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        raise NotImplementedError


@dataclass
class Rules:
    security_weights: dict
    performance_thresholds: dict
    critical_services: list
    score_weights: dict

    @classmethod
    def from_dict(cls, data: dict) -> "Rules":
        return cls(
            security_weights=data.get("security_weights", {}),
            performance_thresholds=data.get("performance_thresholds", {}),
            critical_services=data.get("critical_services", []),
            score_weights=data.get("score_weights", {"security": 0.6, "performance": 0.4}),
        )