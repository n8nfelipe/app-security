from fastapi import APIRouter, Depends
from app.core.auth import require_api_token
from pydantic import BaseModel
from typing import List, Optional
from pathlib import Path
import json

router = APIRouter(dependencies=[Depends(require_api_token)])

RULES_FILE = Path(__file__).resolve().parents[2] / "config" / "rules.json"

class Rule(BaseModel):
    id: str
    description: str
    severity: str
    enabled: bool = True
    category: Optional[str] = None

class RulesSummary(BaseModel):
    total: int
    enabled: int
    disabled: int
    rules: List[Rule]

def load_rules() -> dict:
    if not RULES_FILE.exists():
        return {}
    return json.loads(RULES_FILE.read_text())

def save_rules(data: dict) -> None:
    RULES_FILE.write_text(json.dumps(data, indent=2))

@router.get("/rules", response_model=RulesSummary)
def get_rules() -> RulesSummary:
    data = load_rules()
    
    security_weights = data.get("security_weights", {})
    critical_services = data.get("critical_services", [])
    
    # Build rules list from config
    rules = []
    
    # Security rules from weights
    for sev, weight in security_weights.items():
        rules.append(Rule(
            id=f"sec_{sev.lower()}_severity",
            description=f"Findings with {sev} severity",
            severity=sev,
            enabled=True,
            category="security"
        ))
    
    # Critical services
    for svc in critical_services:
        rules.append(Rule(
            id=f"svc_{svc.replace('.', '_')}",
            description=f"Critical service: {svc}",
            severity="HIGH",
            enabled=True,
            category="services"
        ))
    
    enabled = sum(1 for r in rules if r.enabled)
    
    return RulesSummary(
        total=len(rules),
        enabled=enabled,
        disabled=len(rules) - enabled,
        rules=rules
    )

@router.post("/rules/reload")
def reload_rules() -> dict:
    """Reload rules from file"""
    return {"status": "ok", "message": "Rules reloaded"}