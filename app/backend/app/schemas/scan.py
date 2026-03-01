from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["INFO", "LOW", "MED", "HIGH", "CRIT"]


class ScanCreateRequest(BaseModel):
    mode: Literal["agentless", "agent"] = "agentless"
    target_name: str | None = Field(default=None, max_length=255)


class ScanCreateResponse(BaseModel):
    scan_id: str
    status: str
    mode: str
    created_at: datetime


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    mode: str
    started_at: datetime
    completed_at: datetime | None = None
    error_message: str | None = None


class ScoreBreakdown(BaseModel):
    security: float
    performance: float
    overall: float
    explanation: dict


class FindingResponse(BaseModel):
    id: int
    check_id: str
    domain: str
    category: str
    severity: Severity
    title: str
    evidence: str
    recommendation: str
    reference: str | None
    rationale: str
    weight: int
    metadata: dict | None = None


class RecommendationResponse(BaseModel):
    id: int
    title: str
    priority: str
    risk: str
    impact: str
    effort: str
    domain: str
    action: str
    reason: str
    source_check_id: str | None = None
    metadata: dict | None = None


class ScanResultResponse(BaseModel):
    scan_id: str
    status: str
    mode: str
    machine_hostname: str | None
    machine_id: str | None
    distro: str | None
    started_at: datetime
    completed_at: datetime | None = None
    summary: dict | None = None
    scores: ScoreBreakdown | None = None
    findings: list[FindingResponse]
    recommendations: list[RecommendationResponse]
    raw_payload: dict | None = None


class HistoryItem(BaseModel):
    scan_id: str
    status: str
    mode: str
    machine_hostname: str | None
    machine_id: str | None
    overall_score: float | None
    security_score: float | None
    performance_score: float | None
    started_at: datetime
    completed_at: datetime | None = None


class HistoryResponse(BaseModel):
    items: list[HistoryItem]


class ExportArtifactResponse(BaseModel):
    scan_id: str
    artifact_type: str
    file_name: str
    file_path: str | None = None
    content_type: str
    payload: dict | None = None
