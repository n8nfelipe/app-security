from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import HTTPException

from app.collectors.linux import collect_local_snapshot
from app.core.config import settings
from app.core.errors import AgentModeUnavailableError, ScanExecutionError
from app.core.logging import get_logger
from app.db.models import Finding, Recommendation, Scan
from app.db.session import get_db
from app.schemas.scan import (
    HistoryItem,
    HistoryResponse,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanResultResponse,
    ScanStatusResponse,
    ScoreBreakdown,
)
from app.services.agent_client import collect_via_agent
from app.services import parser
from app.services.recommendations import build_recommendations
from app.services.scoring import build_findings, calculate_scores, load_rules, summarize_snapshot

logger = get_logger(__name__)


def create_scan(payload: ScanCreateRequest) -> ScanCreateResponse:
    with get_db() as db:
        scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        scan = Scan(id=scan_id, mode=payload.mode, target_name=payload.target_name, status="queued", started_at=now)
        db.add(scan)
        db.commit()
        return ScanCreateResponse(scan_id=scan_id, status=scan.status, mode=scan.mode, created_at=now)


def run_scan_background(scan_id: str) -> None:
    with get_db() as db:
        try:
            scan = db.get(Scan, scan_id)
            if not scan:
                return
            scan.status = "running"
            db.commit()
            rules = load_rules(settings.rules_file)
            snapshot = collect_via_agent(scan.target_name) if scan.mode == "agent" else collect_local_snapshot()
            findings = build_findings(snapshot, rules)
            scores = calculate_scores(findings, rules)
            recommendations = build_recommendations(findings)
            summary = summarize_snapshot(snapshot, findings)
            os_release = parser.parse_key_value_file(snapshot["files"]["os_release"].get("content", ""))

            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.machine_hostname = snapshot["metadata"].get("hostname")
            scan.machine_id = snapshot["files"]["machine_id"].get("content", "").strip() or None
            scan.distro = os_release.get("PRETTY_NAME")
            scan.security_score = scores["security"]
            scan.performance_score = scores["performance"]
            scan.overall_score = scores["overall"]
            scan.score_explanation = scores["explanation"]
            scan.summary = summary
            scan.raw_payload = snapshot

            for finding in findings:
                db.add(Finding(scan_id=scan_id, **finding))
            for recommendation in recommendations:
                db.add(Recommendation(scan_id=scan_id, **recommendation))
            db.commit()
            logger.info("scan_completed", extra={"scan_id": scan_id, "overall_score": scores["overall"]})
        except (ScanExecutionError, AgentModeUnavailableError) as exc:
            _mark_scan_failed(db, scan_id, str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            _mark_scan_failed(db, scan_id, f"Unhandled scan failure: {exc}")


def get_scan_status(scan_id: str) -> ScanStatusResponse:
    with get_db() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return ScanStatusResponse(
            scan_id=scan.id,
            status=scan.status,
            mode=scan.mode,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            error_message=scan.error_message,
        )


def get_scan_result(scan_id: str) -> ScanResultResponse:
    with get_db() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = [
            {
                "id": item.id,
                "check_id": item.check_id,
                "domain": item.domain,
                "category": item.category,
                "severity": item.severity,
                "title": item.title,
                "evidence": item.evidence,
                "recommendation": item.recommendation,
                "reference": item.reference,
                "rationale": item.rationale,
                "weight": item.weight,
                "metadata": item.extra_data,
            }
            for item in scan.findings
        ]
        recommendations = [
            {
                "id": item.id,
                "title": item.title,
                "priority": item.priority,
                "risk": item.risk,
                "impact": item.impact,
                "effort": item.effort,
                "domain": item.domain,
                "action": item.action,
                "reason": item.reason,
                "source_check_id": item.source_check_id,
                "metadata": item.extra_data,
            }
            for item in scan.recommendations
        ]
        scores = None
        if scan.security_score is not None and scan.performance_score is not None and scan.overall_score is not None:
            scores = ScoreBreakdown(
                security=scan.security_score,
                performance=scan.performance_score,
                overall=scan.overall_score,
                explanation=scan.score_explanation or {},
            )
        return ScanResultResponse(
            scan_id=scan.id,
            status=scan.status,
            mode=scan.mode,
            machine_hostname=scan.machine_hostname,
            machine_id=scan.machine_id,
            distro=scan.distro,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            summary=scan.summary,
            scores=scores,
            findings=findings,
            recommendations=recommendations,
            raw_payload=scan.raw_payload,
        )


def get_scan_history(hostname: str | None, machine_id: str | None, limit: int) -> HistoryResponse:
    with get_db() as db:
        query = db.query(Scan).order_by(Scan.started_at.desc())
        if hostname:
            query = query.filter(Scan.machine_hostname == hostname)
        if machine_id:
            query = query.filter(Scan.machine_id == machine_id)
        items = [
            HistoryItem(
                scan_id=scan.id,
                status=scan.status,
                mode=scan.mode,
                machine_hostname=scan.machine_hostname,
                machine_id=scan.machine_id,
                overall_score=scan.overall_score,
                security_score=scan.security_score,
                performance_score=scan.performance_score,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
            )
            for scan in query.limit(limit).all()
        ]
        return HistoryResponse(items=items)


def _mark_scan_failed(db, scan_id: str, error_message: str) -> None:
    scan = db.get(Scan, scan_id)
    if not scan:
        return
    scan.status = "failed"
    scan.completed_at = datetime.now(timezone.utc)
    scan.error_message = error_message
    db.commit()
    logger.error("scan_failed", extra={"scan_id": scan_id, "error": error_message})
