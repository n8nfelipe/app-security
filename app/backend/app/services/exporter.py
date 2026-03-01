from __future__ import annotations

import json
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from app.core.config import settings
from app.db.models import Artifact
from app.db.session import SessionLocal
from app.schemas.scan import ExportArtifactResponse
from app.services.scan_service import get_scan_result


def export_scan_to_json(scan_id: str) -> ExportArtifactResponse:
    result = get_scan_result(scan_id)
    file_name = f"{scan_id}.json"
    file_path = settings.export_dir / file_name
    payload = result.model_dump(mode="json")
    file_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    _upsert_artifact(scan_id, "json", file_name, file_path, "application/json")
    return ExportArtifactResponse(
        scan_id=scan_id,
        artifact_type="json",
        file_name=file_name,
        file_path=str(file_path),
        content_type="application/json",
        payload=payload,
    )


def export_scan_to_pdf(scan_id: str) -> ExportArtifactResponse:
    result = get_scan_result(scan_id)
    file_name = f"{scan_id}.pdf"
    file_path = settings.export_dir / file_name
    _render_pdf(file_path, result.model_dump(mode="json"))
    _upsert_artifact(scan_id, "pdf", file_name, file_path, "application/pdf")
    return ExportArtifactResponse(
        scan_id=scan_id,
        artifact_type="pdf",
        file_name=file_name,
        file_path=str(file_path),
        content_type="application/pdf",
    )


def _render_pdf(path: Path, payload: dict) -> None:
    pdf = canvas.Canvas(str(path), pagesize=A4)
    width, height = A4
    y = height - 50
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(40, y, "App Security Audit Report")
    y -= 24
    pdf.setFont("Helvetica", 10)
    lines = [
        f"Scan ID: {payload['scan_id']}",
        f"Host: {payload.get('machine_hostname') or 'unknown'}",
        f"Security Score: {payload['scores']['security'] if payload.get('scores') else 'n/a'}",
        f"Performance Score: {payload['scores']['performance'] if payload.get('scores') else 'n/a'}",
        f"Overall Score: {payload['scores']['overall'] if payload.get('scores') else 'n/a'}",
        "",
        "Top recommendations:",
    ]
    for recommendation in payload.get("recommendations", [])[:8]:
        lines.append(f"- {recommendation['priority']} {recommendation['title']}")
    for line in lines:
        pdf.drawString(40, y, line[:100])
        y -= 16
    pdf.showPage()
    pdf.save()


def _upsert_artifact(scan_id: str, artifact_type: str, file_name: str, file_path: Path, content_type: str) -> None:
    db = SessionLocal()
    try:
        artifact = Artifact(
            scan_id=scan_id,
            artifact_type=artifact_type,
            file_name=file_name,
            file_path=str(file_path),
            content_type=content_type,
        )
        db.add(artifact)
        db.commit()
    finally:
        db.close()
