from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from app.core.auth import require_api_token
from app.core.logging import get_logger
from app.schemas.scan import (
    ExportArtifactResponse,
    HistoryResponse,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanResultResponse,
    ScanStatusResponse,
)
from app.services.exporter import export_scan_to_json, export_scan_to_pdf
from app.services.scan_service import (
    create_scan,
    get_scan_history,
    get_scan_result,
    get_scan_status,
    run_scan_background,
)

router = APIRouter(dependencies=[Depends(require_api_token)])
logger = get_logger(__name__)


@router.post("/scans", response_model=ScanCreateResponse, status_code=202)
def start_scan(payload: ScanCreateRequest, background_tasks: BackgroundTasks) -> ScanCreateResponse:
    scan = create_scan(payload)
    background_tasks.add_task(run_scan_background, scan.scan_id)
    logger.info("scan_scheduled", extra={"scan_id": scan.scan_id, "mode": payload.mode})
    return scan


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
def scan_status(scan_id: str) -> ScanStatusResponse:
    return get_scan_status(scan_id)


@router.get("/scans/{scan_id}/results", response_model=ScanResultResponse)
def scan_results(scan_id: str) -> ScanResultResponse:
    return get_scan_result(scan_id)


@router.get("/history", response_model=HistoryResponse)
def scan_history(
    hostname: str | None = Query(default=None),
    machine_id: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
) -> HistoryResponse:
    return get_scan_history(hostname=hostname, machine_id=machine_id, limit=limit)


@router.get("/scans/{scan_id}/export/json")
def export_json(scan_id: str):
    artifact = export_scan_to_json(scan_id)
    return JSONResponse(
        status_code=200,
        content=ExportArtifactResponse.model_validate(artifact).model_dump(mode="json"),
    )


@router.get("/scans/{scan_id}/export/pdf")
def export_pdf(scan_id: str):
    artifact = export_scan_to_pdf(scan_id)
    if not artifact.file_path:
        raise HTTPException(status_code=501, detail="PDF export is not available")
    return FileResponse(
        artifact.file_path,
        media_type="application/pdf",
        filename=artifact.file_name,
    )
