import pytest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path


def test_export_scan_to_json_not_found():
    from app.services.exporter import export_scan_to_json

    with patch("app.services.exporter.get_scan_result") as mock_result:
        from fastapi import HTTPException
        mock_result.side_effect = HTTPException(status_code=404, detail="Scan not found")
        mock_settings = MagicMock()
        mock_settings.export_dir = MagicMock()

        with patch("app.services.exporter.settings", mock_settings):
            with pytest.raises(HTTPException):
                export_scan_to_json("nonexistent-id")


@patch("app.services.exporter.settings")
@patch("builtins.open", new_callable=mock_open)
def test_export_scan_to_json_success(mock_file, mock_settings):
    from app.services.exporter import export_scan_to_json

    mock_settings.export_dir = MagicMock()
    mock_settings.export_dir.__truediv__ = MagicMock(return_value=MagicMock())
    mock_settings.export_dir.__truediv__.return_value.write_text = MagicMock()

    with patch("app.services.exporter.get_scan_result", return_value=MagicMock(model_dump=MagicMock(return_value={}))):
        with patch("app.services.exporter._upsert_artifact", return_value=None):
            result = export_scan_to_json("scan-123")
            assert result.scan_id == "scan-123"


@patch("app.services.exporter.settings")
def test_export_scan_to_pdf_success(mock_settings):
    from app.services.exporter import export_scan_to_pdf

    mock_settings.export_dir = MagicMock()
    mock_settings.export_dir.__truediv__ = MagicMock(return_value=MagicMock())
    mock_settings.export_dir.__truediv__.return_value.write_bytes = MagicMock()

    mock_result = MagicMock()
    mock_result.model_dump.return_value = {
        "scan_id": "scan-pdf",
        "status": "completed",
        "machine_hostname": "pdf-host",
        "scores": {"security": 80.0, "performance": 85.0, "overall": 82.0}
    }

    with patch("app.services.exporter.get_scan_result", return_value=mock_result), \
         patch("app.services.exporter._upsert_artifact", return_value=None):
        result = export_scan_to_pdf("scan-pdf")
        assert result.scan_id == "scan-pdf"


def test_export_scan_to_pdf_not_found():
    from app.services.exporter import export_scan_to_pdf
    from fastapi import HTTPException

    with patch("app.services.exporter.get_scan_result") as mock_result:
        mock_result.side_effect = HTTPException(status_code=404, detail="Scan not found")

        with patch("app.services.exporter.settings", MagicMock()):
            with pytest.raises(HTTPException):
                export_scan_to_pdf("nonexistent-id")


def test_upsert_artifact_success():
    from app.services.exporter import _upsert_artifact

    with patch("app.services.exporter.Artifact") as mock_artifact_class, \
         patch("app.services.exporter.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_artifact_instance = MagicMock()
        mock_artifact_class.return_value = mock_artifact_instance

        _upsert_artifact(
            scan_id="scan-789",
            artifact_type="json",
            file_name="scan-789.json",
            file_path=Path("/exports/scan-789.json"),
            content_type="application/json"
        )

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()


def test_upsert_artifact_handles_close_on_exception():
    from app.services.exporter import _upsert_artifact

    with patch("app.services.exporter.Artifact") as mock_artifact_class, \
         patch("app.services.exporter.SessionLocal") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_artifact_instance = MagicMock()
        mock_artifact_class.return_value = mock_artifact_instance

        _upsert_artifact(
            scan_id="scan-error",
            artifact_type="json",
            file_name="scan-error.json",
            file_path=Path("/exports/scan-error.json"),
            content_type="application/json"
        )

        mock_session.close.assert_called_once()