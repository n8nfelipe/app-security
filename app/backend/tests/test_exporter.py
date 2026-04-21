import pytest
from unittest.mock import patch, MagicMock, mock_open
from fastapi import HTTPException


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
    
    mock_artifact = MagicMock()
    mock_artifact.scan_id = "scan-123"
    mock_artifact.file_name = "scan-123.json"
    mock_artifact.file_path = "/exports/scan-123.json"
    mock_artifact.content_type = "application/json"
    mock_artifact.payload = {}
    
    with patch("app.services.exporter.get_scan_result", return_value=MagicMock(model_dump=MagicMock(return_value={}))):
        with patch("app.services.exporter._upsert_artifact", return_value=None):
            result = export_scan_to_json("scan-123")
            assert result.scan_id == "scan-123"


@patch("app.services.exporter.settings")
@patch("builtins.open", new_callable=mock_open)
def test_export_scan_to_pdf_success(mock_file, mock_settings):
    from app.services.exporter import export_scan_to_pdf
    
    mock_settings.export_dir = MagicMock()
    mock_settings.export_dir.__truediv__ = MagicMock(return_value=MagicMock())
    mock_settings.export_dir.__truediv__.return_value.write_text = MagicMock()
    
    with patch("app.services.exporter.get_scan_result", return_value=MagicMock(model_dump=MagicMock(return_value={}))):
        with patch("app.services.exporter._render_pdf", return_value=None):
            with patch("app.services.exporter._upsert_artifact", return_value=None):
                result = export_scan_to_pdf("scan-123")
                assert result.scan_id == "scan-123"


def test_render_pdf():
    from app.services.exporter import _render_pdf
    
    with patch("app.services.exporter.canvas.Canvas") as mock_canvas:
        mock_canvas_instance = MagicMock()
        mock_canvas.return_value = mock_canvas_instance
        
        _render_pdf(MagicMock(), {"scan_id": "test-123", "scores": {"security": 80, "performance": 85, "overall": 82}})
        
        mock_canvas_instance.setFont.assert_called()
        mock_canvas_instance.drawString.assert_called()
        mock_canvas_instance.save.assert_called_once()