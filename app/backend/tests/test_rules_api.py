import pytest
from unittest.mock import patch, MagicMock


def test_get_rules_loads_rules():
    from app.services.scoring import load_rules

    with patch("app.services.scoring.Path") as mock_path:
        mock_rules_file = MagicMock()
        mock_path.return_value = mock_rules_file
        
        with patch("app.services.scoring.Path.exists", return_value=True):
            with patch("builtins.open", MagicMock()):
                import json
                mock_rules_file.read_text.return_value = json.dumps({
                    "security_weights": {"low": 5},
                    "score_weights": {"security": 0.6}
                })
                
                from pathlib import Path
                with patch.object(Path, "exists", return_value=True):
                    mock_path.return_value.exists = lambda: True
                    mock_path.return_value.resolve.return_value = mock_path.return_value
                    
                    result = load_rules(mock_path.return_value)
                    assert "security_weights" in result


def test_save_rules():
    from app.api.routes.rules import save_rules
    
    test_data = {"security_weights": {"low": 5}}
    
    with patch("app.api.routes.rules.RULES_FILE") as mock_file:
        mock_file.write_text = MagicMock()
        save_rules(test_data)
        mock_file.write_text.assert_called_once()


def test_get_rules_returns_summary():
    from app.api.routes.rules import get_rules, RulesSummary
    
    with patch("app.api.routes.rules.load_rules", return_value={
        "security_weights": {"low": 5, "medium": 15},
        "critical_services": ["ssh", "nginx"]
    }):
        result = get_rules()
        assert isinstance(result, RulesSummary)
        assert result.total >= 2


def test_reload_rules_returns_ok():
    from app.api.routes.rules import reload_rules
    
    result = reload_rules()
    assert result["status"] == "ok"
    assert "Rules reloaded" in result["message"]