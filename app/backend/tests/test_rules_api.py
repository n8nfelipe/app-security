from unittest.mock import patch, mock_open, MagicMock
from app.api.routes.rules import load_rules, save_rules


class TestLoadRules:
    def test_load_rules_file_not_exists(self):
        with patch("pathlib.Path.exists", return_value=False):
            result = load_rules()
            assert result == {}

    def test_load_rules_file_exists(self):
        mock_data = '{"security_weights": {"HIGH": 3.0}}'
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value=mock_data):
                result = load_rules()
                assert result["security_weights"]["HIGH"] == 3.0


class TestSaveRules:
    def test_save_rules_writes_json(self):
        data = {"security_weights": {"HIGH": 3.0}}
        with patch("pathlib.Path.write_text") as mock_write:
            save_rules(data)
            mock_write.assert_called_once()
            assert "security_weights" in mock_write.call_args[0][0]