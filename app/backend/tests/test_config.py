import pytest
from unittest.mock import patch, MagicMock

def test_config_settings():
    from app.core.config import Settings, settings
    assert settings.app_name == "App Security Audit"
    assert settings.default_scan_mode == "agentless"

def test_config_custom():
    from app.core.config import Settings
    s = Settings(api_token="test-token")
    assert s.api_token == "test-token"

def test_config_cors():
    from app.core.config import settings
    assert "localhost" in str(settings.cors_origins)

def test_config_rules_file():
    from app.core.config import settings
    assert settings.rules_file is not None

def test_config_export_dir():
    from app.core.config import settings
    assert settings.export_dir is not None

def test_config_timeout():
    from app.core.config import settings
    assert settings.command_timeout_seconds > 0

def test_config_singleton():
    from app.core.config import settings
    s1 = settings
    s2 = settings
    assert s1 is s2