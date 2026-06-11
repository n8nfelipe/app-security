from app.core.config import Settings


def test_settings_defaults():
    s = Settings(api_token="test-token")
    assert s.app_name == "App Security Audit"
    assert s.api_token == "test-token"
    assert s.default_scan_mode == "agentless"


def test_settings_with_custom_values():
    s = Settings(
        app_name="Custom App",
        api_token="custom-token",
        default_scan_mode="agent"
    )
    assert s.app_name == "Custom App"
    assert s.api_token == "custom-token"


def test_settings_cors_list():
    s = Settings(api_token="test-token")
    assert "localhost" in str(s.cors_origins)


def test_settings_timeout_values():
    s = Settings(api_token="test-token")
    assert s.command_timeout_seconds > 0
    assert s.find_timeout_seconds > 0


def test_settings_export_dir():
    s = Settings(api_token="test-token")
    assert s.export_dir is not None


def test_settings_database_url():
    s = Settings(api_token="test-token")
    assert s.database_url is not None
    assert "sqlite" in s.database_url or "postgresql" in s.database_url


def test_settings_rules_file():
    s = Settings(api_token="test-token")
    assert s.rules_file is not None


def test_get_settings_singleton():
    from app.core.config import get_settings
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2