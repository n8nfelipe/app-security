import pytest
from unittest.mock import patch, MagicMock
from app.core import errors


def test_scan_execution_error():
    err = errors.ScanExecutionError("Test error")
    assert "Test error" in str(err)


def test_agent_mode_unavailable_error():
    err = errors.AgentModeUnavailableError("Agent unavailable")
    assert "Agent unavailable" in str(err)


def test_scan_execution_error_with_cause():
    cause = ValueError("Original cause")
    err = errors.ScanExecutionError("Test error")
    assert err is not None