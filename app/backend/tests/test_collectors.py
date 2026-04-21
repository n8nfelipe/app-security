import pytest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
from app.collectors.linux import (
    CommandSpec,
    TEXT_FILES,
    DIRECTORIES,
    COMMANDS,
    _safe_read_text,
    _safe_read_directory,
    _run_command,
    _run_limited_find,
    collect_local_snapshot,
)


class TestCommandSpec:
    def test_command_spec_creation(self):
        spec = CommandSpec(
            key="test_key",
            argv=["echo", "hello"],
            rationale="Test command",
            timeout=10
        )
        assert spec.key == "test_key"
        assert spec.argv == ["echo", "hello"]
        assert spec.rationale == "Test command"
        assert spec.timeout == 10


class TestSafeReadText:
    @patch("app.collectors.linux.Path.read_text")
    def test_safe_read_text_success(self, mock_read):
        mock_read.return_value = "test content"
        path = Path("/etc/passwd")
        result = _safe_read_text(path)
        assert result["exists"] is True
        assert result["content"] == "test content"
        assert result["path"] == str(path)

    @patch("app.collectors.linux.Path.read_text")
    def test_safe_read_text_file_not_found(self, mock_read):
        mock_read.side_effect = FileNotFoundError()
        path = Path("/nonexistent")
        result = _safe_read_text(path)
        assert result["exists"] is False
        assert result["content"] == ""

    @patch("app.collectors.linux.Path.read_text")
    def test_safe_read_text_permission_denied(self, mock_read):
        mock_read.side_effect = PermissionError()
        path = Path("/root/secret")
        result = _safe_read_text(path)
        assert result["exists"] is False
        assert result["error"] == "permission_denied"


class TestSafeReadDirectory:
    @patch("app.collectors.linux.Path.exists")
    def test_safe_read_directory_not_exists(self, mock_exists):
        mock_exists.return_value = False
        path = Path("/nonexistent")
        result = _safe_read_directory(path)
        assert result["exists"] is False
        assert result["entries"] == []

    @patch("app.collectors.linux.Path.iterdir")
    @patch("app.collectors.linux.Path.exists")
    def test_safe_read_directory_success(self, mock_exists, mock_iterdir):
        mock_exists.return_value = True
        
        mock_file = MagicMock()
        mock_file.name = "test.txt"
        mock_file.is_file.return_value = True
        mock_file.read_text.return_value = "file content"
        mock_iterdir.return_value = [mock_file]
        
        path = Path("/test")
        result = _safe_read_directory(path)
        assert result["exists"] is True
        assert len(result["entries"]) == 1
        assert result["entries"][0]["name"] == "test.txt"

    @patch("app.collectors.linux.Path.iterdir")
    @patch("app.collectors.linux.Path.exists")
    def test_safe_read_directory_permission_denied(self, mock_exists, mock_iterdir):
        mock_exists.return_value = True
        mock_iterdir.side_effect = PermissionError()
        
        path = Path("/test")
        result = _safe_read_directory(path)
        assert result["exists"] is False
        assert result["error"] == "permission_denied"


class TestRunCommand:
    @patch("app.collectors.linux.settings")
    @patch("app.collectors.linux.shutil.which")
    def test_run_command_binary_not_found(self, mock_which, mock_settings):
        mock_settings.host_fs_prefix = ""
        mock_which.return_value = None
        
        spec = CommandSpec(
            key="nonexistent",
            argv=["nonexistent_cmd"],
            rationale="Test",
            timeout=5
        )
        
        result = _run_command(spec)
        assert result["available"] is False
        assert result["reason"] == "binary_not_found"

    @patch("app.collectors.linux.subprocess.run")
    @patch("app.collectors.linux.shutil.which")
    @patch("app.collectors.linux.settings")
    def test_run_command_success(self, mock_settings, mock_which, mock_run):
        mock_settings.host_fs_prefix = ""
        mock_which.return_value = "/bin/echo"
        
        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_completed.stdout = "hello"
        mock_completed.stderr = ""
        mock_run.return_value = mock_completed
        
        spec = CommandSpec(
            key="echo",
            argv=["echo", "hello"],
            rationale="Test",
            timeout=5
        )
        
        result = _run_command(spec)
        assert result["available"] is True
        assert result["timed_out"] is False
        assert result["returncode"] == 0

    @patch("app.collectors.linux.subprocess.run")
    @patch("app.collectors.linux.shutil.which")
    @patch("app.collectors.linux.settings")
    def test_run_command_timeout(self, mock_settings, mock_which, mock_run):
        import subprocess
        mock_settings.host_fs_prefix = ""
        mock_which.return_value = "/bin/sleep"
        mock_run.side_effect = subprocess.TimeoutExpired("sleep 100", "output")
        
        spec = CommandSpec(
            key="sleep",
            argv=["sleep", "100"],
            rationale="Test",
            timeout=5
        )
        
        result = _run_command(spec)
        assert result["available"] is True
        assert result["timed_out"] is True

    @patch("app.collectors.linux.subprocess.run")
    @patch("app.collectors.linux.shutil.which")
    @patch("app.collectors.linux.settings")
    def test_run_command_with_chroot(self, mock_settings, mock_which, mock_run):
        import subprocess
        mock_settings.host_fs_prefix = "/mnt"
        mock_which.return_value = "/usr/sbin/chroot"
        
        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_completed.stdout = "output"
        mock_completed.stderr = ""
        mock_run.return_value = mock_completed
        
        spec = CommandSpec(
            key="list_ports",
            argv=["ss", "-tulpen"],
            rationale="Test",
            timeout=5
        )
        
        result = _run_command(spec)
        assert result["available"] is True
        mock_run.assert_called_once()


class TestRunLimitedFind:
    @patch("app.collectors.linux.subprocess.run")
    @patch("app.collectors.linux.shutil.which")
    @patch("app.collectors.linux.settings")
    def test_run_limited_find_success(self, mock_settings, mock_which, mock_run):
        mock_settings.find_timeout_seconds = 10
        mock_settings.command_output_limit = 20000
        mock_which.return_value = "/usr/bin/find"
        
        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_completed.stdout = "file1\nfile2\n"
        mock_completed.stderr = ""
        mock_run.return_value = mock_completed
        
        result = _run_limited_find(["/", "-name", "*.txt"])
        assert result["available"] is True
        assert result["timed_out"] is False

    @patch("app.collectors.linux.subprocess.run")
    @patch("app.collectors.linux.shutil.which")
    @patch("app.collectors.linux.settings")
    def test_run_limited_find_binary_not_found(self, mock_settings, mock_which, mock_run):
        mock_settings.find_timeout_seconds = 10
        mock_which.return_value = None
        
        result = _run_limited_find(["/", "-name", "*.txt"])
        assert result["available"] is False
        assert result["reason"] == "binary_not_found"

    @patch("app.collectors.linux.subprocess.run")
    @patch("app.collectors.linux.shutil.which")
    @patch("app.collectors.linux.settings")
    def test_run_limited_find_timeout(self, mock_settings, mock_which, mock_run):
        import subprocess
        mock_settings.find_timeout_seconds = 10
        mock_settings.command_output_limit = 20000
        mock_which.return_value = "/usr/bin/find"
        mock_run.side_effect = subprocess.TimeoutExpired("find", "partial output")
        
        result = _run_limited_find(["/", "-name", "*.txt"])
        assert result["available"] is True
        assert result["timed_out"] is True