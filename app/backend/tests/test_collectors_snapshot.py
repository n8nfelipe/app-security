from unittest.mock import patch, MagicMock
from app.collectors.linux import (
    TEXT_FILES,
    DIRECTORIES,
    COMMANDS,
    collect_local_snapshot,
)


class TestCollectLocalSnapshot:
    @patch("app.collectors.linux.Path.exists")
    @patch("app.collectors.linux.Path.read_text")
    @patch("app.collectors.linux.psutil")
    def test_collect_local_snapshot_success(self, mock_psutil, mock_read_text, mock_exists):
        mock_exists.return_value = True
        mock_read_text.return_value = "test-hostname"
        
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 50.0
        mock_psutil.getloadavg.return_value = (1.0, 0.5, 0.25)
        mock_psutil.virtual_memory.return_value = MagicMock(_asdict=lambda: {"total": 8000})
        mock_psutil.swap_memory.return_value = MagicMock(_asdict=lambda: {"total": 1000})
        mock_psutil.disk_usage.return_value = MagicMock(_asdict=lambda: {"total": 100000})
        mock_psutil.net_io_counters.return_value = MagicMock(_asdict=lambda: {"bytes_sent": 1000})
        
        with patch("app.collectors.linux._run_command") as mock_cmd:
            with patch("app.collectors.linux._run_limited_find") as mock_find:
                mock_cmd.return_value = {"available": True, "stdout": "test"}
                mock_find.return_value = {"available": True, "stdout": "test"}
                
                result = collect_local_snapshot()
                
                assert "metadata" in result
                assert "psutil" in result["metadata"]
                assert result["metadata"]["hostname"] == "test-hostname"
                assert "files" in result
                assert "commands" in result
                assert "filesystem_checks" in result

    @patch("app.collectors.linux.Path.exists")
    @patch("app.collectors.linux.Path.read_text")
    @patch("app.collectors.linux.psutil")
    def test_collect_local_snapshot_files_structure(self, mock_psutil, mock_read_text, mock_exists):
        mock_exists.return_value = False
        mock_read_text.return_value = ""
        
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 50.0
        mock_psutil.getloadavg.return_value = (1.0, 0.5, 0.25)
        mock_psutil.virtual_memory.return_value = MagicMock(_asdict=lambda: {"total": 8000})
        mock_psutil.swap_memory.return_value = MagicMock(_asdict=lambda: {"total": 1000})
        mock_psutil.disk_usage.return_value = MagicMock(_asdict=lambda: {"total": 100000})
        mock_psutil.net_io_counters.return_value = MagicMock(_asdict=lambda: {"bytes_sent": 1000})
        
        with patch("app.collectors.linux._run_command") as mock_cmd:
            with patch("app.collectors.linux._run_limited_find") as mock_find:
                mock_cmd.return_value = {"available": True, "stdout": "test"}
                mock_find.return_value = {"available": True, "stdout": "test"}
                
                result = collect_local_snapshot()
                
                assert "files" in result
                assert "passwd" in result["files"]
                assert "group" in result["files"]


def test_text_files_dict():
    assert "passwd" in TEXT_FILES
    assert "group" in TEXT_FILES
    assert "os_release" in TEXT_FILES


def test_directories_dict():
    assert "sudoers_d" in DIRECTORIES


def test_commands_dict_has_all():
    assert "listening_ports" in COMMANDS
    assert "established_connections" in COMMANDS
    assert "systemd_units" in COMMANDS
    assert "firewall_nft" in COMMANDS
    assert "disk_usage" in COMMANDS