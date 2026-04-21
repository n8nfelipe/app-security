import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from app.collectors.linux import (
    TEXT_FILES,
    DIRECTORIES,
    COMMANDS,
)


def test_text_files_structure():
    assert "passwd" in TEXT_FILES
    assert "group" in TEXT_FILES
    assert "os_release" in TEXT_FILES


def test_directories_structure():
    assert "sudoers_d" in DIRECTORIES


def test_commands_keys():
    assert "listening_ports" in COMMANDS
    assert "established_connections" in COMMANDS
    assert "systemd_units" in COMMANDS
    assert "firewall_nft" in COMMANDS


def test_comman_all_have_keys():
    for key, spec in COMMANDS.items():
        assert spec.key == key
        assert spec.argv is not None
        assert spec.rationale is not None