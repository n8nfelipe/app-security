import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from app.services import parser


def test_parse_passwd_empty():
    result = parser.parse_passwd("")
    assert result == []


def test_parse_passwd_valid():
    content = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    result = parser.parse_passwd(content)
    assert len(result) == 2
    assert result[0]["username"] == "root"
    assert result[0]["uid"] == 0


def test_parse_group_empty():
    result = parser.parse_group("")
    assert result == []


def test_parse_group_valid():
    content = "root:x:0:\nsudo:x:27:user1,user2\n"
    result = parser.parse_group(content)
    assert len(result) == 2


def test_parse_key_value_file_empty():
    result = parser.parse_key_value_file("")
    assert result == {}


def test_parse_key_value_file_valid():
    content = 'NAME="Ubuntu"\nVERSION="22.04"\n'
    result = parser.parse_key_value_file(content)
    assert result["NAME"] == "Ubuntu"
    assert result["VERSION"] == "22.04"


def test_parse_systemd_units_empty():
    result = parser.parse_systemd_units("")
    assert result == []


def test_parse_systemd_units_valid():
    content = "ssh.service enabled\nsnapd.service enabled\n"
    result = parser.parse_systemd_units(content)
    assert len(result) == 2


def test_parse_ss_listening_empty():
    result = parser.parse_ss_listening("")
    assert result == []


def test_parse_ss_listening_valid():
    content = "LISTEN 0 128 *:22 *:*\n"
    result = parser.parse_ss_listening(content)
    assert isinstance(result, list)


def test_parse_df_empty():
    result = parser.parse_df("")
    assert result == []


def test_parse_df_valid():
    content = "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 100G 50G 50G 50% /\n"
    result = parser.parse_df(content)
    assert len(result) == 1
    assert result[0]["filesystem"] == "/dev/sda1"


def test_parse_docker_ps_empty():
    result = parser.parse_docker_ps("")
    assert result == []


def test_parse_docker_ps_valid():
    content = '{"Id":"abc123","Names":["container1"],"Image":"nginx:latest","State":"running"}\n'
    result = parser.parse_docker_ps(content)
    assert len(result) == 1


def test_parse_docker_info_empty():
    result = parser.parse_docker_info("")
    assert result == {}


def test_parse_docker_info_valid():
    content = '{"ServerVersion": "20.10", "Containers": 5}'
    result = parser.parse_docker_info(content)
    assert result["ServerVersion"] == "20.10"


def test_parse_ps_table_empty():
    result = parser.parse_ps_table("")
    assert result == []


def test_parse_ps_table_valid():
    content = "  123  1 bash  0.0  0.0 S\n  456  2 zsh  0.1  0.2 R\n"
    result = parser.parse_ps_table(content)
    assert len(result) >= 1


def test_count_lines_empty():
    result = parser.count_lines("")
    assert result == 0


def test_count_lines_valid():
    result = parser.count_lines("line1\nline2\nline3\n")
    assert result == 3


def test_any_match_empty():
    result = parser.any_match(["value1", "value2"], "pattern")
    assert result is False


def test_any_match_valid():
    result = parser.any_match(["some text", "pattern text"], "pattern")
    assert result is True


def test_parse_systemd_blame_empty():
    result = parser.parse_systemd_blame("")
    assert result == []


def test_parse_systemd_blame_valid():
    content = "1.200s nginx.service\n0.800s docker.service\n"
    result = parser.parse_systemd_blame(content)
    assert len(result) == 2