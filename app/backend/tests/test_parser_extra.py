import pytest
from unittest.mock import patch, MagicMock
import json


def test_parse_key_value_file_with_comments():
    from app.services.parser import parse_key_value_file

    content = """
    # Comment line
    KEY1=value1
    KEY2="value with spaces"
    # Another comment
    KEY3=value3
    """
    result = parse_key_value_file(content)
    assert result["KEY1"] == "value1"
    assert result["KEY2"] == "value with spaces"
    assert result["KEY3"] == "value3"


def test_parse_key_value_file_empty():
    from app.services.parser import parse_key_value_file

    result = parse_key_value_file("")
    assert result == {}


def test_parse_key_value_file_with_multiple_equals():
    from app.services.parser import parse_key_value_file

    content = 'KEY=value=extra'
    result = parse_key_value_file(content)
    assert result["KEY"] == "value=extra"


def test_parse_passwd_with_uid_gid():
    from app.services.parser import parse_passwd

    content = "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:User:/home/user:/bin/bash"
    result = parse_passwd(content)
    assert len(result) == 2
    assert result[0]["uid"] == 0
    assert result[0]["gid"] == 0
    assert result[1]["uid"] == 1000


def test_parse_passwd_with_incomplete_lines():
    from app.services.parser import parse_passwd

    content = "root:x:0:0:root:/root:/bin/bash\nincomplete"
    result = parse_passwd(content)
    assert len(result) == 1


def test_parse_group():
    from app.services.parser import parse_group

    content = "sudo:x:27:user1,user2\nwheel:x:10:admin"
    result = parse_group(content)
    assert len(result) == 2
    assert result[0]["name"] == "sudo"
    assert result[0]["gid"] == 27
    assert "user1" in result[0]["members"]


def test_parse_group_empty_members():
    from app.services.parser import parse_group

    content = "nogroup:x:65534:"
    result = parse_group(content)
    assert result[0]["members"] == []


def test_parse_ps_table_with_cpu_mem_errors():
    from app.services.parser import parse_ps_table

    content = """PID  PPID  COMMAND  %CPU  %MEM  STATE
1  0  init  abc  def  S
2  1  bash  10.5  50  R
3  0  test  20.3  R"""
    result = parse_ps_table(content)
    assert result[0]["cpu_percent"] == 0.0
    assert result[0]["memory_percent"] == 0.0
    assert result[1]["cpu_percent"] == 10.5


def test_parse_df_with_percent_sign():
    from app.services.parser import parse_df

    content = """Filesystem  Size  Used  Avail  Use%  Mounted on
/dev/sda1  50G  20G  30G  40%  /
/dev/sdb1  100G  90G  10G  90%  /data"""
    result = parse_df(content)
    assert result[0]["use_percent"] == 40
    assert result[1]["use_percent"] == 90


def test_parse_df_with_incomplete_lines():
    from app.services.parser import parse_df

    content = """Filesystem  Size  Used
/dev/sda1  50G  20G"""
    result = parse_df(content)
    assert len(result) == 0


def test_parse_systemd_units():
    from app.services.parser import parse_systemd_units

    content = "nginx.service  active\nsshd.service  inactive"
    result = parse_systemd_units(content)
    assert len(result) == 2
    assert result[0]["unit"] == "nginx.service"
    assert result[0]["state"] == "active"


def test_parse_systemd_blame_with_limit():
    from app.services.parser import parse_systemd_blame

    content = """5min  nginx.service
10min  postgresql.service
15min  redis.service"""
    result = parse_systemd_blame(content, limit=2)
    assert len(result) == 2
    assert result[0]["duration"] == "5min"


def test_parse_systemd_blame_with_incomplete_lines():
    from app.services.parser import parse_systemd_blame

    content = """5min  nginx.service
incomplete
10min"""
    result = parse_systemd_blame(content, limit=3)
    assert len(result) == 1


def test_count_lines():
    from app.services.parser import count_lines

    content = "line1\nline2\n\nline3"
    assert count_lines(content) == 3


def test_any_match():
    from app.services.parser import any_match

    values = ["ssh", "http", "ftp"]
    assert any_match(values, "ssh") is True
    assert any_match(values, "mysql") is False


def test_parse_docker_ps_with_json_lines():
    from app.services.parser import parse_docker_ps
    import json

    content = json.dumps({"id": "abc123", "image": "nginx"})
    result = parse_docker_ps(content)
    assert len(result) == 1
    assert result[0]["id"] == "abc123"


def test_parse_docker_ps_with_invalid_json():
    from app.services.parser import parse_docker_ps

    content = "invalid json line\nnot valid\n{}"
    result = parse_docker_ps(content)
    assert len(result) == 1


def test_parse_docker_ps_with_mixed_lines():
    from app.services.parser import parse_docker_ps
    import json

    content = '{"id": "1"}\ninvalid\n{"id": "2"}'
    result = parse_docker_ps(content)
    assert len(result) == 2


def test_parse_docker_info():
    from app.services.parser import parse_docker_info
    import json

    content = json.dumps({"Containers": 5, "Images": 10})
    result = parse_docker_info(content)
    assert result["Containers"] == 5


def test_parse_docker_info_with_invalid_json():
    from app.services.parser import parse_docker_info

    result = parse_docker_info("invalid")
    assert result == {}