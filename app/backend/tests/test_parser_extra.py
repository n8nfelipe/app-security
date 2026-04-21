from app.services.parser import (
    parse_passwd,
    parse_group,
    parse_ss_listening,
    parse_ps_table,
    parse_df,
    parse_systemd_units,
    parse_systemd_blame,
    parse_docker_ps,
    parse_docker_info,
    count_lines,
    any_match,
)


class TestParsePasswd:
    def test_comment_line_ignored(self):
        content = "# This is a comment\nroot:x:0:0:root:/root:/bin/bash\n"
        result = parse_passwd(content)
        assert len(result) == 1

    def test_line_with_fewer_parts_ignored(self):
        content = "short:line\nroot:x:0:0:root:/root:/bin/bash\n"
        result = parse_passwd(content)
        assert len(result) == 1

    def test_uid_and_gid_parsed(self):
        content = "user:x:1001:1001:User:/home/user:/bin/bash\n"
        result = parse_passwd(content)
        assert result[0]["uid"] == 1001
        assert result[0]["gid"] == 1001


class TestParseGroup:
    def test_empty_members_parsed(self):
        content = "group:x:1000:\n"
        result = parse_group(content)
        assert result[0]["members"] == []

    def test_multiple_members_parsed(self):
        content = "sudo:x:27:user1,user2,user3\n"
        result = parse_group(content)
        assert len(result[0]["members"]) == 3


class TestParseSsListening:
    def test_header_line_skipped(self):
        content = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
        result = parse_ss_listening(content)
        assert result == []


class TestParsePsTable:
    def test_process_count_respects_limit(self):
        content = "  1  0 init  0.0  0.0 S\n  2  0 bash  0.0  0.0 S\n"
        result = parse_ps_table(content, limit=1)
        assert len(result) == 1

    def test_invalid_line_skipped(self):
        content = "short line\n  1  0 bash  0.0  0.0 S\n"
        result = parse_ps_table(content)
        assert len(result) == 1


class TestParseDf:
    def test_filesystem_use_percent_parsed(self):
        content = "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 100G 50G 50G 75% /\n"
        result = parse_df(content)
        assert result[0]["use_percent"] == 75


class TestParseSystemdUnits:
    def test_partial_line_ignored(self):
        content = "short\nssh.service enabled\n"
        result = parse_systemd_units(content)
        assert len(result) == 1


class TestParseSystemdBlame:
    def test_limit_respected(self):
        content = "1.200s unit1\n0.800s unit2\n0.500s unit3\n"
        result = parse_systemd_blame(content, limit=2)
        assert len(result) == 2


class TestParseDockerPs:
    def test_invalid_json_skipped(self):
        content = '{"Id":"abc123"}\nnot valid json\n{"Id":"def456"}\n'
        result = parse_docker_ps(content)
        assert len(result) == 2

    def test_multiple_containers(self):
        content = '{"Id":"abc","Names":["c1"]}\n{"Id":"def","Names":["c2"]}\n'
        result = parse_docker_ps(content)
        assert len(result) == 2


class TestParseDockerInfo:
    def test_invalid_json_returns_empty(self):
        result = parse_docker_info("not json")
        assert result == {}

    def test_valid_json_parsed(self):
        content = '{"ServerVersion": "24.0", "Os": "linux"}'
        result = parse_docker_info(content)
        assert result["ServerVersion"] == "24.0"


class TestCountLines:
    def test_blank_lines_not_counted(self):
        content = "line1\n\nline2\n   \nline3\n"
        result = count_lines(content)
        assert result == 3


class TestAnyMatch:
    def test_no_match_returns_false(self):
        result = any_match(["foo", "bar"], "xyz")
        assert result is False

    def test_match_returns_true(self):
        result = any_match(["foo", "bar", "baz"], "bar")
        assert result is True