from app.services._checks import (
    _check_docker_socket,
    _check_docker_containers,
    _check_established_connections,
    _docker_finding,
)


DEFAULT_RULES = {
    "security_weights": {"CRIT": 40, "HIGH": 20, "MED": 10, "LOW": 5, "INFO": 0},
    "performance_thresholds": {},
    "critical_services": [],
    "score_weights": {"security": 0.6, "performance": 0.4},
}


class TestCheckDockerSocket:
    def test_no_socket(self):
        findings = _check_docker_socket({}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_socket_without_world_writable(self):
        commands = {"docker_socket": {"stdout": "srw-r--r-- 1 root docker 0 /var/run/docker.sock"}}
        findings = _check_docker_socket(commands, DEFAULT_RULES)
        assert len(findings) == 0

    def test_socket_world_writable(self):
        commands = {"docker_socket": {"stdout": "srw-rw-rw- 1 root docker 0 /var/run/docker.sock"}}
        findings = _check_docker_socket(commands, DEFAULT_RULES)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "sec_docker_socket_world_writable"


class TestCheckDockerContainers:
    def test_empty_ps(self):
        findings = _check_docker_containers({}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_whitespace_ps(self):
        findings = _check_docker_containers({"docker_ps": {"stdout": "   \n"}}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_invalid_json_ps(self):
        findings = _check_docker_containers({"docker_ps": {"stdout": "not json\n"}}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_privileged_container(self):
        commands = {"docker_ps": {"stdout": '{"Names":["test"],"ID":"abc123","Privileged":"true"}\n'}}
        findings = _check_docker_containers(commands, DEFAULT_RULES)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "sec_docker_privileged_container"

    def test_container_exposed_ports(self):
        commands = {"docker_ps": {"stdout": '{"Names":["test"],"Ports":"80,443,8080"}\n'}}
        findings = _check_docker_containers(commands, DEFAULT_RULES)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "sec_docker_exposed_ports"

    def test_multiple_findings(self):
        commands = {"docker_ps": {"stdout": '{"Names":["c1"],"Privileged":"true","Ports":"80,443"}\n'}}
        findings = _check_docker_containers(commands, DEFAULT_RULES)
        assert len(findings) == 2


class TestCheckEstablishedConnections:
    def test_no_connections(self):
        findings = _check_established_connections({}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_few_connections(self):
        lines = "\n".join(["ESTAB" for _ in range(50)])
        findings = _check_established_connections({"established_connections": {"stdout": lines}}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_many_connections(self):
        lines = "\n".join(["ESTAB 127.0.0.1:443 127.0.0.1:54321" for _ in range(150)])
        findings = _check_established_connections({"established_connections": {"stdout": lines}}, DEFAULT_RULES)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "sec_many_established_connections"


class TestDockerFinding:
    def test_socket_finding(self):
        result = _docker_finding("sec_docker_socket_world_writable", "line evidence", DEFAULT_RULES)
        assert result["check_id"] == "sec_docker_socket_world_writable"
        assert result["severity"] == "CRIT"
        assert result["weight"] == 40

    def test_privileged_finding(self):
        result = _docker_finding("sec_docker_privileged_container", "container evidence", DEFAULT_RULES)
        assert result["severity"] == "CRIT"
        assert result["weight"] == 40

    def test_exposed_ports_finding(self):
        result = _docker_finding("sec_docker_exposed_ports", "ports evidence", DEFAULT_RULES)
        assert result["severity"] == "MED"
        assert result["weight"] == 10

    def test_unknown_returns_empty_title(self):
        result = _docker_finding("sec_unknown", "evidence", DEFAULT_RULES)
        assert result["title"] == ""
        assert result["severity"] == "CRIT"