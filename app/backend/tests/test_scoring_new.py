import pytest
import json
import tempfile
from pathlib import Path
from app.services import scoring


class TestLoadRules:
    def test_load_rules_returns_dict(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"checks": [], "security_weights": {}}, f)
            f.flush()
            result = scoring.load_rules(Path(f.name))
            assert isinstance(result, dict)
            assert "checks" in result

    def test_load_rules_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json")
            f.flush()
            with pytest.raises(json.JSONDecodeError):
                scoring.load_rules(Path(f.name))


class TestRemediationGuides:
    def test_remediation_guides_not_empty(self):
        assert len(scoring.REMEDIATION_GUIDES) > 0

    def test_uid0_users_has_steps_and_verify(self):
        guide = scoring.REMEDIATION_GUIDES["sec_uid0_users"]
        assert "steps" in guide
        assert "verify" in guide

    def test_sudo_nopasswd_exists(self):
        assert "sec_sudo_nopasswd" in scoring.REMEDIATION_GUIDES

    def test_ssh_root_login_exists(self):
        assert "sec_ssh_root_login" in scoring.REMEDIATION_GUIDES

    def test_many_public_ports_exists(self):
        assert "sec_many_public_ports" in scoring.REMEDIATION_GUIDES


class TestUfwState:
    def test_active_status(self):
        output = "Status: active"
        result = scoring._ufw_state(output)
        assert result is not None

    def test_inactive_status(self):
        output = "Status: inactive"
        result = scoring._ufw_state(output)
        assert result is None

    def test_empty_returns_none(self):
        assert scoring._ufw_state("") is None


class TestDockerChecks:
    def test_empty_commands_no_error(self):
        snapshot = {"files": {}, "commands": {}, "metadata": {}}
        rules = {}
        findings = []
        scoring._docker_checks(snapshot, snapshot["commands"], findings, rules)
        assert isinstance(findings, list)

    def test_with_docker_ps(self):
        snapshot = {
            "files": {"passwd": {"content": "root:x:0:0:root:/root:/bin/bash"}},
            "commands": {"docker ps": {"stdout": "nginx"}},
            "metadata": {},
        }
        rules = {"critical_services": ["docker"]}
        findings = []
        scoring._docker_checks(snapshot, snapshot["commands"], findings, rules)
        assert isinstance(findings, list)