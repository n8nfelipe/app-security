import pytest
from app.services.scoring import _nft_ruleset_state, _ufw_state, _iptables_state, _build_finding_metadata


class TestNftRulesetState:
    def test_empty_output_returns_none(self):
        assert _nft_ruleset_state("") is None

    def test_whitespace_only_returns_none(self):
        assert _nft_ruleset_state("   \n\t  ") is None

    def test_restrictive_nft(self):
        output = "table inet filter {\n  hook input priority 0\n  chain output { accept }\n  policy drop\n}"
        result = _nft_ruleset_state(output)
        assert result["status"] == "restrictive"

    def test_permissive_nft(self):
        output = "table inet filter {\n  hook input priority 0\n  chain input { accept }\n}"
        result = _nft_ruleset_state(output)
        assert result["status"] == "permissive"


class TestUfwState:
    def test_inactive_returns_none(self):
        assert _ufw_state("Status: inactive") is None

    def test_active_restrictive(self):
        output = "Status: active\nDefault: deny (incoming)"
        result = _ufw_state(output)
        assert result["status"] == "restrictive"

    def test_active_permissive(self):
        output = "Status: active\nDefault: allow (incoming)"
        result = _ufw_state(output)
        assert result["status"] == "permissive"


class TestIptablesState:
    def test_empty_returns_none(self):
        assert _iptables_state("") is None

    def test_whitespace_only_returns_none(self):
        assert _iptables_state("   \n  ") is None

    def test_with_drop_policy(self):
        output = "-P INPUT DROP\n-P OUTPUT ACCEPT"
        result = _iptables_state(output)
        assert result["status"] == "restrictive"

    def test_with_custom_chain(self):
        output = "-N CUSTOM_CHAIN\n-A CUSTOM_CHAIN -j ACCEPT"
        result = _iptables_state(output)
        assert result["status"] == "permissive"


class TestBuildFindingMetadata:
    def test_low_severity_returns_empty(self):
        result = _build_finding_metadata("check_1", "LOW", "rec", "ref")
        assert result == {}

    def test_medium_severity_returns_empty(self):
        result = _build_finding_metadata("check_1", "MED", "rec", "ref")
        assert result == {}

    def test_high_severity_has_remediation(self):
        result = _build_finding_metadata("check_1", "HIGH", "rec", "ref")
        assert "remediation" in result
        assert "steps" in result["remediation"]
        assert "verify" in result["remediation"]

    def test_known_check_uses_custom_guide(self):
        result = _build_finding_metadata("sec_uid0_users", "HIGH", "rec", "ref")
        assert "remediation" in result
        assert "Liste as contas" in result["remediation"]["steps"][0]