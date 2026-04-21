import pytest
from app.services._firewall import _nft_ruleset_state, _ufw_state, _iptables_state
from app.services._models import Finding


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


class TestFindingDataclass:
    def test_to_dict(self):
        finding = Finding(
            check_id="test_check",
            domain="security",
            category="test",
            severity="HIGH",
            title="Test Finding",
            rationale="Test rationale",
            evidence="test evidence",
            recommendation="test recommendation",
            reference="test reference",
            weight=10.0,
        )
        result = finding.to_dict()
        assert result["check_id"] == "test_check"
        assert result["severity"] == "HIGH"
        assert result["weight"] == 10.0

    def test_default_weight(self):
        finding = Finding(
            check_id="test",
            domain="security",
            category="test",
            severity="HIGH",
            title="T",
            rationale="R",
            evidence="E",
            recommendation="R",
            reference="R",
        )
        assert finding.weight == 0.0
        assert finding.extra_data == {}