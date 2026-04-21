from app.services._firewall import (
    _evaluate_firewall_state,
    _nft_ruleset_state,
    _ufw_state,
    _iptables_state,
)


class TestEvaluateFirewallState:
    def test_nft_detected(self):
        commands = {
            "firewall_nft": {"stdout": "table inet filter { chain input { hook input priority 0; } policy drop; }"},
            "firewall_ufw": {"stdout": ""},
            "firewall_iptables": {"stdout": ""},
        }
        result = _evaluate_firewall_state(commands)
        assert result["status"] == "restrictive"

    def test_ufw_detected(self):
        commands = {
            "firewall_nft": {"stdout": ""},
            "firewall_ufw": {"stdout": "Status: active\nDefault: deny (incoming)\n"},
            "firewall_iptables": {"stdout": ""},
        }
        result = _evaluate_firewall_state(commands)
        assert result["status"] == "restrictive"

    def test_iptables_detected(self):
        commands = {
            "firewall_nft": {"stdout": ""},
            "firewall_ufw": {"stdout": ""},
            "firewall_iptables": {"stdout": "-P INPUT DROP\n-A INPUT -j ACCEPT\n"},
        }
        result = _evaluate_firewall_state(commands)
        assert result["status"] == "restrictive"

    def test_none_detected_returns_not_confirmed(self):
        commands = {
            "firewall_nft": {"stdout": "", "available": False},
            "firewall_ufw": {"stdout": ""},
            "firewall_iptables": {"stdout": ""},
        }
        result = _evaluate_firewall_state(commands)
        assert result["status"] == "not_confirmed"

    def test_nft_timed_out(self):
        commands = {
            "firewall_nft": {"stdout": "", "timed_out": True},
            "firewall_ufw": {"stdout": ""},
            "firewall_iptables": {"stdout": ""},
        }
        result = _evaluate_firewall_state(commands)
        assert result["status"] == "not_confirmed"

    def test_nft_stderr(self):
        commands = {
            "firewall_nft": {"stdout": "", "stderr": "command not found\nline 2"},
            "firewall_ufw": {"stdout": ""},
            "firewall_iptables": {"stdout": ""},
        }
        result = _evaluate_firewall_state(commands)
        assert result["status"] == "not_confirmed"


class TestNftRulesetState:
    def test_empty_output(self):
        assert _nft_ruleset_state("") is None

    def test_whitespace_only(self):
        assert _nft_ruleset_state("   \n\t  ") is None

    def test_restrictive_with_policy_drop(self):
        output = "table inet filter { chain input { hook input priority 0; } policy drop; }"
        result = _nft_ruleset_state(output)
        assert result["status"] == "restrictive"

    def test_restrictive_with_drop_action(self):
        output = "table ip filter { chain input { hook input priority 0; } action drop; }"
        result = _nft_ruleset_state(output)
        assert result["status"] == "restrictive"

    def test_permissive_accept_only(self):
        output = "table inet filter { chain input { hook input priority 0; } policy accept; }"
        result = _nft_ruleset_state(output)
        assert result["status"] == "permissive"


class TestUfwState:
    def test_inactive(self):
        assert _ufw_state("Status: inactive") is None

    def test_active_restrictive(self):
        output = "Status: active\nDefault: deny (incoming)\n"
        result = _ufw_state(output)
        assert result["status"] == "restrictive"

    def test_active_permissive(self):
        output = "Status: active\nDefault: allow (incoming)\n"
        result = _ufw_state(output)
        assert result["status"] == "permissive"


class TestIptablesState:
    def test_empty(self):
        assert _iptables_state("") is None

    def test_whitespace_only(self):
        assert _iptables_state("   \n  ") is None

    def test_drop_policy(self):
        output = "-P INPUT DROP\n-P OUTPUT ACCEPT\n"
        result = _iptables_state(output)
        assert result["status"] == "restrictive"

    def test_permissive_with_accept_rules(self):
        output = "-N CUSTOM\n-A CUSTOM -j ACCEPT\n"
        result = _iptables_state(output)
        assert result["status"] == "permissive"

    def test_reject_drop_in_rules(self):
        output = "-A INPUT -j DROP\n-A OUTPUT -j REJECT\n"
        result = _iptables_state(output)
        assert result["status"] == "restrictive"