import pytest
from unittest.mock import patch, MagicMock


def test_evaluate_firewall_state_no_commands():
    from app.services._firewall import _evaluate_firewall_state

    commands = {
        "firewall_nft": {"available": False},
        "firewall_ufw": {"available": False},
        "firewall_iptables": {"available": False},
    }
    result = _evaluate_firewall_state(commands)
    assert result["status"] == "not_confirmed"


def test_evaluate_firewall_state_with_timeout():
    from app.services._firewall import _evaluate_firewall_state

    commands = {
        "firewall_nft": {"available": True, "timed_out": True},
        "firewall_ufw": {"available": False},
        "firewall_iptables": {"available": False},
    }
    result = _evaluate_firewall_state(commands)
    assert result["status"] == "not_confirmed"
    assert "timeout" in result["evidence"]


def test_evaluate_firewall_state_with_stderr():
    from app.services._firewall import _evaluate_firewall_state

    commands = {
        "firewall_nft": {"available": True, "stderr": "error line 1\nerror line 2\n"},
        "firewall_ufw": {"available": False},
        "firewall_iptables": {"available": False},
    }
    result = _evaluate_firewall_state(commands)
    assert "stderr" in result["evidence"]


def test_evaluate_firewall_state_with_nft_restrictive():
    from app.services._firewall import _evaluate_firewall_state

    commands = {
        "firewall_nft": {"available": True, "stdout": "table inet filter { hook input priority 0; policy drop; }\n"},
        "firewall_ufw": {"available": False},
        "firewall_iptables": {"available": False},
    }
    result = _evaluate_firewall_state(commands)
    assert result["status"] == "restrictive"


def test_evaluate_firewall_state_with_ufw_active():
    from app.services._firewall import _evaluate_firewall_state

    commands = {
        "firewall_nft": {"available": False},
        "firewall_ufw": {"available": True, "stdout": "Status: active\nDefault: deny (incoming)\n"},
        "firewall_iptables": {"available": False},
    }
    result = _evaluate_firewall_state(commands)
    assert result["status"] == "restrictive"


def test_evaluate_firewall_state_with_iptables_rules():
    from app.services._firewall import _evaluate_firewall_state

    commands = {
        "firewall_nft": {"available": False},
        "firewall_ufw": {"available": False},
        "firewall_iptables": {"available": True, "stdout": "-N CUSTOM\n-A INPUT -j DROP\n-P FORWARD DROP\n"},
    }
    result = _evaluate_firewall_state(commands)
    assert result["status"] == "restrictive"


def test_nft_ruleset_state_with_hooks():
    from app.services._firewall import _nft_ruleset_state

    output = "table inet filter { hook input priority 0; policy accept; }"
    result = _nft_ruleset_state(output)
    assert result is not None


def test_nft_ruleset_state_empty():
    from app.services._firewall import _nft_ruleset_state

    result = _nft_ruleset_state("")
    assert result is None


def test_ufw_state_active():
    from app.services._firewall import _ufw_state

    output = "Status: active\nDefault: deny (incoming)\n"
    result = _ufw_state(output)
    assert result is not None
    assert result["status"] == "restrictive"


def test_ufw_state_inactive():
    from app.services._firewall import _ufw_state

    result = _ufw_state("Status: inactive")
    assert result is None


def test_iptables_state_with_policies():
    from app.services._firewall import _iptables_state

    output = "-P INPUT DROP\n-P FORWARD DROP\n"
    result = _iptables_state(output)
    assert result is not None
    assert result["status"] == "restrictive"


def test_iptables_state_empty():
    from app.services._firewall import _iptables_state

    result = _iptables_state("")
    assert result is None


def test_iptables_state_no_rules():
    from app.services._firewall import _iptables_state

    result = _iptables_state("some text without rules")
    assert result is None