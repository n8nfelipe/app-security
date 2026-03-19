from app.services.scoring import _evaluate_firewall_state


def test_firewall_state_detects_restrictive_ufw():
    commands = {
        "firewall_nft": {"stdout": "", "available": False},
        "firewall_ufw": {"stdout": "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n", "available": True},
        "firewall_iptables": {"stdout": "", "available": False},
    }
    state = _evaluate_firewall_state(commands)
    assert state["status"] == "restrictive"


def test_firewall_state_detects_permissive_iptables():
    commands = {
        "firewall_nft": {"stdout": "", "available": False},
        "firewall_ufw": {"stdout": "", "available": False},
        "firewall_iptables": {"stdout": "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n", "available": True},
    }
    state = _evaluate_firewall_state(commands)
    assert state["status"] == "permissive"


def test_firewall_state_detects_not_confirmed():
    commands = {
        "firewall_nft": {"stdout": "", "available": False, "reason": "binary_not_found"},
        "firewall_ufw": {"stdout": "", "available": False, "reason": "binary_not_found"},
        "firewall_iptables": {"stdout": "", "available": False, "reason": "binary_not_found"},
    }
    state = _evaluate_firewall_state(commands)
    assert state["status"] == "not_confirmed"
