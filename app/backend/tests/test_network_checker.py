from app.services._network import (
    CheckManyPublicPorts,
    CheckWorldWritableEtc,
    CheckFirewallState,
)


DEFAULT_RULES = {
    "security_weights": {"CRIT": 40, "HIGH": 20, "MED": 10, "LOW": 5, "INFO": 0},
    "performance_thresholds": {},
    "critical_services": [],
    "score_weights": {"security": 0.6, "performance": 0.4},
}


class TestCheckManyPublicPorts:
    def test_no_public_ports(self):
        commands = {"listening_ports": {"stdout": ""}}
        checker = CheckManyPublicPorts()
        findings = checker.check({}, commands, DEFAULT_RULES)
        assert len(findings) == 0

    def test_internal_only(self):
        commands = {"listening_ports": {"stdout": "tcp LISTEN 127.0.0.1:8080 0.0.0.0:*"}}
        checker = CheckManyPublicPorts()
        findings = checker.check({}, commands, DEFAULT_RULES)
        assert len(findings) == 0


class TestCheckWorldWritableEtc:
    def test_no_writable_files(self):
        snapshot = {"directories": {"etc": {"entries": []}}}
        checker = CheckWorldWritableEtc()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 0


class TestCheckFirewallState:
    def test_firewall_not_confirmed(self):
        commands = {
            "firewall_nft": {"stdout": "", "available": False},
            "firewall_ufw": {"stdout": "", "available": False},
            "firewall_iptables": {"stdout": "", "available": False},
        }
        checker = CheckFirewallState()
        findings = checker.check({}, commands, DEFAULT_RULES)
        assert len(findings) == 1
        assert findings[0].check_id == "sec_firewall_unclear"

    def test_firewall_active(self):
        commands = {
            "firewall_nft": {"stdout": "table inet filter { chain input { hook input priority 0; } policy drop; }"},
            "firewall_ufw": {"stdout": ""},
            "firewall_iptables": {"stdout": ""},
        }
        checker = CheckFirewallState()
        findings = checker.check({}, commands, DEFAULT_RULES)
        assert len(findings) == 0