from app.services import parser
from app.services._models import Checker, Finding


class CheckManyPublicPorts(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        stdout = commands.get("listening_ports", {}).get("stdout", "")
        sockets = parser.parse_ss_listening(stdout)
        public_sockets = [
            s for s in sockets
            if ":0.0.0.0:" in s["local_address"] or "[::]:" in s["local_address"]
        ]
        if len(public_sockets) > 5:
            findings.append(Finding(
                check_id="sec_many_public_ports",
                domain="security",
                category="network",
                severity="HIGH",
                title="Muitas portas escutando em todas interfaces",
                rationale="Exposicao publica ampla aumenta superficie de ataque.",
                evidence=f"{len(public_sockets)} portas publicas",
                recommendation="Restringir bind a interfaces internas.",
                reference="CIS Debian 7.2",
                weight=rules["security_weights"]["HIGH"],
            ))
        return findings


class CheckWorldWritableEtc(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        etc_files = snapshot.get("directories", {}).get("etc", {}).get("entries", [])
        writable = [f for f in etc_files if f.get("perms", "").endswith("w")]
        if writable:
            findings.append(Finding(
                check_id="sec_world_writable_etc",
                domain="security",
                category="filesystem",
                severity="HIGH",
                title="Arquivos world-writable em /etc",
                rationale="Qualquer usuario pode modificar configuracoes criticas.",
                evidence=f"{len(writable)} arquivos com permissoes inseguras",
                recommendation="Corrigir permissoes com chmod e investigar origem.",
                reference="CIS Debian 9.1",
                weight=rules["security_weights"]["HIGH"],
            ))
        return findings


class CheckFirewallState(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        from app.services._firewall import _evaluate_firewall_state
        findings: list[Finding] = []
        state = _evaluate_firewall_state(commands)
        if state.get("status") == "not_confirmed":
            findings.append(Finding(
                check_id="sec_firewall_unclear",
                domain="security",
                category="network",
                severity="MED",
                title="Firewall nao detectado ou nao confirmado",
                rationale="Ausencia de firewall controlado amplia superficie de ataque.",
                evidence=state.get("evidence", ""),
                recommendation="Configurar firewall ativo com nftables, ufw ou iptables.",
                reference="CIS Debian 8.1",
                weight=rules["security_weights"]["MED"],
            ))
        return findings