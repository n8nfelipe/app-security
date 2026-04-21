import re
from app.services import parser
from app.services._models import Checker, Finding


class CheckUid0Users(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        passwd = parser.parse_passwd(snapshot["files"]["passwd"]["content"])
        extra_uid0 = [u for u in passwd if u["uid"] == 0 and u["username"] != "root"]
        if extra_uid0:
            findings.append(Finding(
                check_id="sec_uid0_users",
                domain="security",
                category="identity",
                severity="CRIT",
                title="Conta adicional com UID 0 encontrada",
                rationale="Usuarios com UID 0 ampliam superficie de privilegio.",
                evidence=", ".join(u["username"] for u in extra_uid0),
                recommendation="Revisar contas administrativas e remover UID 0 desnecessario.",
                reference="CIS Debian 5.4",
                weight=rules["security_weights"]["CRIT"],
            ))
        return findings


class CheckManyShellUsers(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        passwd = parser.parse_passwd(snapshot["files"]["passwd"]["content"])
        human_users = [
            u for u in passwd
            if u["uid"] >= 1000 and not u["shell"].endswith("nologin")
        ]
        if len(human_users) > 10:
            findings.append(Finding(
                check_id="sec_many_shell_users",
                domain="security",
                category="identity",
                severity="MED",
                title="Numero elevado de usuarios com shell interativo",
                rationale="Mais usuarios interativos aumentam a superficie de ataque.",
                evidence=f"{len(human_users)} usuarios com shell ativo",
                recommendation="Validar contas ativas e remover shells desnecessarios.",
                reference="Principio de menor privilegio",
                weight=rules["security_weights"]["MED"],
            ))
        return findings


class CheckSudoNopasswd(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        sudoers_content = snapshot["files"]["sudoers"]["content"]
        sudoers_d = snapshot.get("directories", {}).get("sudoers_d", {}).get("entries", [])
        merged = "\n".join([sudoers_content, *[e["content"] for e in sudoers_d]])
        if "NOPASSWD" in merged:
            findings.append(Finding(
                check_id="sec_sudo_nopasswd",
                domain="security",
                category="privilege",
                severity="HIGH",
                title="Entrada NOPASSWD detectada em sudoers",
                rationale="Bypass de senha reduz friccao de abuso pos-exploracao.",
                evidence="NOPASSWD presente em /etc/sudoers",
                recommendation="Restringir NOPASSWD apenas a automacao estritamente controlada.",
                reference="CIS Debian 5.2",
                weight=rules["security_weights"]["HIGH"],
            ))
        return findings


class CheckSshRootLogin(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        sshd_config = snapshot["files"]["sshd_config"]["content"]
        if not sshd_config:
            return findings
        pattern = re.compile(r"^\s*PermitRootLogin\s+(?!no\b)", re.MULTILINE | re.IGNORECASE)
        match = pattern.search(sshd_config)
        if match:
            findings.append(Finding(
                check_id="sec_ssh_root_login",
                domain="security",
                category="ssh",
                severity="HIGH",
                title="SSH permite login direto de root",
                rationale="Login direto de root reduz rastreabilidade e amplia impacto.",
                evidence=match.group(0).strip(),
                recommendation="Definir PermitRootLogin no e usar sudo controlado.",
                reference="CIS Debian 5.1",
                weight=rules["security_weights"]["HIGH"],
            ))
        return findings


class CheckSshPasswordAuth(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        sshd_config = snapshot["files"]["sshd_config"]["content"]
        if not sshd_config:
            return findings
        pattern = re.compile(r"^\s*PasswordAuthentication\s+yes\b", re.MULTILINE | re.IGNORECASE)
        if pattern.search(sshd_config):
            findings.append(Finding(
                check_id="sec_ssh_password_auth",
                domain="security",
                category="ssh",
                severity="MED",
                title="SSH aceita autenticacao por senha",
                rationale="Credenciais por senha sao mais suscetiveis a brute force e phishing.",
                evidence="PasswordAuthentication yes",
                recommendation="Preferir chaves, MFA e restricoes por rede.",
                reference="OpenSSH hardening",
                weight=rules["security_weights"]["MED"],
            ))
        return findings