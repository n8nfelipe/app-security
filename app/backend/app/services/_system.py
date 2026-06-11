from app.services._models import Checker, Finding

INSECURE_SERVICES = {
    "telnet": "CRIT",
    "telnet.socket": "CRIT",
    "rsh": "CRIT",
    "rlogin": "CRIT",
    "rexec": "CRIT",
    "finger": "MED",
    "tftp": "HIGH",
    "vsftpd": "HIGH",
    "proftpd": "HIGH",
    "rpcbind": "MED",
    "avahi-daemon": "LOW",
    "cups": "LOW",
    "bluetooth": "LOW",
}

RISKY_PORTS = {
    21: ("FTP", "HIGH"),
    23: ("Telnet", "HIGH"),
    25: ("SMTP", "MED"),
    110: ("POP3", "MED"),
    143: ("IMAP", "MED"),
    512: ("rexec", "HIGH"),
    513: ("rlogin", "HIGH"),
    514: ("rsh/syslog", "HIGH"),
    3389: ("RDP", "MED"),
    5900: ("VNC", "HIGH"),
}


class CheckPendingUpdates(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        updates = commands.get("updates_debian", {}).get("stdout", "")
        if not updates.strip() or not updates.startswith("Listing"):
            return findings
        count = sum(1 for line in updates.splitlines() if "upgradable" in line)
        if count > 0:
            findings.append(Finding(
                check_id="sec_pending_updates",
                domain="security",
                category="updates",
                severity="CRIT",
                title=f"{count} pacote(s) com atualizacao pendente",
                rationale="Pacotes desatualizados podem conter vulnerabilidades conhecidas (CVE).",
                evidence=f"{count} pacote(s) upgradavel(is)",
                recommendation="Aplicar atualizacoes com apt upgrade e verificar pacotes de seguranca.",
                reference="CIS Debian 1.6",
                weight=rules["security_weights"]["CRIT"],
            ))
        return findings


class CheckInsecureServices(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        units = commands.get("systemd_units", {}).get("stdout", "")
        if not units:
            return findings
        active_services_raw = commands.get("active_services", {}).get("stdout", "")
        active_services = set()
        for line in active_services_raw.splitlines():
            parts = line.split()
            if parts:
                name = parts[0].strip()
                if name.endswith(".service"):
                    name = name[:-8]
                active_services.add(name)

        for line in units.splitlines():
            parts = line.split()
            if not parts or len(parts) < 2:
                continue
            unit_name = parts[0].strip()
            for svc, severity in INSECURE_SERVICES.items():
                if unit_name.startswith(svc) and parts[1] == "enabled":
                    active = unit_name.rstrip(".service") in active_services
                    title = f"Servico inseguro ativo: {svc}" if active else f"Servico inseguro habilitado: {svc}"
                    findings.append(Finding(
                        check_id=f"sec_insecure_service_{svc.replace('.','_')}",
                        domain="security",
                        category="services",
                        severity=severity,
                        title=title,
                        rationale=f"{svc} e um servico inseguro que deve ser desabilitado.",
                        evidence=f"Unit: {unit_name} ({'running' if active else 'enabled'})",
                        recommendation=f"Desabilitar e parar {svc}: systemctl disable --now {unit_name}",
                        reference="CIS Debian 6.2",
                        weight=rules["security_weights"][severity],
                    ))
        return findings


class CheckRiskyPorts(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        from app.services import parser
        stdout = commands.get("listening_ports", {}).get("stdout", "")
        sockets = parser.parse_ss_listening(stdout)
        for sock in sockets:
            addr = sock.get("local_address", "")
            port_part = addr.rsplit(":", 1)[-1]
            try:
                port = int(port_part)
            except ValueError:
                continue
            if port in RISKY_PORTS:
                name, severity = RISKY_PORTS[port]
                findings.append(Finding(
                    check_id=f"sec_risky_port_{port}",
                    domain="security",
                    category="network",
                    severity=severity,
                    title=f"Porta de risco aberta: {port} ({name})",
                    rationale=f"A porta {port} ({name}) e conhecida como vetor de ataque ou protocolo inseguro.",
                    evidence=f"Porta {port} escutando em {addr}",
                    recommendation=f"Fechar porta {port} ou substituir {name} por alternativa segura.",
                    reference="CIS Debian 7.3",
                    weight=rules["security_weights"][severity],
                ))
        return findings


class CheckSuidSgidBinaries(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        output = snapshot.get("filesystem_checks", {}).get("suid_sgid_usr", {}).get("stdout", "")
        if not output:
            return findings
        count = len([l for l in output.splitlines() if l.strip()])
        threshold = rules.get("suid_sgid_threshold", 30)
        if count > threshold:
            findings.append(Finding(
                check_id="sec_excessive_suid_sgid",
                domain="security",
                category="filesystem",
                severity="MED",
                title=f"Numero elevado de binarios SUID/SGID: {count}",
                rationale="Binarios SUID/SGID permitem escalada de privilegio se mal configurados.",
                evidence=f"{count} binarios SUID/SGID em /usr (threshold: {threshold})",
                recommendation="Revisar binarios SUID/SGID e remover bit de binarios nao essenciais.",
                reference="CIS Debian 9.2",
                weight=rules["security_weights"]["MED"],
            ))
        return findings


class CheckInodeUsage(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        from app.services import parser
        output = commands.get("inode_usage", {}).get("stdout", "")
        if not output:
            return findings
        threshold = rules.get("performance_thresholds", {}).get("inode_high_percent", 80)
        for row in parser.parse_df(output):
            use_percent = row.get("use_percent", 0)
            if use_percent >= threshold:
                findings.append(Finding(
                    check_id="perf_inode_high",
                    domain="performance",
                    category="disk",
                    severity="MED" if use_percent < 95 else "HIGH",
                    title=f"Inodes em {row.get('mountpoint')} com {use_percent}% de uso",
                    rationale="Alto uso de inodes pode impedir criacao de novos arquivos.",
                    evidence=f"{row.get('mountpoint')}: {use_percent}% inodes usados",
                    recommendation="Limpar arquivos pequenos ou expandir filesystem.",
                    reference="Inode usage baseline",
                    weight=rules["security_weights"]["MED"] if use_percent < 95 else rules["security_weights"]["HIGH"],
                ))
        return findings


class CheckKernelSecurityParams(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        output = commands.get("kernel_security", {}).get("stdout", "")
        if not output:
            return findings
        expected = {
            "net.ipv4.ip_forward": ("0", "HIGH", "Encaminhamento de pacotes habilitado - sistema atuando como roteador"),
            "net.ipv4.conf.all.accept_redirects": ("0", "HIGH", "Aceita redirects ICMP - vetor de MITM"),
            "net.ipv4.conf.all.send_redirects": ("0", "MED", "Envia redirects ICMP - revela topologia de rede"),
            "net.ipv4.conf.all.accept_source_route": ("0", "HIGH", "Source routing permite spoofing de IP"),
            "net.ipv4.tcp_syncookies": ("1", "HIGH", "SYN cookies desabilitados - vulneravel a SYN flood"),
            "kernel.randomize_va_space": ("2", "CRIT", "ASLR incompleto - facilita exploracao de buffer overflow"),
            "kernel.dmesg_restrict": ("1", "MED", "dmesg acessivel a usuarios comuns - vaza info do kernel"),
            "fs.suid_dumpable": ("0", "MED", "Core dumps SUID habilitados - vaza dados sensiveis"),
            "net.ipv4.conf.all.rp_filter": ("1", "MED", "Reverse path filter desabilitado - permite IP spoofing"),
            "kernel.core_uses_pid": ("1", "LOW", "Core dumps sem PID no nome"),
        }

        actual_values = {}
        for line in output.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                actual_values[k.strip()] = v.strip()

        for key, (expected_val, severity, rationale) in expected.items():
            actual = actual_values.get(key)
            if actual is not None and actual != expected_val:
                findings.append(Finding(
                    check_id=f"sec_kernel_{key.replace('.', '_')}",
                    domain="security",
                    category="kernel",
                    severity=severity,
                    title=f"Parametro de kernel inseguro: {key} = {actual}",
                    rationale=rationale,
                    evidence=f"{key} = {actual} (esperado: {expected_val})",
                    recommendation=f"Corrigir com: sysctl -w {key}={expected_val}",
                    reference="CIS Debian 10.1",
                    weight=rules["security_weights"][severity],
                ))
        return findings


class CheckAppArmorSELinux(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        aa = commands.get("apparmor_status", {}).get("stdout", "")
        se = commands.get("selinux_status", {}).get("stdout", "")

        if aa and "profiles are loaded" in aa:
            enforce = sum(1 for l in aa.splitlines() if "enforce mode" in l and "profiles are in enforce" not in l)
            complain = sum(1 for l in aa.splitlines() if "complain mode" in l and "profiles are in complain" not in l)
            if complain and complain > 0:
                findings.append(Finding(
                    check_id="sec_apparmor_complain",
                    domain="security",
                    category="mac",
                    severity="MED",
                    title=f"AppArmor: {complain} perfis em modo complain",
                    rationale="Perfis em modo complain apenas registram violacoes, sem bloquear.",
                    evidence=f"{complain} perfil(is) em modo complain",
                    recommendation="Colocar perfis em enforce: aa-enforce /etc/apparmor.d/*",
                    reference="AppArmor hardening",
                    weight=rules["security_weights"]["MED"],
                ))
        elif aa and "no" in aa.lower() and "profiles" not in aa:
            findings.append(Finding(
                check_id="sec_apparmor_inactive",
                domain="security",
                category="mac",
                severity="HIGH",
                title="AppArmor instalado mas inativo",
                rationale="AppArmor sem perfis carregados nao protege o sistema.",
                evidence="aa-status indica nenhum perfil carregado",
                recommendation="Instalar perfis e ativar: systemctl enable --now apparmor",
                reference="AppArmor hardening",
                weight=rules["security_weights"]["HIGH"],
            ))
        elif not aa and not se:
            return findings

        if "Enforcing" in se:
            pass
        elif se.strip() and se.strip() != "Enforcing":
            findings.append(Finding(
                check_id="sec_selinux_not_enforcing",
                domain="security",
                category="mac",
                severity="HIGH",
                title=f"SELinux: {se.strip()} (recomendado: Enforcing)",
                rationale="SELinux sem modo enforcing reduz confinamento de processos.",
                evidence=f"SELinux em modo: {se.strip()}",
                recommendation="Ativar Enforcing: setenforce 1 && sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
                reference="SELinux hardening",
                weight=rules["security_weights"]["HIGH"],
            ))

        if not aa and not se.strip():
            findings.append(Finding(
                check_id="sec_no_mac",
                domain="security",
                category="mac",
                severity="HIGH",
                title="Nenhum MAC detectado (AppArmor/SELinux)",
                rationale="Sem controle de acesso obrigatorio, processo comprometido tem acesso total ao sistema.",
                evidence="AppArmor e SELinux nao encontrados",
                recommendation="Instalar AppArmor: apt install apparmor apparmor-utils apparmor-profiles",
                reference="CIS Debian 11.1",
                weight=rules["security_weights"]["HIGH"],
            ))

        return findings


class CheckServiceStatus(Checker):
    SERVICES = {
        "auditd": ("sec_auditd_inactive", "MED", "Daemon de auditoria (auditd) inativo", "Sem rastreamento de eventos do kernel."),
        "rsyslog": ("sec_rsyslog_inactive", "HIGH", "Syslog (rsyslog) inativo", "Eventos do sistema nao registrados."),
        "fail2ban": ("sec_fail2ban_inactive", "HIGH", "fail2ban inativo", "Sem bloqueio automatico de brute-force."),
    }

    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        for service, (check_id, severity, title, rationale) in self.SERVICES.items():
            svc_key = f"service_{service}"
            result = commands.get(svc_key, {}).get("stdout", "").strip()
            if result == "active":
                continue
            if commands.get(svc_key, {}).get("available", False) is False:
                result_type = "binary_not_found"
            elif not result:
                result_type = "inactive"
            else:
                result_type = result

            findings.append(Finding(
                check_id=check_id,
                domain="security",
                category="audit",
                severity=severity,
                title=title,
                rationale=rationale,
                evidence=f"systemctl is-active {service}: {result_type}",
                recommendation=f"Ativar {service}: systemctl enable --now {service}",
                reference="CIS Debian 11.2",
                weight=rules["security_weights"][severity],
            ))
        return findings


class CheckAvIdsTools(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        output = commands.get("av_tools", {}).get("stdout", "")
        if not output:
            return findings
        missing = []
        expected_tools = {
            "clamscan": "ClamAV (antivirus)",
            "rkhunter": "Rootkit Hunter",
            "chkrootkit": "chkrootkit",
            "aide": "AIDE (integridade)",
            "fail2ban-client": "fail2ban",
        }
        found = set()
        for line in output.splitlines():
            for tool in expected_tools:
                if tool in line and "not found" not in line.lower() and "no " not in line.lower():
                    found.add(tool)
        for tool, name in expected_tools.items():
            if tool not in found:
                missing.append(name)

        if missing:
            findings.append(Finding(
                check_id="sec_missing_av_ids_tools",
                domain="security",
                category="audit",
                severity="MED",
                title="Ferramentas AV/IDS ausentes",
                rationale="Sem ferramentas de deteccao, malware e rootkits podem passar despercebidos.",
                evidence=f"Ausentes: {', '.join(missing)}",
                recommendation="Instalar ferramentas: apt install clamav rkhunter chkrootkit aide fail2ban",
                reference="CIS Debian 11.3",
                weight=rules["security_weights"]["MED"],
            ))
        return findings


class CheckTmpNoexec(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        mounts = snapshot.get("files", {}).get("proc_mounts", {}).get("content", "")
        if not mounts:
            return findings
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "/tmp":
                opts = parts[3]
                missing = []
                if "noexec" not in opts:
                    missing.append("noexec")
                if "nosuid" not in opts:
                    missing.append("nosuid")
                if "nodev" not in opts:
                    missing.append("nodev")
                if missing:
                    findings.append(Finding(
                        check_id="sec_tmp_noexec",
                        domain="security",
                        category="filesystem",
                        severity="MED",
                        title=f"/tmp sem opcoes de seguranca: {', '.join(missing)}",
                        rationale="/tmp sem restricoes permite execucao direta de malware baixado.",
                        evidence=f"Opcoes atuais: {opts}",
                        recommendation=f"Adicionar {', '.join(missing)} ao /tmp em /etc/fstab",
                        reference="CIS Debian 9.3",
                        weight=rules["security_weights"]["MED"],
                    ))
                break
        return findings


class CheckDiskEncryption(Checker):
    def check(self, snapshot: dict, commands: dict, rules: dict) -> list[Finding]:
        findings: list[Finding] = []
        output = commands.get("lsblk", {}).get("stdout", "")
        if not output:
            return findings
        has_crypt = any(line.strip() == "crypt" for line in output.splitlines())
        if not has_crypt:
            findings.append(Finding(
                check_id="sec_no_disk_encryption",
                domain="security",
                category="filesystem",
                severity="HIGH",
                title="Nenhuma criptografia de disco detectada (LUKS)",
                rationale="Dados acessiveis por anyone com acesso fisico ao dispositivo.",
                evidence="Nenhum dispositivo LUKS encontrado",
                recommendation="Implementar criptografia full-disk com LUKS.",
                reference="CIS Debian 9.4",
                weight=rules["security_weights"]["HIGH"],
            ))
        return findings
