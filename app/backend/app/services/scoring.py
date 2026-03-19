from __future__ import annotations

import json
import re
from pathlib import Path

from app.services import parser


REMEDIATION_GUIDES = {
    "sec_uid0_users": {
        "steps": [
            "Liste as contas com UID 0 e confirme qual delas realmente precisa de privilegio total.",
            "Remova o UID 0 das contas desnecessarias com `usermod -u <novo_uid> <usuario>` ou desative a conta se ela nao for mais usada.",
            "Revise scripts e automacoes que dependam dessa conta antes da mudanca.",
        ],
        "verify": [
            "Confirme em `/etc/passwd` que apenas `root` permanece com UID 0.",
            "Execute `getent passwd 0` e valide que nao existem aliases administrativos indevidos.",
        ],
    },
    "sec_sudo_nopasswd": {
        "steps": [
            "Revise os arquivos `/etc/sudoers` e `/etc/sudoers.d/*` para identificar quais entradas usam `NOPASSWD`.",
            "Troque `NOPASSWD` por regras com senha ou restrinja o comando permitido a um conjunto minimo e auditavel.",
            "Valide as mudancas com `visudo -c` antes de aplicar em producao.",
        ],
        "verify": [
            "Confirme que as entradas indevidas nao aparecem mais em `sudo -l` para o usuario afetado.",
            "Valide que `visudo -c` retorna configuracao consistente.",
        ],
    },
    "sec_ssh_root_login": {
        "steps": [
            "Ajuste `PermitRootLogin no` em `sshd_config` ou no drop-in correspondente.",
            "Garanta acesso administrativo via conta nominal e `sudo` antes de reiniciar o servico.",
            "Recarregue o SSH de forma segura com `sshd -t && systemctl reload sshd`.",
        ],
        "verify": [
            "Execute `sshd -T | grep permitrootlogin` e confirme valor `no`.",
            "Teste login administrativo com conta nao-root antes de encerrar a sessao atual.",
        ],
    },
    "sec_many_public_ports": {
        "steps": [
            "Mapeie quais servicos precisam realmente escutar em `0.0.0.0` ou `[::]`.",
            "Restrinja o bind para interfaces internas quando possivel e feche portas nao utilizadas no firewall.",
            "Revise servicos publicados por systemd, docker ou proxies reversos.",
        ],
        "verify": [
            "Rode `ss -tulpen` novamente e confirme reducao da exposicao publica.",
            "Valide as regras do firewall com `nft list ruleset` ou ferramenta equivalente.",
        ],
    },
    "sec_world_writable_etc": {
        "steps": [
            "Liste os arquivos afetados em `/etc` e confirme owner/grupo esperados.",
            "Corrija as permissoes com `chmod` e, se necessario, ajuste ownership com `chown`.",
            "Investigue como a permissao insegura foi introduzida para evitar recorrencia.",
        ],
        "verify": [
            "Rode novamente `find /etc -xdev -type f -perm -0002` e confirme retorno vazio.",
            "Valide se os servicos dependentes continuam funcionando apos a correcao.",
        ],
    },
    "sec_firewall_unclear": {
        "steps": [
            "Defina qual stack sera o baseline oficial: `nftables`, `ufw` ou `iptables`.",
            "Implemente politica default de bloqueio de entrada e permita apenas portas justificadas.",
            "Documente as excecoes por servico e ambiente para evitar drift operacional.",
        ],
        "verify": [
            "Confirme a politica ativa com `nft list ruleset`, `ufw status verbose` ou `iptables -S`.",
            "Teste conectividade apenas nas portas que devem permanecer acessiveis.",
        ],
    },
    "sec_firewall_permissive": {
        "steps": [
            "Revise a politica de entrada do firewall e identifique portas liberadas alem do necessario.",
            "Restrinja regras amplas por origem, interface ou servico e mantenha apenas excecoes justificadas.",
            "Prefira uma baseline com negacao por padrao ou regras explicitas bem documentadas.",
        ],
        "verify": [
            "Valide o ruleset com `nft list ruleset`, `ufw status verbose` ou `iptables -S`.",
            "Teste somente os servicos que devem ficar acessiveis apos o ajuste.",
        ],
    },
    "perf_cpu_high": {
        "steps": [
            "Identifique os processos mais consumidores com `ps` ou `top` e confirme se o pico e esperado.",
            "Reveja concorrencia, afinidade de CPU, jobs em lote e throttling de servicos pesados.",
            "Se o comportamento for recorrente, reavalie capacidade ou distribua carga.",
        ],
        "verify": [
            "Monitore `top`, `pidstat` ou a propria coleta para confirmar queda do uso de CPU.",
            "Valide impacto em latencia e tempo de resposta do servico principal.",
        ],
    },
    "perf_memory_high": {
        "steps": [
            "Liste processos com maior consumo de memoria e confirme se existe leak ou working set excessivo.",
            "Reduza caches residentes, ajuste limites de servico e remova processos nao essenciais.",
            "Se a carga for legitima, replaneje memoria disponivel ou escalonamento.",
        ],
        "verify": [
            "Reavalie o host e confirme queda no uso percentual de RAM e swap.",
            "Verifique se os eventos de reclaim ou OOM deixaram de ocorrer.",
        ],
    },
    "perf_disk_high": {
        "steps": [
            "Descubra quais diretorios consomem mais espaco com `du -xh --max-depth=1` no mount afetado.",
            "Ajuste retencao de logs, caches, artefatos temporarios e backups locais.",
            "Planeje expansao de capacidade se o crescimento for estrutural.",
        ],
        "verify": [
            "Rode `df -h` novamente e confirme folga acima do threshold.",
            "Valide se logs e servicos voltaram a operar sem falhas por falta de espaco.",
        ],
    },
    "perf_oom_signals": {
        "steps": [
            "Identifique qual processo foi encerrado pelo OOM usando `journalctl` e `dmesg`.",
            "Revise limites de memoria, leaks, cache excessivo e picos de carga associados.",
            "Aplique ajuste de configuracao ou capacidade antes que o evento se repita.",
        ],
        "verify": [
            "Confirme ausencia de novos eventos OOM no journal apos a correcao.",
            "Valide estabilidade do servico afetado durante o pico de carga.",
        ],
    },
}


def load_rules(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_findings(snapshot: dict, rules: dict) -> list[dict]:
    findings: list[dict] = []
    files = snapshot["files"]
    commands = snapshot["commands"]
    psutil_metrics = snapshot["metadata"]["psutil"]
    thresholds = rules["performance_thresholds"]
    critical_services = set(rules["critical_services"])

    passwd_entries = parser.parse_passwd(files["passwd"]["content"])
    human_users = [user for user in passwd_entries if user["uid"] >= 1000 and not user["shell"].endswith("nologin")]
    if any(user["uid"] == 0 and user["username"] != "root" for user in passwd_entries):
        findings.append(
            _finding(
                "sec_uid0_users",
                "security",
                "identity",
                "CRIT",
                "Conta adicional com UID 0 encontrada",
                "Usuarios com UID 0 ampliam superficie de privilegio.",
                evidence=", ".join(user["username"] for user in passwd_entries if user["uid"] == 0),
                recommendation="Revisar contas administrativas e remover UID 0 desnecessario.",
                reference="CIS Debian 5.4",
                rules=rules,
            )
        )

    if len(human_users) > 10:
        findings.append(
            _finding(
                "sec_many_shell_users",
                "security",
                "identity",
                "MED",
                "Numero elevado de usuarios com shell interativo",
                "Mais usuarios interativos aumentam a superficie de ataque.",
                evidence=f"{len(human_users)} usuarios com shell ativo",
                recommendation="Validar contas ativas e remover shells desnecessarios.",
                reference="Principio de menor privilegio",
                rules=rules,
            )
        )

    sudoers_content = files["sudoers"]["content"]
    sudoers_d = snapshot.get("directories", {}).get("sudoers_d", {}).get("entries", [])
    sudoers_merged = "\n".join([sudoers_content, *[entry["content"] for entry in sudoers_d]])
    if "NOPASSWD" in sudoers_merged:
        findings.append(
            _finding(
                "sec_sudo_nopasswd",
                "security",
                "privilege",
                "HIGH",
                "Entrada NOPASSWD detectada em sudoers",
                "Bypass de senha reduz friccao de abuso pos-exploracao.",
                evidence="NOPASSWD presente em /etc/sudoers",
                recommendation="Restringir NOPASSWD apenas a automacao estritamente controlada.",
                reference="CIS Debian 5.2",
                rules=rules,
            )
        )

    sshd_config = files["sshd_config"]["content"]
    if sshd_config:
        # Detecta PermitRootLogin com qualquer valor inseguro (yes, without-password,
        # prohibit-password). Ignora linhas comentadas e whitespace extra.
        _root_login_insecure = re.compile(
            r"^\s*PermitRootLogin\s+(?!no\b)",
            re.MULTILINE | re.IGNORECASE,
        )
        _root_login_match = _root_login_insecure.search(sshd_config)
        if _root_login_match:
            evidence_value = _root_login_match.group(0).strip()
            findings.append(
                _finding(
                    "sec_ssh_root_login",
                    "security",
                    "ssh",
                    "HIGH",
                    "SSH permite login direto de root",
                    "Login direto de root reduz rastreabilidade e amplia impacto.",
                    evidence=f"PermitRootLogin configurado como: {evidence_value!r}",
                    recommendation="Definir PermitRootLogin no e usar sudo controlado.",
                    reference="CIS Debian 5.1",
                    rules=rules,
                )
            )
        # Detecta PasswordAuthentication yes (ignora comentários e espaços extras)
        _pw_auth_insecure = re.compile(
            r"^\s*PasswordAuthentication\s+yes\b",
            re.MULTILINE | re.IGNORECASE,
        )
        if _pw_auth_insecure.search(sshd_config):
            findings.append(
                _finding(
                    "sec_ssh_password_auth",
                    "security",
                    "ssh",
                    "MED",
                    "SSH aceita autenticacao por senha",
                    "Credenciais por senha sao mais suscetiveis a brute force e phishing.",
                    evidence="PasswordAuthentication yes",
                    recommendation="Preferir chaves, MFA e restricoes por rede.",
                    reference="OpenSSH hardening",
                    rules=rules,
                )
            )

    sockets = parser.parse_ss_listening(commands["listening_ports"].get("stdout", ""))
    public_sockets = [sock for sock in sockets if ":0.0.0.0:" in sock["local_address"] or "[::]:" in sock["local_address"]]
    if len(public_sockets) > 5:
        findings.append(
            _finding(
                "sec_many_public_ports",
                "security",
                "network",
                "HIGH",
                "Muitas portas escutando em interfaces amplas",
                "Exposicao de rede aumenta a chance de ataque remoto.",
                evidence=f"{len(public_sockets)} sockets em 0.0.0.0/[::]",
                recommendation="Restringir bind, firewall e servicos nao essenciais.",
                reference="Baseline de exposicao minima",
                rules=rules,
            )
        )

    units = parser.parse_systemd_units(commands["systemd_units"].get("stdout", ""))
    enabled_critical = [unit["unit"] for unit in units if unit["unit"] in critical_services and unit["state"] == "enabled"]
    if enabled_critical:
        findings.append(
            _finding(
                "sec_critical_services_enabled",
                "security",
                "services",
                "LOW",
                "Servicos criticos habilitados",
                "Servicos de infraestrutura exigem patching e monitoramento continuo.",
                evidence=", ".join(enabled_critical),
                recommendation="Confirmar necessidade de cada servico e reforcar observabilidade.",
                reference="Asset exposure baseline",
                rules=rules,
            )
        )

    world_writable = parser.count_lines(snapshot["filesystem_checks"]["world_writable_etc"].get("stdout", ""))
    if world_writable > 0:
        findings.append(
            _finding(
                "sec_world_writable_etc",
                "security",
                "filesystem",
                "CRIT",
                "Arquivos world-writable encontrados em /etc",
                "Permissao global de escrita em configuracoes e altamente arriscada.",
                evidence=f"{world_writable} entradas em /etc",
                recommendation="Corrigir ownership e permissoes imediatamente.",
                reference="Filesystem integrity baseline",
                rules=rules,
            )
        )

    suid_count = parser.count_lines(snapshot["filesystem_checks"]["suid_sgid_usr"].get("stdout", ""))
    if suid_count > 50:
        findings.append(
            _finding(
                "sec_suid_sgid_sprawl",
                "security",
                "filesystem",
                "MED",
                "Quantidade alta de binarios SUID/SGID",
                "Cada binario privilegiado amplia superficie de escalacao local.",
                evidence=f"{suid_count} arquivos SUID/SGID em /usr",
                recommendation="Revisar baseline do sistema e remover pacotes desnecessarios.",
                reference="Privileged binaries review",
                rules=rules,
            )
        )

    firewall_state = _evaluate_firewall_state(commands)
    if firewall_state["status"] == "not_confirmed":
        findings.append(
            _finding(
                "sec_firewall_unclear",
                "security",
                "network",
                "HIGH",
                "Firewall ativo nao ficou evidente na coleta",
                "Ausencia de bloqueio de entrada aumenta exposicao desnecessaria.",
                evidence=firewall_state["evidence"],
                recommendation="Validar nftables/ufw/iptables e documentar baseline.",
                reference="Host firewall baseline",
                rules=rules,
            )
        )
    elif firewall_state["status"] == "permissive":
        findings.append(
            _finding(
                "sec_firewall_permissive",
                "security",
                "network",
                "MED",
                "Firewall detectado, mas sem postura restritiva evidente",
                "Ha indicao de firewall ativo, porem as regras observadas nao demonstram bloqueio padrao ou filtragem suficientemente defensiva.",
                evidence=firewall_state["evidence"],
                recommendation="Revisar regras permitidas e reduzir exposicao desnecessaria.",
                reference="Host firewall hardening baseline",
                rules=rules,
            )
        )

    os_release = parser.parse_key_value_file(files["os_release"]["content"])
    update_lines = commands["updates_debian"].get("stdout", "")
    if "upgradable" in update_lines and parser.count_lines(update_lines) > 1:
        findings.append(
            _finding(
                "sec_pending_updates",
                "security",
                "patching",
                "MED",
                "Pacotes pendentes de atualizacao detectados",
                "Backlog de patches aumenta janela de exposicao a CVEs.",
                evidence=f"Distro {os_release.get('PRETTY_NAME', 'desconhecida')} com updates pendentes",
                recommendation="Aplicar atualizacoes em janela controlada e validar rollback.",
                reference="Patch management baseline",
                rules=rules,
            )
        )

    if psutil_metrics["cpu_percent"] >= thresholds["cpu_high_percent"]:
        findings.append(
            _finding(
                "perf_cpu_high",
                "performance",
                "cpu",
                "HIGH",
                "CPU em utilizacao elevada",
                "Uso sustentado reduz folga operacional e aumenta latencia.",
                evidence=f"CPU {psutil_metrics['cpu_percent']:.1f}%",
                recommendation="Analisar processos no topo e revisar throttling, concorrencia e afinidade.",
                reference="Performance baseline",
                rules=rules,
            )
        )

    if psutil_metrics["memory"]["percent"] >= thresholds["memory_high_percent"]:
        findings.append(
            _finding(
                "perf_memory_high",
                "performance",
                "memory",
                "HIGH",
                "RAM proxima do limite",
                "Pressao de memoria gera swap, reclaim e degradacao geral.",
                evidence=f"Memoria {psutil_metrics['memory']['percent']:.1f}%",
                recommendation="Revisar caches, servicos residentes e capacidade.",
                reference="Performance baseline",
                rules=rules,
            )
        )

    swap_used_mb = psutil_metrics["swap"]["used"] / (1024 * 1024)
    if swap_used_mb >= thresholds["swap_used_mb"]:
        findings.append(
            _finding(
                "perf_swap_used",
                "performance",
                "memory",
                "MED",
                "Uso relevante de swap detectado",
                "Swap ativo e sinal de pressao de memoria ou tuning inadequado.",
                evidence=f"Swap usada {swap_used_mb:.0f} MB",
                recommendation="Validar working set, swappiness e tamanho de RAM.",
                reference="Memory pressure baseline",
                rules=rules,
            )
        )

    disk_rows = parser.parse_df(commands["disk_usage"].get("stdout", ""))
    hot_filesystems = [row for row in disk_rows if row["use_percent"] >= thresholds["disk_high_percent"]]
    if hot_filesystems:
        findings.append(
            _finding(
                "perf_disk_high",
                "performance",
                "storage",
                "HIGH",
                "Filesystem com ocupacao alta",
                "Disco cheio degrada I/O, logs e operacao de servicos.",
                evidence=", ".join(f"{row['mountpoint']}={row['use_percent']}%" for row in hot_filesystems),
                recommendation="Liberar espaco, revisar retention e capacidade.",
                reference="Capacity baseline",
                rules=rules,
            )
        )

    loadavg = psutil_metrics["loadavg"][0]
    cpu_count = max(1, int(psutil_metrics.get("cpu_count", 1)))
    if loadavg / cpu_count >= thresholds["load_per_cpu_warn"]:
        findings.append(
            _finding(
                "perf_load_high",
                "performance",
                "cpu",
                "MED",
                "Load average elevado por nucleo",
                "Fila de trabalho acima da folga tende a aumentar latencia.",
                evidence=f"load1={loadavg:.2f}",
                recommendation="Cruzar com iowait, CPU steal e top processos.",
                reference="Linux load baseline",
                rules=rules,
            )
        )

    journal_errors = parser.count_lines(commands["journal_errors"].get("stdout", ""))
    if journal_errors > 5:
        findings.append(
            _finding(
                "perf_journal_errors",
                "performance",
                "stability",
                "LOW",
                "Erros recentes no journal podem afetar desempenho",
                "Falhas recorrentes de servico costumam gerar retry e overhead.",
                evidence=f"{journal_errors} linhas de erro recentes",
                recommendation="Revisar servicos com erro recorrente antes de tunar performance.",
                reference="Stability before tuning",
                rules=rules,
            )
        )

    if "oom" in commands["dmesg_oom"].get("stdout", "").lower():
        findings.append(
            _finding(
                "perf_oom_signals",
                "performance",
                "memory",
                "HIGH",
                "Sinais de OOM killer encontrados",
                "OOM impacta disponibilidade e mascara causas reais de saturacao.",
                evidence="dmesg/journal indica OOM",
                recommendation="Investigar working set, leaks e limites de memoria.",
                reference="Kernel OOM investigation",
                rules=rules,
            )
        )

    slow_units = parser.parse_systemd_blame(commands["systemd_analyze"].get("stdout", ""))
    if slow_units:
        findings.append(
            _finding(
                "perf_boot_slow_units",
                "performance",
                "boot",
                "LOW",
                "Servicos lentos no boot identificados",
                "Boot lento indica inicializacao sequencial ou dependencia custosa.",
                evidence=", ".join(f"{item['unit']} ({item['duration']})" for item in slow_units[:3]),
                recommendation="Postergar servicos nao criticos e revisar dependencias.",
                reference="systemd-analyze",
                rules=rules,
            )
        )

    return findings


def calculate_scores(findings: list[dict], rules: dict) -> dict:
    security_penalty = 0
    performance_penalty = 0
    weights = rules["security_weights"]
    severity_counts = {"security": {}, "performance": {}}

    for finding in findings:
        penalty = weights[finding["severity"]]
        severity_counts[finding["domain"]][finding["severity"]] = severity_counts[finding["domain"]].get(finding["severity"], 0) + 1
        if finding["domain"] == "security":
            security_penalty += penalty
        else:
            performance_penalty += penalty

    security_score = max(0.0, 100.0 - security_penalty)
    performance_score = max(0.0, 100.0 - performance_penalty)
    overall_score = round(
        (security_score * rules["score_weights"]["security"]) + (performance_score * rules["score_weights"]["performance"]),
        2,
    )
    return {
        "security": round(security_score, 2),
        "performance": round(performance_score, 2),
        "overall": overall_score,
        "explanation": {
            "weights": rules["score_weights"],
            "severity_counts": severity_counts,
            "security_penalty": security_penalty,
            "performance_penalty": performance_penalty,
            "why": [
                "Seguranca desconta pontos por severidade ponderada dos achados.",
                "Performance desconta pontos por thresholds operacionais excedidos.",
                "Score geral aplica 60% seguranca e 40% performance no MVP.",
            ],
        },
    }


def summarize_snapshot(snapshot: dict, findings: list[dict]) -> dict:
    files = snapshot["files"]
    commands = snapshot["commands"]
    passwd_entries = parser.parse_passwd(files["passwd"]["content"])
    disk_rows = parser.parse_df(commands["disk_usage"].get("stdout", ""))
    sockets = parser.parse_ss_listening(commands["listening_ports"].get("stdout", ""))
    top_processes = parser.parse_ps_table(commands["cpu_processes"].get("stdout", ""))

    return {
        "host": snapshot["metadata"]["hostname"],
        "human_users": len([user for user in passwd_entries if user["uid"] >= 1000]),
        "listening_ports": len(sockets),
        "critical_findings": len([finding for finding in findings if finding["severity"] in {"HIGH", "CRIT"}]),
        "disk_pressure_mounts": [row for row in disk_rows if row["use_percent"] >= 85],
        "top_processes": top_processes[:5],
    }


def _finding(
    check_id: str,
    domain: str,
    category: str,
    severity: str,
    title: str,
    rationale: str,
    evidence: str,
    recommendation: str,
    reference: str,
    rules: dict,
) -> dict:
    return {
        "check_id": check_id,
        "domain": domain,
        "category": category,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
        "reference": reference,
        "rationale": rationale,
        "weight": rules["security_weights"][severity],
        "extra_data": _build_finding_metadata(check_id, severity, recommendation, reference),
    }


def _build_finding_metadata(check_id: str, severity: str, recommendation: str, reference: str) -> dict:
    metadata: dict = {}
    if severity not in {"HIGH", "CRIT"}:
        return metadata

    guide = REMEDIATION_GUIDES.get(
        check_id,
        {
            "steps": [
                recommendation,
                "Aplique a mudanca em janela controlada e com rollback definido.",
                "Registre a decisao tecnica para manter o baseline consistente.",
            ],
            "verify": [
                "Execute novamente a coleta e confirme que o finding nao reaparece.",
                f"Valide a configuracao final usando a referencia {reference}.",
            ],
        },
    )
    metadata["remediation"] = {
        "steps": guide["steps"],
        "verify": guide["verify"],
    }
    return metadata


def _evaluate_firewall_state(commands: dict) -> dict:
    nft_stdout = commands["firewall_nft"].get("stdout", "")
    ufw_stdout = commands["firewall_ufw"].get("stdout", "")
    iptables_stdout = commands["firewall_iptables"].get("stdout", "")

    nft_state = _nft_ruleset_state(nft_stdout)
    if nft_state:
        return nft_state
    ufw_state = _ufw_state(ufw_stdout)
    if ufw_state:
        return ufw_state
    iptables_state = _iptables_state(iptables_stdout)
    if iptables_state:
        return iptables_state

    reasons = []
    for command_name in ("firewall_nft", "firewall_ufw", "firewall_iptables"):
        command = commands[command_name]
        if not command.get("available"):
            reasons.append(f"{command_name}=indisponivel")
        elif command.get("timed_out"):
            reasons.append(f"{command_name}=timeout")
        elif command.get("stderr"):
            reasons.append(f"{command_name}=stderr:{command['stderr'].splitlines()[0][:80]}")
        else:
            reasons.append(f"{command_name}=sem-regras-detectadas")
    return {"status": "not_confirmed", "evidence": "; ".join(reasons)}


def _nft_ruleset_state(output: str) -> dict | None:
    lower = output.lower()
    if not lower.strip():
        return None
    has_hook = " hook input " in lower or " hook forward " in lower or " hook output " in lower
    has_policy = "policy drop" in lower or "policy reject" in lower
    has_rule_action = " accept" in lower or " drop" in lower or " reject" in lower
    has_table = "table inet" in lower or "table ip " in lower or "table ip6" in lower
    restrictive = has_policy or " drop" in lower or " reject" in lower
    if (has_hook and has_rule_action) or (has_table and has_policy):
        return {
            "status": "restrictive" if restrictive else "permissive",
            "evidence": "nftables possui ruleset ativo com hooks e regras de filtro",
        }
    return None


def _ufw_state(output: str) -> dict | None:
    lower = output.lower()
    if "status: active" not in lower:
        return None
    restrictive = "default: deny" in lower or "deny (incoming)" in lower or "reject (incoming)" in lower
    return {
        "status": "restrictive" if restrictive else "permissive",
        "evidence": "UFW reporta status ativo" + (" com default deny" if restrictive else " sem default deny evidente"),
    }


def _iptables_state(output: str) -> dict | None:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return None
    non_empty_rules = [line for line in lines if line.startswith("-A ")]
    restrictive_policies = [line for line in lines if line.startswith("-P ") and (" DROP" in line or " REJECT" in line)]
    custom_chains = [line for line in lines if line.startswith("-N ")]
    if not (non_empty_rules or restrictive_policies or custom_chains):
        return None
    restrictive = bool(restrictive_policies) or any(" -j DROP" in line or " -j REJECT" in line for line in non_empty_rules)
    return {
        "status": "restrictive" if restrictive else "permissive",
        "evidence": "iptables possui regras/chains ativas" + (" com bloqueio explicito" if restrictive else " sem bloqueio explicito"),
    }
