from __future__ import annotations

import json
from pathlib import Path

from app.services import parser
from app.services._firewall import (
    _nft_ruleset_state,
    _ufw_state,
    _iptables_state,
)
from app.services._checks import (
    _check_docker_socket,
    _check_docker_containers,
    _check_established_connections,
)
from app.services._identity import (
    CheckUid0Users,
    CheckManyShellUsers,
    CheckSudoNopasswd,
    CheckSshRootLogin,
    CheckSshPasswordAuth,
)
from app.services._network import (
    CheckManyPublicPorts,
    CheckWorldWritableEtc,
    CheckFirewallState,
)



SECURITY_CHECKS = [
    CheckUid0Users,
    CheckManyShellUsers,
    CheckSudoNopasswd,
    CheckSshRootLogin,
    CheckSshPasswordAuth,
    CheckManyPublicPorts,
    CheckWorldWritableEtc,
    CheckFirewallState,
]


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
    "sec_docker_socket_world_writable": {
        "steps": [
            "Corriga as permissoes do socket Docker com `chmod 660 /var/run/docker.sock`.",
            "Garanta que apenas usuarios autorizados belongcam ao grupo docker.",
            "Se necessario, remova usuarios do grupo docker que nao precisam de acesso.",
        ],
        "verify": [
            "Confirme que `ls -la /var/run/docker.sock` mostra permissao 660 e grupo docker.",
            "Valide que apenas usuarios autorizados conseguem executar `docker ps`.",
        ],
    },
    "sec_docker_privileged_container": {
        "steps": [
            "Reimplemente o container sem a flag `--privileged`.",
            "Use capacidades especificas (CAP_NET_RAW, CAP_SYS_ADMIN, etc.) se necessario.",
            "Considere usar rootless Docker ou Podman para isolamento adicional.",
        ],
        "verify": [
            "Execute `docker inspect` e confirme que Privileged = false.",
            "Teste acesso a recursos sensiveis pelo container.",
        ],
    },
    "sec_docker_exposed_ports": {
        "steps": [
            "Revise as portas expostas e remova as desnecessarias.",
            "Use redes Docker internas para comunicacao entre containers.",
            "Implemente proxy reverso para entrada controlada.",
        ],
        "verify": [
            "Execute `docker ps` e confirme apenas portas essenciais expostas.",
            "Teste conectividade externa apenas nas portas permitidas.",
        ],
    },
    "sec_many_established_connections": {
        "steps": [
            "Identifique os processos com muitas conexoes estabelecidas.",
            "Revise connections persistentes e limpa releases desnecessarios.",
            "Implemente rate limiting e temporizacao apropriada.",
        ],
        "verify": [
            "Execute `ss -tan` e confirme reducao de conexoes persistentes.",
            "Monitore metricas de rede para validar estabilidade.",
        ],
    },
}


def load_rules(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_findings(snapshot: dict, rules: dict) -> list[dict]:
    findings: list[dict] = []
    commands = snapshot["commands"]

    for checker_cls in SECURITY_CHECKS:
        checker = checker_cls()
        for finding in checker.check(snapshot, commands, rules):
            findings.append(finding.to_dict())

    _docker_checks(snapshot, commands, findings, rules)
    _performance_checks(snapshot, commands, findings, rules)

    return findings


def _docker_checks(snapshot: dict, commands: dict, findings: list[dict], rules: dict) -> None:
    findings.extend(_check_docker_socket(commands, rules))
    findings.extend(_check_docker_containers(commands, rules))
    findings.extend(_check_established_connections(commands, rules))


def _performance_checks(snapshot: dict, commands: dict, findings: list[dict], rules: dict) -> None:
    thresholds = rules.get("performance_thresholds", {})
    weights = rules.get("security_weights", {})
    disk_output = commands.get("disk_usage", {}).get("stdout", "")
    meminfo = snapshot.get("files", {}).get("proc_meminfo", {}).get("content", "")
    loadavg = snapshot.get("files", {}).get("proc_loadavg", {}).get("stdout", "")
    swaps = snapshot.get("files", {}).get("proc_swaps", {}).get("content", "")
    dmesg = commands.get("dmesg_oom", {}).get("stdout", "")

    _check_disk_pressure(disk_output, thresholds, weights, findings)
    _check_memory_pressure(meminfo, thresholds, weights, findings)
    _check_swap_usage(swaps, thresholds, weights, findings)
    _check_cpu_load(loadavg, thresholds, weights, findings)
    _check_oom_events(dmesg, findings)


def _check_disk_pressure(disk_output: str, thresholds: dict, weights: dict, findings: list[dict]) -> None:
    if not disk_output:
        return
    threshold = thresholds.get("disk_high_percent", 85)
    for row in parser.parse_df(disk_output):
        use_percent = row.get("use_percent", 0)
        if use_percent >= threshold:
            findings.append({
                "check_id": "perf_disk_high",
                "domain": "performance",
                "category": "disk",
                "severity": "CRIT" if use_percent >= 95 else "HIGH" if use_percent >= 90 else "MED",
                "title": f"Disco em {row.get('mountpoint')} com {use_percent}% de uso",
                "rationale": "Espaço em disco baixo pode causar falhas em serviços.",
                "evidence": f"{row.get('mountpoint')}: {use_percent}% usado de {row.get('size')}",
                "recommendation": "Limpar logs, caches ou expandir capacidade.",
                "reference": "Disk usage baseline",
                "weight": weights.get("CRIT") if use_percent >= 95 else weights.get("HIGH") if use_percent >= 90 else weights.get("MED"),
            })


def _check_memory_pressure(meminfo: str, thresholds: dict, weights: dict, findings: list[dict]) -> None:
    if not meminfo:
        return
    threshold = thresholds.get("memory_high_percent", 90)
    mem_data: dict[str, int] = {}
    for line in meminfo.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(":"):
            key = parts[0].rstrip(":")
            value = parts[1]
            if value.isdigit():
                mem_data[key] = int(value)
    total = mem_data.get("MemTotal", 0)
    available = mem_data.get("MemAvailable", mem_data.get("MemFree", 0))
    if total > 0:
        used = total - available
        use_percent = int((used / total) * 100)
        if use_percent >= threshold:
            findings.append({
                "check_id": "perf_memory_high",
                "domain": "performance",
                "category": "memory",
                "severity": "CRIT" if use_percent >= 98 else "HIGH" if use_percent >= 95 else "MED",
                "title": f"Memória com {use_percent}% de uso",
                "rationale": "Memória alta pode causar swapping e lentidão.",
                "evidence": f"Uso: {use_percent}% ({used}KB / {total}KB)",
                "recommendation": "Reduzir consumo ou expandir RAM.",
                "reference": "Memory usage baseline",
                "weight": weights.get("CRIT") if use_percent >= 98 else weights.get("HIGH") if use_percent >= 95 else weights.get("MED"),
            })


def _check_swap_usage(swaps_content: str, thresholds: dict, weights: dict, findings: list[dict]) -> None:
    if not swaps_content:
        return
    threshold_kb = thresholds.get("swap_used_mb", 512) * 1024
    swap_data: dict[str, int] = {}
    for line in swaps_content.splitlines():
        if line.startswith("Filename"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            try:
                swap_data["Size"] = int(parts[2])
                swap_data["Used"] = int(parts[3])
            except (ValueError, IndexError):
                continue
    used = swap_data.get("Used", 0)
    if used >= threshold_kb:
        findings.append({
            "check_id": "perf_swap_high",
            "domain": "performance",
            "category": "memory",
            "severity": "HIGH",
            "title": f"Swap em uso: {used // 1024}MB",
            "rationale": "Swap ativo indica memória insuficiente.",
            "evidence": f"Swap usado: {used // 1024}MB",
            "recommendation": "Aumentar RAM ou ajustar swappiness.",
            "reference": "Swap usage baseline",
            "weight": weights.get("HIGH"),
        })


def _check_cpu_load(loadavg: str, thresholds: dict, weights: dict, findings: list[dict]) -> None:
    if not loadavg:
        return
    threshold = thresholds.get("load_per_cpu_warn", 1.5)
    parts = loadavg.split()
    try:
        load_1m = float(parts[0])
        cpu_cores = max(1, int(parts[2])) if len(parts) > 2 else 1
        load_per_cpu = load_1m / cpu_cores if cpu_cores > 0 else load_1m
        if load_1m > threshold * cpu_cores:
            findings.append({
                "check_id": "perf_cpu_high",
                "domain": "performance",
                "category": "cpu",
                "severity": "HIGH",
                "title": f"Load average alto: {load_1m} (por core: {load_per_cpu:.2f})",
                "rationale": "Alta carga de CPU pode causar lentidão.",
                "evidence": f"Load 1m: {load_1m}, cores: {cpu_cores}",
                "recommendation": "Identificar processos consumidores.",
                "reference": "CPU load baseline",
                "weight": weights.get("HIGH"),
            })
    except (ValueError, IndexError, TypeError):
        pass


def _check_oom_events(dmesg: str, findings: list[dict]) -> None:
    if dmesg and "Out of memory" in dmesg:
        findings.append({
            "check_id": "perf_oom_signals",
            "domain": "performance",
            "category": "memory",
            "severity": "CRIT",
            "title": "Evento OOM detectado",
            "rationale": "OOM indica falha por falta de memória.",
            "evidence": "Kernel OOM killer ativado",
            "recommendation": "Aumentar memória ou ajustar limites.",
            "reference": "OOM events baseline",
            "weight": 25,
        })


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

    docker_containers = []
    docker_networks = []
    established_connections = 0

    docker_ps_raw = commands.get("docker_ps", {}).get("stdout", "")
    if docker_ps_raw:
        docker_containers = parser.parse_docker_ps(docker_ps_raw)

    docker_network_raw = commands.get("docker_network", {}).get("stdout", "")
    if docker_network_raw:
        docker_networks = parser.parse_docker_ps(docker_network_raw)

    established_raw = commands.get("established_connections", {}).get("stdout", "")
    if established_raw:
        established_connections = sum(1 for line in established_raw.splitlines() if "ESTAB" in line)

    listening_ports_data = [
        {
            "protocol": sock.get("proto", ""),
            "state": sock.get("state", ""),
            "address": sock.get("local_address", ""),
        }
        for sock in sockets
    ]

    established_list = []
    established_raw = commands.get("established_connections", {}).get("stdout", "")
    if established_raw:
        for line in established_raw.splitlines():
            if "ESTAB" in line:
                parts = line.split()
                if len(parts) >= 5:
                    established_list.append({
                        "protocol": parts[0],
                        "local_address": parts[3] if len(parts) > 3 else "",
                        "remote_address": parts[4] if len(parts) > 4 else "",
                        "state": "ESTAB",
                    })

    return {
        "host": snapshot["metadata"]["hostname"],
        "human_users": len([u for u in passwd_entries if u["uid"] >= 1000 and not u.get("shell", "").endswith("nologin")]),
        "listening_ports": len(sockets),
        "critical_findings": len([finding for finding in findings if finding["severity"] in {"HIGH", "CRIT"}]),
        "disk_pressure_mounts": [row for row in disk_rows if row["use_percent"] >= 85],
        "top_processes": top_processes[:5],
        "docker_containers": len(docker_containers),
        "docker_networks": len(docker_networks),
        "established_connections": established_connections,
        "network_details": {
            "listening_ports": listening_ports_data[:50],
            "established_connections": established_list[:50],
        },
    }



