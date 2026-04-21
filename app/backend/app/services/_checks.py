from app.services import parser


def _check_docker_socket(commands: dict, rules: dict) -> list[dict]:
    findings: list[dict] = []
    docker_socket = commands.get("docker_socket", {}).get("stdout", "")
    if docker_socket:
        for line in docker_socket.splitlines():
            if "docker.sock" in line and "srw-rw-rw-" in line:
                findings.append(_docker_finding("sec_docker_socket_world_writable", line, rules))
                break
    return findings


def _check_docker_containers(commands: dict, rules: dict) -> list[dict]:
    findings: list[dict] = []
    docker_ps = commands.get("docker_ps", {}).get("stdout", "")
    if not docker_ps.strip():
        return findings
    try:
        containers = parser.parse_docker_ps(docker_ps)
        for container in containers:
            if container.get("Privileged", "").lower() == "true":
                findings.append(_docker_finding(
                    "sec_docker_privileged_container",
                    f"Container {container.get('Names')} (ID: {container.get('ID')})",
                    rules,
                ))
            ports = container.get("Ports", "")
            if ports and "," in ports:
                findings.append(_docker_finding(
                    "sec_docker_exposed_ports",
                    f"Container {container.get('Names')}: {ports}",
                    rules,
                ))
    except Exception:
        pass
    return findings


def _check_established_connections(commands: dict, rules: dict) -> list[dict]:
    findings: list[dict] = []
    established = commands.get("established_connections", {}).get("stdout", "")
    if not established:
        return findings
    conn_count = sum(1 for line in established.splitlines() if "ESTAB" in line)
    if conn_count > 100:
        findings.append({
            "check_id": "sec_many_established_connections",
            "domain": "security",
            "category": "network",
            "severity": "MED",
            "title": "Muitas conexoes TCP estabelecidas",
            "rationale": "Alto numero de conexoes pode indicar vazamento ou ataque.",
            "evidence": f"{conn_count} conexoes ESTAB",
            "recommendation": "Identificar processos e limpar conexoes persistentes.",
            "reference": "TCP connection baseline",
            "weight": rules["security_weights"]["MED"],
        })
    return findings


def _docker_finding(check_id: str, evidence: str, rules: dict) -> dict:
    titles = {
        "sec_docker_socket_world_writable": "Socket Docker com permissao world-writable",
        "sec_docker_privileged_container": "Container privilegiado",
        "sec_docker_exposed_ports": "Container com multiplas portas expostas",
    }
    rationales = {
        "sec_docker_socket_world_writable": "Acesso irrestrito ao socket Docker permite escape de container.",
        "sec_docker_privileged_container": "Container privilegiado tem acesso completo ao host.",
        "sec_docker_exposed_ports": "Multiplas portas expostas aumentam superficie de ataque.",
    }
    recommendations = {
        "sec_docker_socket_world_writable": "Corrigir permissao para 660 e restringir grupo.",
        "sec_docker_privileged_container": "Remover flag --privileged e usar capacidades especificas.",
        "sec_docker_exposed_ports": "Revisar portas expostas e usar rede interna.",
    }
    references = {
        "sec_docker_socket_world_writable": "Docker socket security",
        "sec_docker_privileged_container": "Docker privileged containers",
        "sec_docker_exposed_ports": "Docker network exposure",
    }
    return {
        "check_id": check_id,
        "domain": "security",
        "category": "container",
        "severity": "CRIT" if check_id != "sec_docker_exposed_ports" else "MED",
        "title": titles.get(check_id, ""),
        "rationale": rationales.get(check_id, ""),
        "evidence": evidence,
        "recommendation": recommendations.get(check_id, ""),
        "reference": references.get(check_id, ""),
        "weight": rules["security_weights"]["CRIT" if check_id != "sec_docker_exposed_ports" else "MED"],
    }