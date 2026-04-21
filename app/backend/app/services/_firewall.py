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