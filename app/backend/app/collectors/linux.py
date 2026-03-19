from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import psutil

from app.core.config import settings
from app.core.errors import ScanExecutionError
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class CommandSpec:
    key: str
    argv: list[str]
    rationale: str
    timeout: int = settings.command_timeout_seconds


COMMANDS: dict[str, CommandSpec] = {
    "listening_ports": CommandSpec("listening_ports", ["ss", "-tulpen"], "Inventariar portas em escuta."),
    "systemd_units": CommandSpec(
        "systemd_units",
        ["systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend"],
        "Identificar servicos habilitados e superficie ativa.",
    ),
    "firewall_nft": CommandSpec("firewall_nft", ["nft", "list", "ruleset"], "Coletar estado do firewall nftables."),
    "firewall_ufw": CommandSpec("firewall_ufw", ["ufw", "status", "verbose"], "Coletar estado do UFW."),
    "firewall_iptables": CommandSpec("firewall_iptables", ["iptables", "-S"], "Coletar regras do iptables."),
    "last_logins": CommandSpec("last_logins", ["last", "-n", "15"], "Consultar acessos recentes."),
    "journal_errors": CommandSpec(
        "journal_errors",
        ["journalctl", "-p", "3", "-n", "40", "--no-pager"],
        "Resumir erros recentes do journal sem leitura extensa.",
    ),
    "dmesg_oom": CommandSpec(
        "dmesg_oom",
        ["dmesg", "--ctime", "--level=err,warn"],
        "Buscar sinais recentes de pressao e OOM.",
    ),
    "cpu_processes": CommandSpec(
        "cpu_processes",
        ["ps", "-eo", "pid,ppid,comm,%cpu,%mem,state", "--sort=-%cpu"],
        "Listar processos mais pesados.",
    ),
    "disk_usage": CommandSpec("disk_usage", ["df", "-h"], "Avaliar uso de disco."),
    "inode_usage": CommandSpec("inode_usage", ["df", "-i"], "Avaliar uso de inodes."),
    "ip_link_stats": CommandSpec("ip_link_stats", ["ip", "-s", "link"], "Verificar erros de rede."),
    "dns_config": CommandSpec("dns_config", ["resolvectl", "status"], "Ler configuracao DNS ativa."),
    "systemd_analyze": CommandSpec(
        "systemd_analyze",
        ["systemd-analyze", "blame"],
        "Identificar servicos lentos no boot.",
    ),
    "updates_debian": CommandSpec("updates_debian", ["apt", "list", "--upgradable"], "Identificar updates pendentes."),
}


TEXT_FILES = {
    "passwd": Path(f"{settings.host_fs_prefix}/etc/passwd"),
    "group": Path(f"{settings.host_fs_prefix}/etc/group"),
    "sudoers": Path(f"{settings.host_fs_prefix}/etc/sudoers"),
    "os_release": Path(f"{settings.host_fs_prefix}/etc/os-release"),
    "machine_id": Path(f"{settings.host_fs_prefix}/etc/machine-id"),
    "sshd_config": Path(f"{settings.host_fs_prefix}/etc/ssh/sshd_config"),
    "fstab": Path(f"{settings.host_fs_prefix}/etc/fstab"),
    "resolv_conf": Path(f"{settings.host_fs_prefix}/etc/resolv.conf"),
    "proc_loadavg": Path(f"{settings.host_fs_prefix}/proc/loadavg"),
    "proc_meminfo": Path(f"{settings.host_fs_prefix}/proc/meminfo"),
    "proc_diskstats": Path(f"{settings.host_fs_prefix}/proc/diskstats"),
    "proc_stat": Path(f"{settings.host_fs_prefix}/proc/stat"),
    "proc_swaps": Path(f"{settings.host_fs_prefix}/proc/swaps"),
}

DIRECTORIES = {
    "sudoers_d": Path(f"{settings.host_fs_prefix}/etc/sudoers.d"),
}


def _safe_read_text(path: Path) -> dict:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        return {"path": str(path), "exists": True, "content": content[: settings.command_output_limit]}
    except FileNotFoundError:
        return {"path": str(path), "exists": False, "content": ""}
    except PermissionError:
        return {"path": str(path), "exists": False, "error": "permission_denied", "content": ""}


def _safe_read_directory(path: Path) -> dict:
    if not path.exists():
        return {"path": str(path), "exists": False, "entries": []}
    entries = []
    try:
        for item in sorted(path.iterdir()):
            if item.is_file():
                entries.append(
                    {
                        "name": item.name,
                        "content": item.read_text(encoding="utf-8", errors="replace")[: settings.command_output_limit],
                    }
                )
    except PermissionError:
        return {"path": str(path), "exists": False, "error": "permission_denied", "entries": []}
    return {"path": str(path), "exists": True, "entries": entries}


def _run_command(spec: CommandSpec) -> dict:
    original_argv = spec.argv
    if settings.host_fs_prefix:
        argv = ["chroot", settings.host_fs_prefix, *spec.argv]
        binary = shutil.which("chroot")
    else:
        argv = spec.argv
        binary = shutil.which(spec.argv[0])

    if not binary:
        return {"available": False, "reason": "binary_not_found", "command": original_argv}
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=spec.timeout,
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("command_timeout", extra={"command": spec.key, "timeout": spec.timeout})
        return {"available": True, "timed_out": True, "command": original_argv, "stdout": exc.stdout or "", "stderr": exc.stderr or ""}

    stdout = (completed.stdout or "")[: settings.command_output_limit]
    stderr = (completed.stderr or "")[: settings.command_output_limit]
    return {
        "available": True,
        "timed_out": False,
        "command": original_argv,
        "returncode": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


def _run_limited_find(args: list[str]) -> dict:
    binary = shutil.which("find")
    if not binary:
        return {"available": False, "reason": "binary_not_found", "command": ["find", *args]}
    try:
        completed = subprocess.run(
            [binary, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=settings.find_timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "available": True,
            "timed_out": True,
            "command": ["find", *args],
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
        }
    return {
        "available": True,
        "timed_out": False,
        "command": ["find", *args],
        "returncode": completed.returncode,
        "stdout": (completed.stdout or "")[: settings.command_output_limit],
        "stderr": (completed.stderr or "")[: settings.command_output_limit],
    }


def collect_local_snapshot() -> dict:
    try:
        snapshot = {
            "metadata": {
                "hostname": Path(f"{settings.host_fs_prefix}/etc/hostname").read_text(encoding="utf-8", errors="replace").strip()
                if Path(f"{settings.host_fs_prefix}/etc/hostname").exists()
                else None,
                "psutil": {
                    "cpu_count": psutil.cpu_count() or 1,
                    "cpu_percent": psutil.cpu_percent(interval=0.2),
                    "loadavg": list(getattr(psutil, "getloadavg", lambda: (0.0, 0.0, 0.0))()),
                    "memory": psutil.virtual_memory()._asdict(),
                    "swap": psutil.swap_memory()._asdict(),
                    "disk": psutil.disk_usage("/")._asdict(),
                    "net_io": psutil.net_io_counters()._asdict(),
                },
            },
            "files": {name: _safe_read_text(path) for name, path in TEXT_FILES.items()},
            "directories": {name: _safe_read_directory(path) for name, path in DIRECTORIES.items()},
            "commands": {name: _run_command(spec) for name, spec in COMMANDS.items()},
            "filesystem_checks": {
                "world_writable_etc": _run_limited_find([f"{settings.host_fs_prefix}/etc", "-xdev", "-type", "f", "-perm", "-0002"]),
                "suid_sgid_usr": _run_limited_find([f"{settings.host_fs_prefix}/usr", "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")"]),
            },
        }
    except Exception as exc:  # pragma: no cover - defensive wrapper
        raise ScanExecutionError("Unexpected read-only collection failure") from exc

    logger.info("local_snapshot_collected", extra={"keys": list(snapshot.keys())})
    return json.loads(json.dumps(snapshot))
