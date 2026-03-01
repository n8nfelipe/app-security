from __future__ import annotations

from collections.abc import Iterable


def parse_key_value_file(content: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in content.splitlines():
        if "=" not in line or line.strip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"')
    return data


def parse_passwd(content: str) -> list[dict]:
    users: list[dict] = []
    for line in content.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        users.append(
            {
                "username": parts[0],
                "uid": int(parts[2]),
                "gid": int(parts[3]),
                "home": parts[5],
                "shell": parts[6],
            }
        )
    return users


def parse_group(content: str) -> list[dict]:
    groups: list[dict] = []
    for line in content.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        groups.append(
            {
                "name": parts[0],
                "gid": int(parts[2]),
                "members": [member for member in parts[3].split(",") if member],
            }
        )
    return groups


def parse_ss_listening(content: str) -> list[dict]:
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    sockets: list[dict] = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        sockets.append(
            {
                "proto": parts[0],
                "state": parts[1],
                "local_address": parts[4],
                "raw": line,
            }
        )
    return sockets


def parse_ps_table(content: str, limit: int = 10) -> list[dict]:
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    processes: list[dict] = []
    for line in lines[1 : limit + 1]:
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        processes.append(
            {
                "pid": int(parts[0]),
                "ppid": int(parts[1]),
                "command": parts[2],
                "cpu_percent": float(parts[3]),
                "memory_percent": float(parts[4]),
                "state": parts[5],
            }
        )
    return processes


def parse_df(content: str) -> list[dict]:
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    rows: list[dict] = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        rows.append(
            {
                "filesystem": parts[0],
                "size": parts[1],
                "used": parts[2],
                "available": parts[3],
                "use_percent": int(parts[4].rstrip("%")),
                "mountpoint": parts[5],
            }
        )
    return rows


def parse_systemd_units(content: str) -> list[dict]:
    units: list[dict] = []
    for line in content.splitlines():
        parts = [part for part in line.split() if part]
        if len(parts) < 2:
            continue
        units.append({"unit": parts[0], "state": parts[1]})
    return units


def parse_systemd_blame(content: str, limit: int = 10) -> list[dict]:
    items: list[dict] = []
    for line in content.splitlines()[:limit]:
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        items.append({"duration": parts[0], "unit": parts[1]})
    return items


def count_lines(content: str) -> int:
    return sum(1 for line in content.splitlines() if line.strip())


def any_match(values: Iterable[str], predicate: str) -> bool:
    return any(predicate in value for value in values)
