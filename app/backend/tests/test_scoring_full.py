import pytest
from unittest.mock import patch, MagicMock
import json
import tempfile


def test_build_findings_with_security_checks():
    from app.services.scoring import build_findings

    mock_snapshot = {
        "metadata": {"hostname": "test-host"},
        "commands": {},
        "files": {}
    }
    mock_rules = {
        "security_weights": {"low": 5, "medium": 15, "high": 30, "critical": 50},
        "score_weights": {"security": 0.6, "performance": 0.4}
    }

    with patch("app.services.scoring.SECURITY_CHECKS", []):
        findings = build_findings(mock_snapshot, mock_rules)
        assert isinstance(findings, list)


def test_calculate_scores_all_findings():
    from app.services.scoring import calculate_scores

    mock_findings = [
        {"domain": "security", "severity": "high"},
        {"domain": "security", "severity": "medium"},
        {"domain": "performance", "severity": "low"},
    ]
    mock_rules = {
        "security_weights": {"low": 5, "medium": 15, "high": 30, "critical": 50},
        "score_weights": {"security": 0.6, "performance": 0.4}
    }

    result = calculate_scores(mock_findings, mock_rules)

    assert "security" in result
    assert "performance" in result
    assert "overall" in result
    assert "explanation" in result
    assert result["security"] == 55.0
    assert result["performance"] == 95.0


def test_calculate_scores_no_findings():
    from app.services.scoring import calculate_scores

    mock_findings = []
    mock_rules = {
        "security_weights": {"low": 5, "medium": 15, "high": 30, "critical": 50},
        "score_weights": {"security": 0.6, "performance": 0.4}
    }

    result = calculate_scores(mock_findings, mock_rules)

    assert result["security"] == 100.0
    assert result["performance"] == 100.0
    assert result["overall"] == 100.0


def test_calculate_scores_critical_findings():
    from app.services.scoring import calculate_scores

    mock_findings = [
        {"domain": "security", "severity": "critical"},
        {"domain": "security", "severity": "critical"},
        {"domain": "security", "severity": "critical"},
    ]
    mock_rules = {
        "security_weights": {"low": 5, "medium": 15, "high": 30, "critical": 50},
        "score_weights": {"security": 0.6, "performance": 0.4}
    }

    result = calculate_scores(mock_findings, mock_rules)

    assert result["security"] == 0.0


def test_calculate_scores_mixed_domains():
    from app.services.scoring import calculate_scores

    mock_findings = [
        {"domain": "security", "severity": "low"},
        {"domain": "performance", "severity": "high"},
        {"domain": "security", "severity": "low"},
        {"domain": "performance", "severity": "high"},
    ]
    mock_rules = {
        "security_weights": {"low": 5, "medium": 15, "high": 30, "critical": 50},
        "score_weights": {"security": 0.6, "performance": 0.4}
    }

    result = calculate_scores(mock_findings, mock_rules)

    assert result["security"] == 90.0
    assert result["performance"] == 40.0


def test_calculate_scores_explanation():
    from app.services.scoring import calculate_scores

    mock_findings = [
        {"domain": "security", "severity": "high"},
    ]
    mock_rules = {
        "security_weights": {"low": 5, "medium": 15, "high": 30, "critical": 50},
        "score_weights": {"security": 0.6, "performance": 0.4}
    }

    result = calculate_scores(mock_findings, mock_rules)

    assert "weights" in result["explanation"]
    assert "severity_counts" in result["explanation"]
    assert "security_penalty" in result["explanation"]
    assert "why" in result["explanation"]


def test_summarize_snapshot_with_docker():
    from app.services.scoring import summarize_snapshot

    mock_snapshot = {
        "metadata": {"hostname": "docker-host"},
        "files": {
            "passwd": {"content": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:User:/home/user:/bin/bash"},
            "os_release": {"content": 'PRETTY_NAME="Ubuntu 22.04"'}
        },
        "commands": {
            "disk_usage": {"stdout": "Filesystem      Size  Used  Avail  Use%  Mounted on\n/dev/sda1       50G   20G   30G   40%  /"},
            "listening_ports": {"stdout": "Netid  State   Recv-Q  Send-Q  Local Address    Peer Address\ntcp    LISTEN  0       0      0.0.0.0:22      0.0.0.0:*"},
            "cpu_processes": {"stdout": "PID  USER  %CPU  %MEM  COMMAND\n1    root   0.1   0.2   systemd"},
            "docker_ps": {"stdout": "CONTAINER ID  IMAGE  STATUS\nabc123        nginx   Up 2 hours"},
            "docker_network": {"stdout": "NETWORK ID  NAME  DRIVER\nnet123       bridge  bridge"},
            "established_connections": {"stdout": "tcp  ESTAB  0  0  192.168.1.1:22  192.168.1.2:54321"}
        }
    }
    mock_findings = []

    result = summarize_snapshot(mock_snapshot, mock_findings)

    assert "docker_containers" in result
    assert "docker_networks" in result
    assert "listening_ports" in result


def test_summarize_snapshot_without_docker():
    from app.services.scoring import summarize_snapshot

    mock_snapshot = {
        "metadata": {"hostname": "no-docker-host"},
        "files": {
            "passwd": {"content": "root:x:0:0:root:/root:/bin/bash"},
            "os_release": {"content": 'PRETTY_NAME="Debian 12"'}
        },
        "commands": {
            "disk_usage": {"stdout": "Filesystem      Size  Used  Avail  Use%  Mounted on\n/dev/sda1       50G   20G   30G   40%  /"},
            "listening_ports": {"stdout": "Netid  State   Recv-Q  Send-Q  Local Address    Peer Address\ntcp    LISTEN  0       0      0.0.0.0:22      0.0.0.0:*"},
            "cpu_processes": {"stdout": "PID  USER  %CPU  %MEM  COMMAND\n1    root   0.1   0.2   systemd"},
            "established_connections": {"stdout": ""}
        }
    }
    mock_findings = []

    result = summarize_snapshot(mock_snapshot, mock_findings)

    assert result["docker_containers"] == 0
    assert result["docker_networks"] == 0


def test_summarize_snapshot_with_established_connections():
    from app.services.scoring import summarize_snapshot

    mock_snapshot = {
        "metadata": {"hostname": "connected-host"},
        "files": {
            "passwd": {"content": "root:x:0:0:root:/root:/bin/bash"},
            "os_release": {"content": 'PRETTY_NAME="Ubuntu 22.04"'}
        },
        "commands": {
            "disk_usage": {"stdout": "Filesystem      Size  Used  Avail  Use%  Mounted on\n/dev/sda1       50G   20G   30G   40%  /"},
            "listening_ports": {"stdout": "Netid  State   Recv-Q  Send-Q  Local Address    Peer Address\ntcp    LISTEN  0       0      0.0.0.0:22      0.0.0.0:*"},
            "cpu_processes": {"stdout": "PID  USER  %CPU  %MEM  COMMAND\n1    root   0.1   0.2   systemd"},
            "established_connections": {"stdout": "tcp  ESTAB  0  0  192.168.1.1:22  192.168.1.2:54321\ntcp  ESTAB  0  0  192.168.1.1:443  192.168.1.3:12345"}
        }
    }
    mock_findings = []

    result = summarize_snapshot(mock_snapshot, mock_findings)

    assert result["established_connections"] == 2


def test_summarize_snapshot_empty_passwd():
    from app.services.scoring import summarize_snapshot

    mock_snapshot = {
        "metadata": {"hostname": "empty-host"},
        "files": {
            "passwd": {"content": ""},
            "os_release": {"content": 'PRETTY_NAME="Unknown"'}
        },
        "commands": {
            "disk_usage": {"stdout": ""},
            "listening_ports": {"stdout": ""},
            "cpu_processes": {"stdout": ""},
            "established_connections": {"stdout": ""}
        }
    }
    mock_findings = []

    result = summarize_snapshot(mock_snapshot, mock_findings)

    assert result["human_users"] == 0


def test_summarize_snapshot_high_disk_pressure():
    from app.services.scoring import summarize_snapshot

    mock_snapshot = {
        "metadata": {"hostname": "disk-host"},
        "files": {
            "passwd": {"content": "root:x:0:0:root:/root:/bin/bash"},
            "os_release": {"content": 'PRETTY_NAME="Ubuntu 22.04"'}
        },
        "commands": {
            "disk_usage": {"stdout": "Filesystem      Size  Used  Avail  Use%  Mounted on\n/dev/sda1       50G   45G   5G   90%  /\n/dev/sdb1       100G   50G   50G   50%  /data"},
            "listening_ports": {"stdout": ""},
            "cpu_processes": {"stdout": ""},
            "established_connections": {"stdout": ""}
        }
    }
    mock_findings = []

    result = summarize_snapshot(mock_snapshot, mock_findings)

    assert len(result["disk_pressure_mounts"]) == 1


def test_summarize_snapshot_with_critical_findings():
    from app.services.scoring import summarize_snapshot

    mock_snapshot = {
        "metadata": {"hostname": "critical-host"},
        "files": {
            "passwd": {"content": "root:x:0:0:root:/root:/bin/bash"},
            "os_release": {"content": 'PRETTY_NAME="Ubuntu 22.04"'}
        },
        "commands": {
            "disk_usage": {"stdout": ""},
            "listening_ports": {"stdout": ""},
            "cpu_processes": {"stdout": ""},
            "established_connections": {"stdout": ""}
        }
    }
    mock_findings = [
        {"severity": "HIGH"},
        {"severity": "CRIT"},
        {"severity": "LOW"}
    ]

    result = summarize_snapshot(mock_snapshot, mock_findings)

    assert result["critical_findings"] == 2


def test_summarize_snapshot_network_details():
    from app.services.scoring import summarize_snapshot

    mock_snapshot = {
        "metadata": {"hostname": "network-host"},
        "files": {
            "passwd": {"content": "root:x:0:0:root:/root:/bin/bash"},
            "os_release": {"content": 'PRETTY_NAME="Ubuntu 22.04"'}
        },
        "commands": {
            "disk_usage": {"stdout": ""},
            "listening_ports": {"stdout": "Netid  State   Local Address:Port\ntcp    LISTEN  0.0.0.0:22"},
            "cpu_processes": {"stdout": ""},
            "established_connections": {"stdout": ""}
        }
    }
    mock_findings = []

    result = summarize_snapshot(mock_snapshot, mock_findings)

    assert "network_details" in result
    assert "listening_ports" in result["network_details"]