import pytest
from app.services._identity import (
    CheckUid0Users,
    CheckManyShellUsers,
    CheckSudoNopasswd,
    CheckSshRootLogin,
    CheckSshPasswordAuth,
)


DEFAULT_RULES = {
    "security_weights": {"CRIT": 40, "HIGH": 20, "MED": 10, "LOW": 5, "INFO": 0},
    "performance_thresholds": {},
    "critical_services": [],
    "score_weights": {"security": 0.6, "performance": 0.4},
}


class TestCheckUid0Users:
    def test_no_extra_uid0(self):
        snapshot = {"files": {"passwd": {"content": "root:x:0:0:root:/root:/bin/bash\n"}}, "commands": {}}
        checker = CheckUid0Users()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_extra_uid0_found(self):
        snapshot = {
            "files": {
                "passwd": {
                    "content": "root:x:0:0:root:/root:/bin/bash\nadmin:x:0:0:admin:/home/admin:/bin/bash\n"
                }
            }
        }
        checker = CheckUid0Users()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 1
        assert findings[0].check_id == "sec_uid0_users"
        assert findings[0].severity == "CRIT"


class TestCheckManyShellUsers:
    def test_few_users(self):
        content = "\n".join([f"user{i}:x:{1000+i}:1000:User{i}:/home/user{i}:/bin/bash" for i in range(5)])
        snapshot = {"files": {"passwd": {"content": content + "\nroot:x:0:0:root:/root:/bin/bash\n"}}, "commands": {}}
        checker = CheckManyShellUsers()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_many_users(self):
        content = "\n".join([f"user{i}:x:{1000+i}:1000:User{i}:/home/user{i}:/bin/bash" for i in range(15)])
        snapshot = {"files": {"passwd": {"content": content + "\nroot:x:0:0:root:/root:/bin/bash\n"}}, "commands": {}}
        checker = CheckManyShellUsers()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 1
        assert findings[0].check_id == "sec_many_shell_users"
        assert findings[0].severity == "MED"


class TestCheckSudoNopasswd:
    def test_no_nopasswd(self):
        snapshot = {
            "files": {
                "sudoers": {"content": "root ALL=(ALL) ALL\n"},
                "sudoers_d": {"entries": []},
            },
            "commands": {},
        }
        checker = CheckSudoNopasswd()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_nopasswd_found(self):
        snapshot = {
            "files": {
                "sudoers": {"content": "user ALL=(ALL) NOPASSWD: ALL\n"},
                "sudoers_d": {"entries": []},
            },
            "commands": {},
        }
        checker = CheckSudoNopasswd()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 1
        assert findings[0].check_id == "sec_sudo_nopasswd"
        assert findings[0].severity == "HIGH"


class TestCheckSshRootLogin:
    def test_no_sshd_config(self):
        snapshot = {"files": {"sshd_config": {"content": ""}}, "commands": {}}
        checker = CheckSshRootLogin()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_permitrootlogin_yes(self):
        snapshot = {"files": {"sshd_config": {"content": "PermitRootLogin yes\n"}}, "commands": {}}
        checker = CheckSshRootLogin()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 1
        assert findings[0].check_id == "sec_ssh_root_login"

    def test_permitrootlogin_no(self):
        snapshot = {"files": {"sshd_config": {"content": "PermitRootLogin no\n"}}, "commands": {}}
        checker = CheckSshRootLogin()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_permitrootlogin_prohibit_password(self):
        snapshot = {"files": {"sshd_config": {"content": "PermitRootLogin prohibit-password\n"}}, "commands": {}}
        checker = CheckSshRootLogin()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 1


class TestCheckSshPasswordAuth:
    def test_no_sshd_config(self):
        snapshot = {"files": {"sshd_config": {"content": ""}}, "commands": {}}
        checker = CheckSshPasswordAuth()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 0

    def test_password_auth_yes(self):
        snapshot = {"files": {"sshd_config": {"content": "PasswordAuthentication yes\n"}}, "commands": {}}
        checker = CheckSshPasswordAuth()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 1
        assert findings[0].check_id == "sec_ssh_password_auth"

    def test_password_auth_no(self):
        snapshot = {"files": {"sshd_config": {"content": "PasswordAuthentication no\n"}}, "commands": {}}
        checker = CheckSshPasswordAuth()
        findings = checker.check(snapshot, {}, DEFAULT_RULES)
        assert len(findings) == 0