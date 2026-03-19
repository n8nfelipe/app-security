import re

def check_ssh_regex(line):
    # Lógica extraída do scoring.py
    permit_root = re.search(r'^\s*PermitRootLogin\s+(yes|without-password|prohibit-password)\b', line, re.IGNORECASE)
    pass_auth = re.search(r'^\s*PasswordAuthentication\s+yes\b', line, re.IGNORECASE)
    return bool(permit_root), bool(pass_auth)

test_cases = [
    ("PermitRootLogin yes", (True, False)),
    ("  PermitRootLogin prohibit-password", (True, False)),
    ("PermitRootLogin no", (False, False)),
    ("#PermitRootLogin yes", (False, False)),
    ("PasswordAuthentication yes", (False, True)),
    ("PasswordAuthentication no", (False, False)),
    ("  PasswordAuthentication  yes  ", (False, True)),
]

for line, expected in test_cases:
    result = check_ssh_regex(line)
    status = "PASS" if result == expected else "FAIL"
    print(f"[{status}] Line: '{line}' -> Result: {result}, Expected: {expected}")
