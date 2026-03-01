from app.services import parser


def test_parse_passwd_extracts_shell_users():
    content = "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/zsh\n"
    rows = parser.parse_passwd(content)
    assert rows[1]["username"] == "user"
    assert rows[1]["shell"] == "/bin/zsh"


def test_parse_df_returns_mount_percent():
    content = "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 100G 95G 5G 95% /\n"
    rows = parser.parse_df(content)
    assert rows == [
        {
            "filesystem": "/dev/sda1",
            "size": "100G",
            "used": "95G",
            "available": "5G",
            "use_percent": 95,
            "mountpoint": "/",
        }
    ]
