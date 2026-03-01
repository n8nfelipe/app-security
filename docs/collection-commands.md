# Scripts e comandos de coleta

Todos os comandos sao executados em modo somente leitura, com timeout e sem shell.

- `/etc/passwd`, `/etc/group`
  Justificativa: inventario de contas, shells e grupos.
- `/etc/sudoers`, `/etc/sudoers.d`
  Justificativa: delegacao de privilegios e NOPASSWD.
- `/etc/ssh/sshd_config`
  Justificativa: baseline de SSH.
- `ss -tulpen`
  Justificativa: portas em escuta e exposicao.
- `systemctl list-unit-files --type=service`
  Justificativa: servicos habilitados.
- `nft list ruleset`, `ufw status verbose`, `iptables -S`
  Justificativa: detectar baseline de firewall sem alteracao.
- `apt list --upgradable`
  Justificativa: backlog de updates em Debian/Ubuntu.
- `last -n 15`
  Justificativa: logins recentes sem consulta extensa.
- `journalctl -p 3 -n 40 --no-pager`
  Justificativa: erros recentes limitados.
- `dmesg --ctime --level=err,warn`
  Justificativa: sinais de OOM e estabilidade.
- `ps -eo pid,ppid,comm,%cpu,%mem,state --sort=-%cpu`
  Justificativa: top processos.
- `df -h`, `df -i`
  Justificativa: capacidade de disco e inodes.
- `ip -s link`
  Justificativa: erros de rede.
- `resolvectl status`
  Justificativa: estado DNS.
- `systemd-analyze blame`
  Justificativa: servicos lentos no boot.
- `find /etc -xdev -type f -perm -0002`
  Justificativa: arquivos world-writable perigosos.
- `find /usr -xdev -type f ( -perm -4000 -o -perm -2000 )`
  Justificativa: inventario de SUID/SGID com escopo limitado.
