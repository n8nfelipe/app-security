#!/usr/bin/env bash
# =============================================================================
# linux_security_audit.sh  v2.0
# Auditoria de Segurança para Desktop Linux + Remediação Guiada
#
# Uso:
#   sudo bash linux_security_audit.sh              (modo interativo)
#   sudo bash linux_security_audit.sh --auto-fix   (aplica todas as correções)
#   sudo bash linux_security_audit.sh --report /caminho/relatorio.txt
# =============================================================================

set -uo pipefail
source "$(dirname "$0")/utils.sh"

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
REPORT_FILE="/tmp/security_audit_$(date +%Y%m%d_%H%M%S).txt"
AUTO_FIX=false
INTERACTIVE=true

for arg in "$@"; do
    case "$arg" in
        --auto-fix)   AUTO_FIX=true; INTERACTIVE=false ;;
        --no-fix)     INTERACTIVE=false ;;
        --report)     shift; REPORT_FILE="${1:-$REPORT_FILE}" ;;
    esac
done

PASS=0; WARN=0; FAIL=0; FIXED=0
LOG=()
REMEDIATION_LOG=()

# ---------------------------------------------------------------------------
# Cores
# ---------------------------------------------------------------------------
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

# ---------------------------------------------------------------------------
# Funções de output
# ---------------------------------------------------------------------------
header() {
    echo ""
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════${RESET}"
    echo -e "${CYAN}${BOLD}  $1${RESET}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════${RESET}"
    LOG+=("" "### $1" "")
}

pass()  { echo -e "  ${GREEN}[✔] $1${RESET}";  LOG+=("[PASS] $1");  ((PASS++));  }
warn()  { echo -e "  ${YELLOW}[⚠] $1${RESET}"; LOG+=("[WARN] $1");  ((WARN++));  }
fail()  { echo -e "  ${RED}[✘] $1${RESET}";   LOG+=("[FAIL] $1");  ((FAIL++));  }
info()  { echo -e "  ${CYAN}[ℹ] $1${RESET}";  LOG+=("[INFO] $1");              }

cmd_exists() { command -v "$1" &>/dev/null; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}${BOLD}Execute como root: sudo bash $0${RESET}"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Função central de remediação
# Uso: remediate "DESCRIÇÃO" "RISCO" "COMANDO1" "COMANDO2" ...
# ---------------------------------------------------------------------------
remediate() {
    local DESCRIPTION="$1"
    local RISK="$2"
    shift 2
    local COMMANDS=("$@")

    echo ""
    echo -e "  ${MAGENTA}${BOLD}┌─ AÇÃO DE MELHORIA ─────────────────────────────${RESET}"
    echo -e "  ${MAGENTA}│ ${BOLD}Problema:${RESET} $DESCRIPTION"
    echo -e "  ${MAGENTA}│ ${BOLD}Risco   :${RESET} $RISK"
    echo -e "  ${MAGENTA}│ ${BOLD}Comando(s) para corrigir:${RESET}"
    for CMD in "${COMMANDS[@]}"; do
        echo -e "  ${MAGENTA}│  ${DIM}$ ${RESET}${BOLD}${CMD}${RESET}"
    done
    echo -e "  ${MAGENTA}└────────────────────────────────────────────────${RESET}"

    LOG+=("[REMEDIATION] $DESCRIPTION")
    for CMD in "${COMMANDS[@]}"; do
        LOG+=("  CMD: $CMD")
    done
    REMEDIATION_LOG+=("---" "$DESCRIPTION" "Risco: $RISK")
    for CMD in "${COMMANDS[@]}"; do
        REMEDIATION_LOG+=("  \$ $CMD")
    done

    if $AUTO_FIX; then
        echo -e "  ${BLUE}[AUTO-FIX] Aplicando correção...${RESET}"
        for CMD in "${COMMANDS[@]}"; do
            if eval "$CMD" 2>/dev/null; then
                echo -e "  ${GREEN}[✔] Aplicado: $CMD${RESET}"
                ((FIXED++))
            else
                echo -e "  ${RED}[✘] Falha ao aplicar: $CMD${RESET}"
            fi
        done
    elif $INTERACTIVE; then
        echo -ne "  ${BLUE}[?] Deseja aplicar esta correção agora? [s/N]: ${RESET}"
        read -r CHOICE </dev/tty
        if [[ "${CHOICE,,}" == "s" || "${CHOICE,,}" == "sim" || "${CHOICE,,}" == "y" ]]; then
            for CMD in "${COMMANDS[@]}"; do
                echo -e "  ${BLUE}→ Executando: ${BOLD}$CMD${RESET}"
                if eval "$CMD" 2>/dev/null; then
                    echo -e "  ${GREEN}[✔] Sucesso${RESET}"
                    ((FIXED++))
                else
                    echo -e "  ${RED}[✘] Falha — execute manualmente${RESET}"
                fi
            done
        else
            echo -e "  ${DIM}  (correção ignorada — execute manualmente quando desejar)${RESET}"
        fi
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# 1. INFORMAÇÕES DO SISTEMA
# ---------------------------------------------------------------------------
section_sysinfo() {
    header "1. INFORMAÇÕES DO SISTEMA"
    info "Hostname   : $(hostname)"
    info "OS         : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -o)"
    info "Kernel     : $(uname -r)"
    info "Arquitetura: $(uname -m)"
    info "Uptime     : $(uptime -p 2>/dev/null || uptime)"
    info "Data/Hora  : $(date)"
}

# ---------------------------------------------------------------------------
# 2. ATUALIZAÇÕES DO SISTEMA
# ---------------------------------------------------------------------------
section_updates() {
    header "2. ATUALIZAÇÕES DO SISTEMA"

    if cmd_exists apt-get; then
        ${PKG_MANAGER} update -qq 2>/dev/null || true
        UPGRADABLE=$(apt list --upgradable 2>/dev/null | grep -c upgradable || true)
        if [[ "$UPGRADABLE" -eq 0 ]]; then
            pass "Sistema atualizado (apt)"
        else
            fail "$UPGRADABLE pacote(s) com atualização disponível"
            remediate \
                "$UPGRADABLE pacote(s) desatualizados" \
                "Vulnerabilidades conhecidas podem estar presentes" \
                "${PKG_MANAGER}upgrade -y" \
                "${PKG_MANAGER}dist-upgrade -y"
        fi

        SEC=$(apt list --upgradable 2>/dev/null | grep -ci security || true)
        if [[ "$SEC" -gt 0 ]]; then
            fail "$SEC atualização(ões) de segurança pendente(s)"
            remediate \
                "$SEC patch(es) de segurança pendentes" \
                "CRÍTICO: sistema exposto a vulnerabilidades CVE conhecidas" \
                "${PKG_MANAGER}install -y \$(apt list --upgradable 2>/dev/null | grep security | cut -d/ -f1 | tr '\n' ' ')"
        else
            pass "Sem atualizações de segurança pendentes"
        fi

    elif cmd_exists dnf; then
        UPGRADABLE=$(dnf check-update --quiet 2>/dev/null | grep -c "^[A-Za-z]" || true)
        if [[ "$UPGRADABLE" -gt 0 ]]; then
            fail "$UPGRADABLE pacote(s) desatualizados (dnf)"
            remediate \
                "$UPGRADABLE pacotes desatualizados" \
                "Possíveis vulnerabilidades não corrigidas" \
                "dnf upgrade -y" \
                "dnf updateinfo list security"
        else
            pass "Sistema atualizado (dnf)"
        fi

    elif cmd_exists pacman; then
        UPGRADABLE=$(pacman -Qu 2>/dev/null | wc -l || true)
        if [[ "$UPGRADABLE" -gt 0 ]]; then
            warn "$UPGRADABLE pacote(s) desatualizados (pacman)"
            remediate \
                "$UPGRADABLE pacotes desatualizados no Arch" \
                "Pacotes desatualizados podem conter falhas de segurança" \
                "pacman -Syu --noconfirm"
        else
            pass "Sistema atualizado (pacman)"
        fi
    else
        warn "Gerenciador de pacotes não identificado"
    fi

    # Atualização automática de segurança
    if cmd_exists apt-get && ! dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"; then
        warn "unattended-upgrades não instalado"
        remediate \
            "Atualizações automáticas de segurança desativadas" \
            "Sistema pode ficar desatualizado sem intervenção manual" \
            "${PKG_MANAGER}install -y unattended-upgrades" \
            "dpkg-reconfigure -plow unattended-upgrades"
    fi

    BOOT_KERNEL=$(uname -r)
    info "Kernel em uso: $BOOT_KERNEL"
}

# ---------------------------------------------------------------------------
# 3. USUÁRIOS E AUTENTICAÇÃO
# ---------------------------------------------------------------------------
section_users() {
    header "3. USUÁRIOS E AUTENTICAÇÃO"

    # UID 0 duplicado
    ROOT_USERS=$(awk -F: '($3 == 0){print $1}' /etc/passwd | tr '\n' ' ')
    if [[ "$ROOT_USERS" == "root " ]]; then
        pass "Apenas 'root' com UID 0"
    else
        fail "Múltiplos usuários com UID 0: $ROOT_USERS"
        EXTRA=$(echo "$ROOT_USERS" | tr ' ' '\n' | grep -v '^root$' | grep -v '^$' || true)
        for U in $EXTRA; do
            remediate \
                "Usuário '$U' tem UID 0 (privilégios de root)" \
                "CRÍTICO: backdoor de root — acesso total ao sistema" \
                "usermod -u \$(awk -F: 'NR==1{print \$3+1000}' /etc/passwd) $U" \
                "# OU para remover: userdel -r $U"
        done
    fi

    # Contas sem senha
    NO_PASS=$(awk -F: '($2 == "" || $2 == "!!" ){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ' || true)
    if [[ -z "$NO_PASS" ]]; then
        pass "Nenhuma conta sem senha"
    else
        fail "Contas sem senha: $NO_PASS"
        for U in $NO_PASS; do
            remediate \
                "Conta '$U' não possui senha definida" \
                "ALTO: acesso não autenticado possível" \
                "passwd $U" \
                "# OU para bloquear a conta: passwd -l $U"
        done
    fi

    # Shell interativo
    SHELL_USERS=$(awk -F: '$7 ~ /(bash|sh|zsh|fish|ksh)$/ && $3 >= 1000 {print $1}' /etc/passwd | tr '\n' ' ')
    info "Usuários com shell interativo: ${SHELL_USERS:-nenhum}"

    # NOPASSWD no sudoers
    NOPASSWD_ENTRIES=$(grep -rE '^\s*[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#' || true)
    if [[ -n "$NOPASSWD_ENTRIES" ]]; then
        warn "Existem entradas NOPASSWD no sudoers"
        remediate \
            "sudo NOPASSWD encontrado: permite escalada de privilégio sem senha" \
            "ALTO: qualquer processo rodando como esse usuário obtém root sem autenticação" \
            "visudo  # Remova as linhas NOPASSWD manualmente" \
            "grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d/"
    else
        pass "Nenhum NOPASSWD no sudoers"
    fi

    # Root login SSH
    if grep -qE '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config 2>/dev/null; then
        fail "Login root via SSH está HABILITADO"
        remediate \
            "SSH permite login direto como root" \
            "CRÍTICO: brute-force direto na conta root via rede" \
            "sed -i 's/^\s*PermitRootLogin\s.*/PermitRootLogin no/' /etc/ssh/sshd_config" \
            "systemctl restart sshd"
    else
        pass "Login root via SSH desabilitado"
    fi

    # Expiração de senhas
    MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "99999")
    if [[ "$MAX_DAYS" -le 90 ]]; then
        pass "Expiração máxima de senha: ${MAX_DAYS} dias"
    else
        warn "Expiração de senha: ${MAX_DAYS} dias (recomendado ≤90)"
        remediate \
            "Senhas sem prazo de expiração adequado" \
            "MÉDIO: senhas comprometidas podem ser usadas indefinidamente" \
            "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs" \
            "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'  /etc/login.defs" \
            "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs"
    fi

    # Complexidade de senha (pwquality)
    if ! cmd_exists pwscore && ! grep -q "pam_pwquality" /etc/pam.d/common-password 2>/dev/null; then
        warn "libpam-pwquality não configurada"
        remediate \
            "Sem política de complexidade de senha" \
            "MÉDIO: senhas fracas podem ser criadas sem restrição" \
            "${PKG_MANAGER}install -y libpam-pwquality 2>/dev/null || dnf install -y libpwquality 2>/dev/null || true" \
            "echo 'minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' >> /etc/security/pwquality.conf"
    fi
}

# ---------------------------------------------------------------------------
# 4. PERMISSÕES DE ARQUIVOS CRÍTICOS
# ---------------------------------------------------------------------------
section_permissions() {
    header "4. PERMISSÕES DE ARQUIVOS CRÍTICOS"

    declare -A EXPECTED=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="640"
        ["/etc/group"]="644"
        ["/etc/gshadow"]="640"
        ["/etc/sudoers"]="440"
        ["/etc/ssh/sshd_config"]="600"
        ["/boot/grub/grub.cfg"]="600"
    )

    declare -A OWNERS=(
        ["/etc/shadow"]="root:shadow"
        ["/etc/gshadow"]="root:shadow"
        ["/etc/sudoers"]="root:root"
    )

    for FILE in "${!EXPECTED[@]}"; do
        [[ -f "$FILE" ]] || continue
        ACTUAL=$(stat -c "%a" "$FILE")
        EXPECTED_PERM="${EXPECTED[$FILE]}"
        if [[ "$ACTUAL" -le "$EXPECTED_PERM" ]]; then
            pass "$FILE : $ACTUAL"
        else
            fail "$FILE : $ACTUAL (esperado ≤$EXPECTED_PERM)"
            remediate \
                "Permissão insegura em $FILE ($ACTUAL)" \
                "ALTO: leitura/escrita não autorizada em arquivo crítico" \
                "chmod $EXPECTED_PERM $FILE" \
                "${OWNERS[$FILE]+chown ${OWNERS[$FILE]} $FILE}"
        fi
    done

    # SUID/SGID
    SUID_COUNT=$(find / -xdev -perm /6000 -type f 2>/dev/null | wc -l)
    if [[ "$SUID_COUNT" -le 20 ]]; then
        pass "Arquivos SUID/SGID: $SUID_COUNT (aceitável)"
    else
        warn "Arquivos SUID/SGID: $SUID_COUNT (acima do esperado)"
        remediate \
            "$SUID_COUNT binários com bit SUID/SGID" \
            "MÉDIO: cada SUID desnecessário é uma superfície de escalada de privilégio" \
            "find / -xdev -perm /6000 -type f 2>/dev/null | tee /tmp/suid_list.txt" \
            "# Revise /tmp/suid_list.txt e remova SUID de binários não essenciais com:" \
            "# chmod u-s /caminho/do/binario"
    fi

    # World-writable
    WW=$(find / -xdev -type f -perm -0002 -not -perm -1000 2>/dev/null | wc -l)
    if [[ "$WW" -eq 0 ]]; then
        pass "Sem arquivos world-writable inseguros"
    else
        warn "$WW arquivo(s) world-writable sem sticky bit"
        remediate \
            "$WW arquivo(s) com permissão world-writable" \
            "ALTO: qualquer usuário pode sobrescrever esses arquivos" \
            "find / -xdev -type f -perm -0002 -not -perm -1000 2>/dev/null | tee /tmp/ww_files.txt" \
            "# Corrija cada arquivo listado em /tmp/ww_files.txt:" \
            "# chmod o-w /caminho/do/arquivo"
    fi
}

# ---------------------------------------------------------------------------
# 5. FIREWALL
# ---------------------------------------------------------------------------
section_firewall() {
    header "5. FIREWALL"

    if cmd_exists ufw; then
        STATUS=$(ufw status 2>/dev/null | head -1)
        if echo "$STATUS" | grep -qi "active"; then
            pass "UFW ativo"
        else
            fail "UFW instalado mas INATIVO"
            remediate \
                "Firewall UFW desativado" \
                "CRÍTICO: sistema sem proteção de rede, todas as portas expostas" \
                "ufw default deny incoming" \
                "ufw default allow outgoing" \
                "ufw allow ssh" \
                "ufw --force enable"
        fi
    elif cmd_exists firewall-cmd; then
        if firewall-cmd --state 2>/dev/null | grep -qi "running"; then
            pass "firewalld ativo"
        else
            fail "firewalld inativo"
            remediate \
                "firewalld não está em execução" \
                "CRÍTICO: sem filtragem de pacotes de rede" \
                "systemctl enable --now firewalld" \
                "firewall-cmd --set-default-zone=public" \
                "firewall-cmd --permanent --add-service=ssh" \
                "firewall-cmd --reload"
        fi
    elif cmd_exists iptables; then
        RULES=$(iptables -L 2>/dev/null | grep -c "ACCEPT\|DROP\|REJECT" || true)
        if [[ "$RULES" -gt 0 ]]; then
            pass "iptables com $RULES regras ativas"
        else
            warn "iptables sem regras definidas"
            remediate \
                "iptables instalado mas sem regras de filtragem" \
                "ALTO: tráfego não filtrado em todas as interfaces" \
                "iptables -P INPUT DROP" \
                "iptables -P FORWARD DROP" \
                "iptables -P OUTPUT ACCEPT" \
                "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT" \
                "iptables -A INPUT -i lo -j ACCEPT" \
                "iptables -A INPUT -p tcp --dport 22 -j ACCEPT" \
                "iptables-save > /etc/iptables/rules.v4"
        fi
    else
        fail "Nenhum firewall detectado"
        remediate \
            "Sistema sem firewall instalado" \
            "CRÍTICO: nenhuma proteção de rede presente" \
            "${PKG_MANAGER}install -y ufw 2>/dev/null || dnf install -y firewalld 2>/dev/null || true" \
            "ufw default deny incoming && ufw default allow outgoing && ufw allow ssh && ufw --force enable"
    fi
}

# ---------------------------------------------------------------------------
# 6. SSH
# ---------------------------------------------------------------------------
section_ssh() {
    header "6. CONFIGURAÇÃO SSH"

    SSHD_CONF="/etc/ssh/sshd_config"
    [[ -f "$SSHD_CONF" ]] || { info "sshd_config não encontrado"; return; }

    RESTART_NEEDED=false

    # Porta padrão
    SSH_PORT=$(grep -E '^\s*Port\s+' "$SSHD_CONF" 2>/dev/null | awk '{print $2}' | head -1 || echo "22")
    if [[ "${SSH_PORT:-22}" -eq 22 ]]; then
        warn "SSH na porta padrão 22"
        remediate \
            "SSH escutando na porta padrão 22" \
            "MÉDIO: porta 22 é varrida constantemente por bots de brute-force" \
            "sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config" \
            "# Lembre-se de liberar a nova porta no firewall!" \
            "ufw allow 2222/tcp 2>/dev/null || firewall-cmd --permanent --add-port=2222/tcp 2>/dev/null || true"
        RESTART_NEEDED=true
    else
        pass "SSH na porta não-padrão: $SSH_PORT"
    fi

    # Autenticação por senha
    PASSAUTH=$(grep -E '^\s*PasswordAuthentication' "$SSHD_CONF" | awk '{print $2}' | head -1 || echo "yes")
    if [[ "${PASSAUTH:-yes}" == "no" ]]; then
        pass "PasswordAuthentication desabilitada"
    else
        warn "PasswordAuthentication habilitada"
        remediate \
            "SSH aceita login por senha" \
            "ALTO: senhas podem ser atacadas por brute-force via rede" \
            "# Primeiro, certifique-se de ter uma chave SSH configurada:" \
            "# ssh-keygen -t ed25519 && ssh-copy-id usuario@servidor" \
            "sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config" \
            "sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config"
        RESTART_NEEDED=true
    fi

    # MaxAuthTries
    MAX_AUTH=$(grep -E '^\s*MaxAuthTries' "$SSHD_CONF" 2>/dev/null | awk '{print $2}' || echo "6")
    if [[ "${MAX_AUTH:-6}" -le 4 ]]; then
        pass "MaxAuthTries: $MAX_AUTH"
    else
        warn "MaxAuthTries: ${MAX_AUTH} (recomendado ≤4)"
        remediate \
            "MaxAuthTries muito alto: $MAX_AUTH tentativas por conexão" \
            "MÉDIO: facilita ataques de brute-force por sessão SSH" \
            "sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config"
        RESTART_NEEDED=true
    fi

    # X11Forwarding
    X11=$(grep -E '^\s*X11Forwarding' "$SSHD_CONF" 2>/dev/null | awk '{print $2}' || echo "no")
    if [[ "${X11:-no}" == "yes" ]]; then
        warn "X11Forwarding habilitado"
        remediate \
            "X11Forwarding ativo no SSH" \
            "BAIXO/MÉDIO: permite redirecionamento de janelas gráficas — vetor de ataque se não necessário" \
            "sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config"
        RESTART_NEEDED=true
    else
        pass "X11Forwarding desabilitado"
    fi

    # ClientAliveInterval
    ALIVE=$(grep -E '^\s*ClientAliveInterval' "$SSHD_CONF" 2>/dev/null | awk '{print $2}' || echo "0")
    if [[ "${ALIVE:-0}" -eq 0 ]]; then
        warn "ClientAliveInterval não configurado (sessões ociosas não expiram)"
        remediate \
            "Sessões SSH inativas não são encerradas automaticamente" \
            "MÉDIO: sessão abandonada pode ser sequestrada" \
            "sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config" \
            "sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/'   /etc/ssh/sshd_config"
        RESTART_NEEDED=true
    else
        pass "ClientAliveInterval: $ALIVE s"
    fi

    # Reiniciar sshd se necessário
    if $RESTART_NEEDED && ! $INTERACTIVE; then
        echo -e "  ${DIM}(reinicie o sshd para aplicar as mudanças: systemctl restart sshd)${RESET}"
    fi
}

# ---------------------------------------------------------------------------
# 7. SERVIÇOS INSEGUROS
# ---------------------------------------------------------------------------
section_services() {
    header "7. SERVIÇOS EM EXECUÇÃO"

    declare -A SVC_RISK=(
        ["telnet"]="CRÍTICO: tráfego em texto puro, credenciais expostas"
        ["rsh"]="CRÍTICO: remote shell sem criptografia"
        ["rlogin"]="CRÍTICO: login remoto sem criptografia"
        ["rexec"]="CRÍTICO: execução remota sem criptografia"
        ["finger"]="MÉDIO: expõe informações de usuários"
        ["tftp"]="ALTO: transferência de arquivos sem autenticação"
        ["vsftpd"]="ALTO: FTP transmite credenciais em texto puro"
        ["proftpd"]="ALTO: FTP transmite credenciais em texto puro"
        ["rpcbind"]="MÉDIO: expõe serviços RPC — vetor de exploração"
        ["avahi-daemon"]="BAIXO: mDNS/Bonjour — desnecessário em servidores"
        ["cups"]="BAIXO: servidor de impressão — desnecessário se não imprime"
        ["bluetooth"]="BAIXO: Bluetooth — desative se não utilizado"
    )

    for SVC in "${!SVC_RISK[@]}"; do
        if systemctl is-active --quiet "$SVC" 2>/dev/null; then
            fail "Serviço inseguro ativo: $SVC"
            remediate \
                "Serviço '$SVC' em execução" \
                "${SVC_RISK[$SVC]}" \
                "systemctl stop $SVC" \
                "systemctl disable $SVC" \
                "systemctl mask $SVC"
        else
            pass "$SVC: inativo"
        fi
    done

    ACTIVE=$(systemctl list-units --type=service --state=active 2>/dev/null | grep -c "active running" || true)
    info "Total de serviços ativos: $ACTIVE"
}

# ---------------------------------------------------------------------------
# 8. PORTAS ABERTAS
# ---------------------------------------------------------------------------
section_ports() {
    header "8. PORTAS ABERTAS"

    declare -A PORT_RISK=(
        [21]="FTP — credenciais em texto puro"
        [23]="Telnet — protocolo inseguro"
        [25]="SMTP — verifique se é intencional"
        [110]="POP3 — sem criptografia"
        [143]="IMAP — sem criptografia"
        [512]="rexec — serviço legado inseguro"
        [513]="rlogin — serviço legado inseguro"
        [514]="rsh/syslog — serviço legado inseguro"
        [3389]="RDP — alvo frequente de brute-force"
        [5900]="VNC — acesso remoto sem proteção adequada"
    )

    if cmd_exists ss; then
        PORTS=$(ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | sort -u)
    elif cmd_exists netstat; then
        PORTS=$(netstat -tlnp 2>/dev/null | awk 'NR>2{print $4}' | sort -u)
    else
        warn "ss e netstat não disponíveis"; return
    fi

    while IFS= read -r ADDR; do
        PORT=$(echo "$ADDR" | grep -oP ':\K\d+$' || true)
        [[ -z "$PORT" ]] && continue
        if [[ -n "${PORT_RISK[$PORT]+x}" ]]; then
            fail "Porta de risco aberta: $PORT — ${PORT_RISK[$PORT]}"
            PROC=$(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'users:\(\("\K[^"]+' || echo "desconhecido")
            remediate \
                "Porta $PORT aberta ($PROC) — ${PORT_RISK[$PORT]}" \
                "ALTO: porta conhecida como vetor de ataque" \
                "# Identifique o serviço: ss -tlnp | grep :$PORT" \
                "# Pare o serviço responsável, ex: systemctl stop \$SERVICO" \
                "# Bloqueie a porta: ufw deny $PORT 2>/dev/null || iptables -A INPUT -p tcp --dport $PORT -j DROP"
        else
            info "Porta aberta: $PORT"
        fi
    done <<< "$PORTS"
}

# ---------------------------------------------------------------------------
# 9. ANTIVÍRUS / IDS
# ---------------------------------------------------------------------------
section_av() {
    header "9. ANTIVÍRUS / DETECÇÃO DE INTRUSÃO"

    if cmd_exists clamscan; then
        pass "ClamAV instalado"
    else
        warn "ClamAV não encontrado"
        remediate \
            "Antivírus ClamAV não instalado" \
            "MÉDIO: sem varredura de malware e vírus" \
            "${PKG_MANAGER}install -y clamav clamav-daemon 2>/dev/null || dnf install -y clamav 2>/dev/null || true" \
            "freshclam"
    fi

    if cmd_exists rkhunter; then
        pass "rkhunter instalado"
    else
        warn "rkhunter não encontrado"
        remediate \
            "rkhunter (rootkit hunter) não instalado" \
            "MÉDIO: rootkits podem passar despercebidos" \
            "${PKG_MANAGER}install -y rkhunter 2>/dev/null || dnf install -y rkhunter 2>/dev/null || true" \
            "rkhunter --update && rkhunter --propupd"
    fi

    if cmd_exists chkrootkit; then
        pass "chkrootkit instalado"
    else
        warn "chkrootkit não encontrado"
        remediate \
            "chkrootkit não instalado" \
            "MÉDIO: detecção complementar de rootkits ausente" \
            "${PKG_MANAGER}install -y chkrootkit 2>/dev/null || dnf install -y chkrootkit 2>/dev/null || true"
    fi

    if cmd_exists aide; then
        pass "AIDE (monitoramento de integridade) instalado"
    else
        warn "AIDE não encontrado"
        remediate \
            "AIDE (controle de integridade de arquivos) não instalado" \
            "MÉDIO: alterações em arquivos do sistema podem passar sem detecção" \
            "${PKG_MANAGER}install -y aide 2>/dev/null || dnf install -y aide 2>/dev/null || true" \
            "aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
    fi

    if cmd_exists fail2ban-client; then
        if fail2ban-client status &>/dev/null; then
            pass "fail2ban ativo"
        else
            warn "fail2ban instalado mas inativo"
            remediate \
                "fail2ban instalado mas não está rodando" \
                "ALTO: sem bloqueio automático de brute-force" \
                "systemctl enable --now fail2ban"
        fi
    else
        warn "fail2ban não encontrado"
        remediate \
            "fail2ban não instalado" \
            "ALTO: IPs mal-intencionados não são bloqueados automaticamente" \
            "${PKG_MANAGER}install -y fail2ban 2>/dev/null || dnf install -y fail2ban 2>/dev/null || true" \
            "systemctl enable --now fail2ban"
    fi
}

# ---------------------------------------------------------------------------
# 10. DISCO / CRIPTOGRAFIA
# ---------------------------------------------------------------------------
section_disk() {
    header "10. DISCO E CRIPTOGRAFIA"

    # /tmp noexec
    TMPOPT=$(grep -E '\s/tmp\s' /proc/mounts 2>/dev/null | grep -o 'noexec' || true)
    if [[ "$TMPOPT" == "noexec" ]]; then
        pass "/tmp montado com noexec"
    else
        warn "/tmp sem opção noexec"
        remediate \
            "/tmp permite execução de binários" \
            "MÉDIO: malware pode ser baixado em /tmp e executado diretamente" \
            "# Adicione ao /etc/fstab (se /tmp for partição separada):" \
            "# tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" \
            "mount -o remount,noexec,nosuid,nodev /tmp"
    fi

    # LUKS
    if cmd_exists lsblk; then
        LUKS=$(lsblk -o TYPE 2>/dev/null | grep -c "crypt" || true)
        if [[ "$LUKS" -gt 0 ]]; then
            pass "Criptografia LUKS detectada ($LUKS dispositivo(s))"
        else
            warn "Nenhuma criptografia de disco (LUKS) detectada"
            remediate \
                "Disco sem criptografia full-disk" \
                "ALTO: dados acessíveis por qualquer pessoa com acesso físico ao dispositivo" \
                "# Para criptografar uma partição existente (DESTRUTIVO — faça backup antes!):" \
                "# cryptsetup luksFormat /dev/sdXY" \
                "# Para novo volume: cryptsetup luksFormat /dev/sdXY && cryptsetup open /dev/sdXY crypt_vol" \
                "# Recomendado: habilitar criptografia na instalação do SO"
        fi
    fi

    # Uso de disco
    HIGH_USAGE=$(df -h --output=pcent,target 2>/dev/null | awk 'NR>1{gsub(/%/,""); if($1+0>=90) print $2" ("$1"%)"}' || true)
    if [[ -z "$HIGH_USAGE" ]]; then
        pass "Uso de disco: nenhuma partição acima de 90%"
    else
        warn "Partições com uso ≥90%: $HIGH_USAGE"
        remediate \
            "Disco quase cheio em: $HIGH_USAGE" \
            "MÉDIO: disco cheio pode travar logs, impedir atualizações e causar instabilidade" \
            "du -sh /* 2>/dev/null | sort -rh | head -20  # Identifique os maiores consumidores" \
            "journalctl --vacuum-size=500M  # Limpa logs antigos do systemd" \
            "${PKG_MANAGER}autoremove -y && apt-get clean 2>/dev/null || dnf autoremove -y 2>/dev/null || true"
    fi
}

# ---------------------------------------------------------------------------
# 11. AUDITORIA / LOGS
# ---------------------------------------------------------------------------
section_audit() {
    header "11. SISTEMA DE AUDITORIA E LOGS"

    if systemctl is-active --quiet auditd 2>/dev/null; then
        pass "auditd ativo"
    else
        warn "auditd inativo"
        remediate \
            "Daemon de auditoria (auditd) não está rodando" \
            "MÉDIO: sem rastreamento de eventos do kernel (chamadas de sistema, acesso a arquivos)" \
            "${PKG_MANAGER}install -y auditd audispd-plugins 2>/dev/null || dnf install -y audit 2>/dev/null || true" \
            "systemctl enable --now auditd" \
            "# Regras básicas de auditoria:" \
            "auditctl -w /etc/passwd -p wa -k identity" \
            "auditctl -w /etc/sudoers -p wa -k sudoers" \
            "auditctl -w /var/log/auth.log -p wa -k auth"
    fi

    if systemctl is-active --quiet rsyslog 2>/dev/null || systemctl is-active --quiet syslog 2>/dev/null; then
        pass "Syslog ativo"
    else
        warn "rsyslog/syslog inativo"
        remediate \
            "Sistema de logs (rsyslog) não está em execução" \
            "ALTO: eventos do sistema não são registrados — impossível investigar incidentes" \
            "${PKG_MANAGER}install -y rsyslog 2>/dev/null || dnf install -y rsyslog 2>/dev/null || true" \
            "systemctl enable --now rsyslog"
    fi

    FAIL_AUTH=$(journalctl -q --since "24 hours ago" 2>/dev/null | grep -ci "authentication failure\|Failed password" || true)
    if [[ "$FAIL_AUTH" -eq 0 ]]; then
        pass "Sem falhas de autenticação nas últimas 24h"
    else
        warn "$FAIL_AUTH falha(s) de autenticação nas últimas 24h"
        remediate \
            "$FAIL_AUTH tentativas de autenticação falhas em 24h" \
            "MÉDIO/ALTO: possível brute-force em andamento" \
            "journalctl --since '24 hours ago' | grep -i 'failed\|failure' | tail -20  # Verifique IPs" \
            "# Se fail2ban não estiver ativo, instale-o:" \
            "${PKG_MANAGER}install -y fail2ban 2>/dev/null && systemctl enable --now fail2ban || true" \
            "# Para bloquear IP manualmente: ufw deny from IP_ATACANTE to any"
    fi

    # Rotação de logs
    if ! cmd_exists logrotate; then
        warn "logrotate não encontrado"
        remediate \
            "logrotate não instalado — logs podem crescer indefinidamente" \
            "BAIXO: disco pode encher com logs sem rotação" \
            "${PKG_MANAGER}install -y logrotate 2>/dev/null || dnf install -y logrotate 2>/dev/null || true"
    else
        pass "logrotate instalado"
    fi
}

# ---------------------------------------------------------------------------
# 12. PARÂMETROS DO KERNEL
# ---------------------------------------------------------------------------
section_kernel() {
    header "12. PARÂMETROS DO KERNEL (sysctl)"

    declare -A SYSCTL_CHECKS=(
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.tcp_syncookies"]="1"
        ["kernel.randomize_va_space"]="2"
        ["kernel.dmesg_restrict"]="1"
        ["fs.suid_dumpable"]="0"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["kernel.core_uses_pid"]="1"
    )

    declare -A SYSCTL_RISK=(
        ["net.ipv4.ip_forward"]="Encaminhamento de pacotes habilitado — sistema atuando como roteador"
        ["net.ipv4.conf.all.accept_redirects"]="Aceita pacotes ICMP redirect — vetor de man-in-the-middle"
        ["net.ipv4.conf.all.send_redirects"]="Envia ICMP redirects — revela topologia de rede"
        ["net.ipv4.conf.all.accept_source_route"]="Source routing habilitado — permite spoofing de IP"
        ["net.ipv4.tcp_syncookies"]="SYN cookies desabilitados — vulnerável a SYN flood"
        ["kernel.randomize_va_space"]="ASLR incompleto ou desabilitado — facilita exploração de buffer overflow"
        ["kernel.dmesg_restrict"]="dmesg acessível para usuários comuns — vaza informações do kernel"
        ["fs.suid_dumpable"]="Core dumps de processos SUID habilitados — vaza dados sensíveis"
        ["net.ipv4.conf.all.rp_filter"]="Reverse path filter desabilitado — permite IP spoofing"
        ["kernel.core_uses_pid"]="Core dumps sem PID no nome — dificulta diagnóstico e pode sobrescrever dumps"
    )

    SYSCTL_FIXES=""
    NEED_FIX=false

    for KEY in "${!SYSCTL_CHECKS[@]}"; do
        EXPECTED_VAL="${SYSCTL_CHECKS[$KEY]}"
        ACTUAL_VAL=$(sysctl -n "$KEY" 2>/dev/null || echo "N/A")
        if [[ "$ACTUAL_VAL" == "$EXPECTED_VAL" ]]; then
            pass "$KEY = $ACTUAL_VAL"
        else
            fail "$KEY = ${ACTUAL_VAL} (esperado: $EXPECTED_VAL)"
            SYSCTL_FIXES+="$KEY = $EXPECTED_VAL\n"
            NEED_FIX=true
        fi
    done

    if $NEED_FIX; then
        # Gera bloco de correção para /etc/sysctl.d/
        SYSCTL_SNIPPET=$(printf "$SYSCTL_FIXES")
        remediate \
            "Parâmetros do kernel inseguros detectados" \
            "ALTO: kernel exposto a ataques de rede e exploração de memória" \
            "# Aplicar imediatamente (temporário):" \
            "$(echo -e "$SYSCTL_FIXES" | while IFS='=' read -r K V; do [[ -n "$K" ]] && echo "sysctl -w ${K// /}=${V// /}"; done)" \
            "# Persistir entre reboots:" \
            "printf '$(echo -e "$SYSCTL_FIXES" | tr '\n' '|' | sed 's/|/\\\\n/g')' > /etc/sysctl.d/99-security-hardening.conf" \
            "sysctl -p /etc/sysctl.d/99-security-hardening.conf"
    fi
}

# ---------------------------------------------------------------------------
# 13. APPARMOR / SELINUX
# ---------------------------------------------------------------------------
section_mac() {
    header "13. CONTROLE DE ACESSO OBRIGATÓRIO (MAC)"

    if cmd_exists aa-status; then
        AA=$(aa-status 2>/dev/null | head -1 || true)
        if echo "$AA" | grep -qi "profiles are loaded"; then
            ENFORCED=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | grep -oP '\d+' || echo "0")
            COMPLAIN=$(aa-status 2>/dev/null | grep "profiles are in complain mode" | grep -oP '\d+' || echo "0")
            pass "AppArmor: $ENFORCED perfis enforce, $COMPLAIN em modo complain"
            if [[ "${COMPLAIN:-0}" -gt 0 ]]; then
                warn "$COMPLAIN perfil(s) AppArmor em modo 'complain' (não enforcing)"
                remediate \
                    "$COMPLAIN perfis AppArmor não estão em modo enforce" \
                    "MÉDIO: perfis em complain apenas registram violações, não bloqueiam" \
                    "aa-enforce /etc/apparmor.d/*  # Coloca todos os perfis em modo enforce" \
                    "# Para perfil específico: aa-enforce /etc/apparmor.d/usr.bin.firefox"
            fi
        else
            warn "AppArmor instalado mas sem perfis carregados"
            remediate \
                "AppArmor instalado mas sem perfis ativos" \
                "MÉDIO: confinamento de aplicações não está funcionando" \
                "${PKG_MANAGER}install -y apparmor-profiles apparmor-profiles-extra" \
                "systemctl enable --now apparmor" \
                "aa-enforce /etc/apparmor.d/*"
        fi
    elif cmd_exists getenforce; then
        SE=$(getenforce 2>/dev/null || true)
        if [[ "$SE" == "Enforcing" ]]; then
            pass "SELinux: Enforcing"
        else
            warn "SELinux: $SE (recomendado: Enforcing)"
            remediate \
                "SELinux não está em modo Enforcing (atual: $SE)" \
                "ALTO: confinamento de processos desabilitado" \
                "setenforce 1  # Aplica imediatamente (temporário)" \
                "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config  # Persiste no reboot"
        fi
    else
        warn "AppArmor e SELinux não detectados"
        remediate \
            "Nenhum sistema MAC (AppArmor/SELinux) instalado" \
            "ALTO: processos sem confinamento — exploração de uma aplicação compromete o sistema inteiro" \
            "${PKG_MANAGER}install -y apparmor apparmor-utils apparmor-profiles 2>/dev/null || true" \
            "systemctl enable --now apparmor" \
            "aa-enforce /etc/apparmor.d/*"
    fi
}

# ---------------------------------------------------------------------------
# PLANO DE AÇÃO CONSOLIDADO
# ---------------------------------------------------------------------------
print_action_plan() {
    if [[ ${#REMEDIATION_LOG[@]} -eq 0 ]]; then return; fi

    echo ""
    echo -e "${BOLD}${MAGENTA}══════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${MAGENTA}  PLANO DE AÇÃO CONSOLIDADO${RESET}"
    echo -e "${BOLD}${MAGENTA}══════════════════════════════════════════════════${RESET}"
    echo -e "  ${DIM}Todos os pontos que exigem ação:${RESET}"
    echo ""
    I=1
    for LINE in "${REMEDIATION_LOG[@]}"; do
        if [[ "$LINE" == "---" ]]; then
            echo -e "  ${BOLD}[$I]${RESET}"
            ((I++))
        else
            echo -e "  ${DIM}$LINE${RESET}"
        fi
    done
}

# ---------------------------------------------------------------------------
# SUMÁRIO FINAL
# ---------------------------------------------------------------------------
print_summary() {
    TOTAL=$((PASS + WARN + FAIL))
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  RESUMO DA AUDITORIA${RESET}"
    echo -e "${BOLD}══════════════════════════════════════════════════${RESET}"
    echo -e "  ${GREEN}✔ Aprovado  : $PASS${RESET}"
    echo -e "  ${YELLOW}⚠ Atenção   : $WARN${RESET}"
    echo -e "  ${RED}✘ Falha     : $FAIL${RESET}"
    [[ "$FIXED" -gt 0 ]] && echo -e "  ${BLUE}⚙ Corrigido : $FIXED${RESET}"
    echo -e "  Total       : $TOTAL"
    echo ""

    SCORE=$(( (PASS * 100) / (TOTAL > 0 ? TOTAL : 1) ))
    if   [[ "$SCORE" -ge 80 ]]; then GRADE="${GREEN}BOM ($SCORE%)${RESET}"
    elif [[ "$SCORE" -ge 60 ]]; then GRADE="${YELLOW}REGULAR ($SCORE%)${RESET}"
    else                              GRADE="${RED}CRÍTICO ($SCORE%)${RESET}"
    fi
    echo -e "  Pontuação   : ${BOLD}${GRADE}"
    echo ""

    # Salvar relatório completo
    {
        echo "=================================================================="
        echo " RELATÓRIO DE AUDITORIA DE SEGURANÇA"
        echo " Data   : $(date)"
        echo " Sistema: $(uname -r) | $(hostname)"
        echo " Score  : $SCORE% (PASS=$PASS | WARN=$WARN | FAIL=$FAIL)"
        echo "=================================================================="
        echo ""
        printf '%s\n' "${LOG[@]}"
        echo ""
        echo "=================================================================="
        echo " PLANO DE AÇÃO — REMEDIAÇÕES RECOMENDADAS"
        echo "=================================================================="
        printf '%s\n' "${REMEDIATION_LOG[@]}"
    } > "$REPORT_FILE"

    echo -e "  Relatório salvo em: ${CYAN}$REPORT_FILE${RESET}"
    echo ""
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
main() {
    check_root
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  ╔════════════════════════════════════════════════╗"
    echo "  ║   LINUX DESKTOP SECURITY AUDIT  v2.0          ║"
    echo "  ║   $(date '+%Y-%m-%d %H:%M:%S')                          ║"
    if $AUTO_FIX; then
    echo "  ║   MODO: AUTO-FIX (correções aplicadas)         ║"
    elif $INTERACTIVE; then
    echo "  ║   MODO: INTERATIVO (confirmação por item)       ║"
    else
    echo "  ║   MODO: SOMENTE LEITURA (sem correções)         ║"
    fi
    echo "  ╚════════════════════════════════════════════════╝"
    echo -e "${RESET}"

    section_sysinfo
    section_updates
    section_users
    section_permissions
    section_firewall
    section_ssh
    section_services
    section_ports
    section_av
    section_disk
    section_audit
    section_kernel
    section_mac

    print_action_plan
    print_summary
}

main "$@"
