#!/bin/bash
set -e

# Este script instala o backend do App Security Audit como um serviço systemd rodando como root.
# Isso garante que ele terá plenas permissões para auditar o SO host.

BACKEND_DIR=$(pwd)
SERVICE_FILE="/etc/systemd/system/appsec-backend.service"

echo "Configurando ambiente Python em $BACKEND_DIR..."
# Verifica se estamos no diretório certo
if [ ! -f "pyproject.toml" ]; then
    echo "ERRO: Por favor, rode este script de dentro da pasta app/backend."
    exit 1
fi

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install .

echo "Criando diretórios de dados..."
mkdir -p "$BACKEND_DIR/data/exports"

echo "Gerando arquivo de serviço $SERVICE_FILE..."
sudo bash -c "cat > $SERVICE_FILE <<EOF
[Unit]
Description=App Security Audit Backend
After=network.target

[Service]
User=root
WorkingDirectory=$BACKEND_DIR
Environment=\"PATH=$BACKEND_DIR/.venv/bin:\$PATH\"
Environment=\"APPSEC_API_TOKEN=changeme-token\"
Environment=\"APPSEC_CORS_ORIGINS=['http://localhost:5173','http://localhost:8080']\"
Environment=\"APPSEC_DATABASE_URL=sqlite:///$BACKEND_DIR/data/app_security_audit.db\"
Environment=\"APPSEC_EXPORT_DIR=$BACKEND_DIR/data/exports\"
ExecStart=$BACKEND_DIR/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8001
Restart=always

[Install]
WantedBy=multi-user.target
EOF"

echo "Iniciando e habilitando serviço..."
sudo systemctl daemon-reload
sudo systemctl enable appsec-backend.service
sudo systemctl restart appsec-backend.service

echo "Instalação completa! O backend está rodando nativamente no host na porta 8001 com permissões sudo/root."
echo "Use 'sudo systemctl status appsec-backend.service' para verificar o status."
echo "Use 'sudo journalctl -u appsec-backend.service -f' para ver os logs."
