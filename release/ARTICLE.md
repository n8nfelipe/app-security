# App Security Audit: sua ferramenta open source para auditar servidores Linux

Se você administra servidores Linux, sabe como é importante ter visibilidade sobre o estado de segurança e performance da sua infraestrutura — sem precisar instalar agentes pesados ou mexer em configurações delicadas do sistema.

O **App Security Audit** é uma ferramenta open source que faz exatamente isso: executa coletas read-only (somente leitura) no servidor, calcula scores separados de segurança e performance, e gera recomendações priorizadas para você resolver o que importa primeiro.

## Como funciona na prática?

A ferramenta se conecta ao servidor (via Docker privilegiado ou systemd nativo), executa comandos whitelisted e leituras de arquivos do sistema (`/etc`, `/proc`), coleta evidências e calcula scores — tudo sem modificar nada no host. Depois, você abre o dashboard no navegador e vê:

- **Score de Segurança** — portas abertas, serviços expostos, políticas de firewall, vulnerabilidades de configuração.
- **Score de Performance** — uso de CPU, memória, disco, load average, serviços ativos.
- **Recomendações Priorizadas** — cada finding vem com justificativa e plano de ação, ordenados por prioridade.

## Por que usar?

- **Read-only e seguro:** não executa nenhuma ação destrutiva nem explotação.
- **Dashboard visual:** interface React simples, com Overview, Segurança, Performance e Recomendações.
- **Histórico por host:** compare audits ao longo do tempo por hostname e machine-id.
- **Exportação:** gere JSON ou PDF para auditoria, compliance ou handoff para o time.
- **Fácil de rodar:** Docker Compose para ambiente local, systemd para produção.

## Tecnologias

- **Backend:** FastAPI + SQLite — leve, rápido, sem dependência de banco remoto.
- **Frontend:** React + Vite — interface responsiva e moderna.
- **Testes:** 208 testes no backend com mocks isolados; testes de componentes no frontend.

## Comece agora

Clone o repositório, configure as variáveis de ambiente e rode com Docker Compose para ter o backend e frontend operacionais em minutos:

```bash
git clone https://github.com/bere/app-security.git
cd app-security
docker compose up --build
```

Acesse o frontend em `http://localhost:8080` e o backend em `http://localhost:8001`.

## Contribua

O projeto é livre e aberto para colaboração. Issues, PRs e novas regras de auditoria são bem-vindas. Consulte o [README completo](https://github.com/bere/app-security) para detalhes sobre arquitetura, modelo de dados e checklist de go-live.
