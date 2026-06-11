name: security-scan
description: Escaneia vulnerabilidades e problemas de segurança

instructions:
- backend (Python):
  - rodar bandit -r app/backend/app (SAST)
  - rodar pip-audit (SCA)
- frontend (JavaScript):
  - rodar npm audit --audit-level=high
  - listar vulnerabilidades críticas e altas
  - sugerir npm audit fix quando possível
- infra:
  - rodar hadolint nos Dockerfiles (app/backend/Dockerfile, app/frontend/Dockerfile)
- secrets:
  - rodar gitleaks detect --source . --no-git -v
  - verificar uso de secrets no código (.env, tokens hardcoded, chaves)
- dependências:
  - analisar dependências desatualizadas
  - verificar se Dependabot está configurado (.github/dependabot.yml)
