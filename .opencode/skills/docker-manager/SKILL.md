name: docker-manager
description: Gerencia containers Docker para Node e React

instructions:
- validar docker-compose.yml
- rodar docker compose build
- rodar docker compose up -d
- verificar logs com docker compose logs
- identificar falhas de build