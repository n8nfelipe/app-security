# App Security

Este repositorio contem o produto `App Security Audit`, uma plataforma React + FastAPI para avaliacao read-only de seguranca e performance Linux.

## A) Produto e requisitos

Resumo executivo: a ferramenta coleta evidencias de hosts Linux sem remediacao automatica, calcula scores separados de seguranca e performance, gera um score geral ponderado e produz um plano de acao priorizado. O foco e Blue Team, SRE e lideranca tecnica que precisam de baseline defensiva, capacidade operacional e recomendacoes seguras.

Suposicoes explicitas:

- MVP otimizado para Debian/Ubuntu, com deteccao segura quando comandos nao existem.
- SQLite e suficiente para ambiente local e laboratorios.
- Auth do MVP usa token compartilhado.
- Agent mode existe na arquitetura, mas depende de endpoint remoto configurado.

Detalhamento adicional em [product-overview.md](/home/bere/infra/app-security/docs/product-overview.md).

## B) Arquitetura e threat model

Visao resumida:

1. Frontend React/Vite chama a API FastAPI.
2. A API autentica, registra o scan e agenda a coleta.
3. O coletor executa apenas comandos whitelisted e leituras de `/etc` e `/proc`.
4. A engine de scoring aplica regras externas em JSON.
5. A engine de recomendacoes transforma findings em plano de acao.
6. SQLite guarda historico por hostname e machine-id.
7. Export service produz JSON e PDF.

Threat model resumido em [architecture.md](/home/bere/infra/app-security/docs/architecture.md).

## C) Modelo de dados

Esquema principal documentado em [data-model.md](/home/bere/infra/app-security/docs/data-model.md) e implementado em [models.py](/home/bere/infra/app-security/app/backend/app/db/models.py).

## D) API

Contrato OpenAPI-like em [api-contract.md](/home/bere/infra/app-security/docs/api-contract.md). Rotas implementadas em [scans.py](/home/bere/infra/app-security/app/backend/app/api/routes/scans.py).

## E) Backend

Estrutura principal:

- App FastAPI: [main.py](/home/bere/infra/app-security/app/backend/app/main.py)
- Config e auth: [config.py](/home/bere/infra/app-security/app/backend/app/core/config.py), [auth.py](/home/bere/infra/app-security/app/backend/app/core/auth.py)
- Persistencia: [session.py](/home/bere/infra/app-security/app/backend/app/db/session.py), [models.py](/home/bere/infra/app-security/app/backend/app/db/models.py)
- Coletor read-only: [linux.py](/home/bere/infra/app-security/app/backend/app/collectors/linux.py)
- Parsing, scoring e recomendacoes: [parser.py](/home/bere/infra/app-security/app/backend/app/services/parser.py), [scoring.py](/home/bere/infra/app-security/app/backend/app/services/scoring.py), [recommendations.py](/home/bere/infra/app-security/app/backend/app/services/recommendations.py)
- Orquestracao: [scan_service.py](/home/bere/infra/app-security/app/backend/app/services/scan_service.py)
- Regras externas: [rules.json](/home/bere/infra/app-security/app/backend/app/config/rules.json)

Setup local do backend:

```bash
cd /home/bere/infra/app-security/app/backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
export APPSEC_API_TOKEN=changeme-token
uvicorn app.main:app --reload
```

Migracao local rapida:

- O startup aplica uma migracao SQLite leve para adicionar colunas novas conhecidas, como `recommendations.metadata`.
- Para recriar o banco automaticamente em desenvolvimento, use `APPSEC_DEV_RECREATE_DB=true`.
- Exemplo:

```bash
export APPSEC_DEV_RECREATE_DB=true
uvicorn app.main:app --reload
```

## F) Frontend

Estrutura principal:

- Shell e rotas: [App.jsx](/home/bere/infra/app-security/app/frontend/src/App.jsx)
- Estado e API client: [useAuditData.js](/home/bere/infra/app-security/app/frontend/src/lib/useAuditData.js), [api.js](/home/bere/infra/app-security/app/frontend/src/lib/api.js)
- Paginas: [OverviewPage.jsx](/home/bere/infra/app-security/app/frontend/src/pages/OverviewPage.jsx), [SecurityPage.jsx](/home/bere/infra/app-security/app/frontend/src/pages/SecurityPage.jsx), [PerformancePage.jsx](/home/bere/infra/app-security/app/frontend/src/pages/PerformancePage.jsx), [RecommendationsPage.jsx](/home/bere/infra/app-security/app/frontend/src/pages/RecommendationsPage.jsx), [HistoryPage.jsx](/home/bere/infra/app-security/app/frontend/src/pages/HistoryPage.jsx)
- Componentes: [ScoreCards.jsx](/home/bere/infra/app-security/app/frontend/src/components/ScoreCards.jsx), [FindingsTable.jsx](/home/bere/infra/app-security/app/frontend/src/components/FindingsTable.jsx), [RecommendationList.jsx](/home/bere/infra/app-security/app/frontend/src/components/RecommendationList.jsx), [ExportPanel.jsx](/home/bere/infra/app-security/app/frontend/src/components/ExportPanel.jsx)
- Estilo responsivo: [app.css](/home/bere/infra/app-security/app/frontend/src/styles/app.css)

Setup local do frontend:

```bash
cd /home/bere/infra/app-security/app/frontend
npm install
cp .env.example .env
npm run dev
```

## G) Testes

Backend:

```bash
cd /home/bere/infra/app-security/app/backend
pytest
```

Frontend:

```bash
cd /home/bere/infra/app-security/app/frontend
npm test
```

Arquivos de teste:

- [test_parser.py](/home/bere/infra/app-security/app/backend/tests/test_parser.py)
- [test_scoring.py](/home/bere/infra/app-security/app/backend/tests/test_scoring.py)
- [ScoreCards.test.jsx](/home/bere/infra/app-security/app/frontend/src/components/ScoreCards.test.jsx)
- [FindingsTable.test.jsx](/home/bere/infra/app-security/app/frontend/src/components/FindingsTable.test.jsx)

## H) Docker Compose para subir tudo

```bash
cd /home/bere/infra/app-security
docker compose up --build
```

Arquivos:

- Compose: [docker-compose.yml](/home/bere/infra/app-security/docker-compose.yml)
- Backend image: [Dockerfile](/home/bere/infra/app-security/app/backend/Dockerfile)
- Frontend image: [Dockerfile](/home/bere/infra/app-security/app/frontend/Dockerfile)

Backend em `http://localhost:8000` e frontend em `http://localhost:8080`.

Nota operacional: o `docker compose` sobe a stack para demonstracao e desenvolvimento. Para avaliar o host Linux real em modo agentless, execute o backend diretamente no host-alvo; dentro do container ele enxerga o proprio namespace do container.

## I) README operacional

Contribuicao:

1. Crie branch curta e mantenha regras/thresholds em [rules.json](/home/bere/infra/app-security/app/backend/app/config/rules.json).
2. Nao adicione comandos destrutivos nem shell interpolation no coletor.
3. Todo novo check precisa de teste de parsing ou scoring.
4. Documente a justificativa da coleta em [collection-commands.md](/home/bere/infra/app-security/docs/collection-commands.md).

## J) Checklist de go-live

1. Trocar `APPSEC_API_TOKEN` por segredo real.
2. Restringir `APPSEC_CORS_ORIGINS` aos dominos finais.
3. Validar agentless em host Linux de referencia sem root.
4. Revisar impacto de `find` e ajustar escopo por ambiente.
5. Criar backup/rotacao do SQLite e diretio de exports.
6. Adicionar observabilidade externa para logs JSON.
7. Validar PDF/JSON export com politicas internas.
8. Executar smoke tests do frontend e API antes de publicar.
9. Desativar `APPSEC_DEV_RECREATE_DB` fora de ambiente local.

## Artefatos de planejamento

- Produto: [product-overview.md](/home/bere/infra/app-security/docs/product-overview.md)
- Arquitetura: [architecture.md](/home/bere/infra/app-security/docs/architecture.md)
- Modelo de dados: [data-model.md](/home/bere/infra/app-security/docs/data-model.md)
- Backlog e roadmap: [backlog-roadmap.md](/home/bere/infra/app-security/docs/backlog-roadmap.md)
- API: [api-contract.md](/home/bere/infra/app-security/docs/api-contract.md)
- Comandos de coleta: [collection-commands.md](/home/bere/infra/app-security/docs/collection-commands.md)
