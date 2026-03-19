# Arquitetura e threat model

## Diagrama textual

1. React SPA
2. API FastAPI
3. Scan service
4. Collector engine read-only
5. Scoring engine
6. Recommendation engine
7. SQLite
8. Export service JSON/PDF

Fluxo principal:

1. Frontend chama `POST /api/v1/scans`.
2. API autentica por token (sincronizado via `.env`) e cria scan em SQLite.
3. Background task executa coleta agentless local ou encaminha para agent opcional.
4. Collector usa whitelist de comandos e leitura de `/etc` e `/proc`.
5. Scoring engine transforma evidencias em findings e scores.
6. Recommendation engine prioriza acoes.
7. Frontend consulta status/resultados e exporta relatorios.

## Threat model resumido

- Ator: usuario autenticado malicioso.
  Mitigacao: token compartilhado forte via `.env`, sem interpolar input em subprocess.
- Ator: host potencialmente comprometido retorna dados enganosos.
  Mitigacao: coleta defensiva, logs estruturados, nenhuma confianca para executar remediacao.
- Ator: ataque ao backend via browser.
  Mitigacao: CORS fechado por configuracao, endpoints sem execucao arbitraria.
- Ator: abuso de export.
  Mitigacao: export gera apenas dados ja persistidos para o scan autenticado.
- Ator: escalacao via comandos do coletor.
  Mitigacao: whitelist fixa, timeout, captura de saida e sem shell=True.
- Ator: vazamento de conexão/sessão DB.
  Mitigacao: uso mandário de context managers (`@contextmanager`) para garantir fechamento de sessões SQLAlchemy.
- Ator: bypass de auditoria SSH (falsos negativos).
  Mitigacao: validação via expressão regular robusta para detectar variantes de `PermitRootLogin` e `PasswordAuthentication`.
