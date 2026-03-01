# Backlog MVP e roadmap

## MVP em 2 semanas

Semana 1:

1. API FastAPI, auth por token, SQLite, modelos e rotas de scans.
2. Coletor local read-only com whitelist e parsing basico.
3. Scoring separado de seguranca/performance com regras externas.
4. Dashboard React com overview, findings e recomendacoes.

Semana 2:

1. Historico, export JSON/PDF, testes basicos backend/frontend.
2. Docker Compose e README operacional.
3. Hardening do proprio backend, logs estruturados e erros seguros.
4. Documentar comandos usados e limites eticos.

## Roadmap v1 em 6 semanas

1. Agent mode pronto com endpoint remoto autenticado.
2. Filtros avancados por host, severidade, categoria e janela temporal.
3. Parsing mais profundo para distro, firewall, updates e boot.
4. Multi-tenant simples com RBAC leve.
5. Assinatura do relatorio e trilha de auditoria.
6. Mecanismo de baseline diff entre scans consecutivos.
