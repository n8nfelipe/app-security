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

### Implementado

1. **Scans**: Rotas de scan, historico com filtros por hostname e machine_id. Mode agent e agentless.
2. **Coleta**: Coletor read-only com snapshot, coleta de arquivos, diretorios e comandos.
3. **Scoring**: Scores separados de seguranca e performance, overall score com pesos.
4. **Export**: Export JSON e PDF via API.
5. **Rede**: Scanner de dispositivos de rede e conexoes TCP/UDP.
6. **Containers**: Deteccao de containers Docker.
7. **Usuarios**: Listagem de usuarios e sessoes ativas.
8. **Testes**: 208 testes com mock (backend), cobertura ~70%.
9. **CI/CD**: Pipeline GitHub Actions com test-backend, test-frontend, build e release automatico.
10. **Systemd**: Script de instalacao como servico systemd.

### Pendente

1. Agent mode com endpoint remoto autenticado.
2. Filtros avancados por severidade, categoria e janela temporal.
3. Parsing mais profundo para distro, firewall, updates e boot.
4. Multi-tenant simples com RBAC leve.
5. Assinatura do relatorio e trilha de auditoria.
6. Mecanismo de baseline diff entre scans consecutivos.
