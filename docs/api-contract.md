# API contract

Autenticacao MVP: `Authorization: Bearer <token>` ou `X-API-Token`.

## Endpoints

### `POST /api/v1/scans`

Request:

```json
{
  "mode": "agentless",
  "target_name": "db-prod-01"
}
```

Response `202`:

```json
{
  "scan_id": "uuid",
  "status": "queued",
  "mode": "agentless",
  "created_at": "2026-03-01T12:00:00Z"
}
```

### `GET /api/v1/scans/{scan_id}/status`

Response `200`: status de `queued|running|completed|failed`.

### `GET /api/v1/scans/{scan_id}/results`

Response `200`: scores, findings, recomendacoes, resumo e payload bruto.

### `GET /api/v1/history?hostname=&machine_id=&limit=20`

Response `200`: lista resumida de scans.

### `GET /api/v1/scans/{scan_id}/export/json`

Response `200`: metadata do artefato e payload JSON serializado.

### `GET /api/v1/scans/{scan_id}/export/pdf`

Response `200`: arquivo PDF.

## Erros

- `401` token invalido.
- `404` scan inexistente.
- `422` payload invalido.
- `501` export PDF indisponivel.
