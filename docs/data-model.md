# Modelo de dados

SQLite por padrao.

## Tabelas principais

- `scans`
  - `id`, `mode`, `target_name`, `status`
  - `machine_hostname`, `machine_id`, `distro`
  - `started_at`, `completed_at`
  - `security_score`, `performance_score`, `overall_score`
  - `score_explanation`, `summary`, `raw_payload`, `error_message`
- `findings`
  - `id`, `scan_id`, `check_id`, `domain`, `category`, `severity`
  - `title`, `evidence`, `recommendation`, `reference`, `rationale`, `weight`, `metadata`
- `recommendations`
  - `id`, `scan_id`, `title`, `priority`, `risk`, `impact`, `effort`
  - `domain`, `action`, `reason`, `source_check_id`
- `artifacts`
  - `id`, `scan_id`, `artifact_type`, `file_name`, `file_path`, `content_type`, `generated_at`
