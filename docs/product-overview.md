# Produto e requisitos

## Proposito

App Security Audit e uma ferramenta profissional para avaliar hosts Linux em modo somente leitura, com foco em hardening, exposicao, sinais defensivos de comprometimento, capacidade e recomendacoes acionaveis.

## Usuarios

- Time Blue Team que precisa de baseline rapido sem acao destrutiva.
- SRE/Platform que precisa correlacionar capacidade, servicos e gargalos.
- Tech Leads que precisam priorizar remediacao com risco, impacto e esforco.

## Casos de uso

- Rodar coleta local agentless em servidores Linux.
- Comparar historico por hostname e machine-id.
- Exportar relatorio JSON/PDF para auditoria e handoff.
- Gerar plano de acao priorizado sem alterar o host automaticamente.

## Limites

- Nao corrige configuracoes automaticamente.
- Nao executa exploit, benchmark agressivo ou varredura invasiva.
- Root nunca e assumido; checks restritos por permissao retornam evidencia parcial.
- Agent mode e opcional e depende de endpoint configurado.
