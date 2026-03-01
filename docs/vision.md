# Visao do sistema

## Problema

Muitas distros leves sacrificam ergonomia, e muitas distros faceis de usar acabam carregando excesso de pacotes, servicos e superficie de ataque.

## Meta

Criar uma derivacao Debian com os seguintes principios:

- Leve: boot rapido, baixo uso de RAM e conjunto pequeno de servicos ativos.
- Segura: configuracao defensiva por padrao, sem depender do usuario para ativar o basico.
- Usavel: interface previsivel, apps essenciais prontos e defaults coerentes.
- Conservadora: priorizar componentes maduros e auditaveis.

## Principios tecnicos

- Debian Stable como base para reduzir churn operacional.
- Poucos repositorios e preferencia por pacotes oficiais.
- Menor privilegio por padrao.
- Servicos de rede desativados quando nao forem essenciais.
- Logs e auditoria suficientes para troubleshooting e incidentes.
- Build reproduzivel e versionado.

## Baseline de seguranca

- AppArmor ativo.
- `nftables` com politica default restritiva.
- `sudo` para administracao, root interativo desincentivado.
- `unattended-upgrades` para atualizacoes de seguranca.
- `tmpfs` e `sysctl` endurecidos conforme impacto aceitavel em desktop.
- Bloqueio de pacotes e apps de alto risco que nao sejam essenciais.

## Baseline de usabilidade

- Ambiente XFCE com menu simples, atalho para configuracoes e tema limpo.
- Navegador, editor de texto, visualizador PDF, gerenciador de arquivos e utilitarios de rede.
- Boot live funcional para teste antes da instalacao.
- Defaults locais claros para idioma, teclado e timezone.
