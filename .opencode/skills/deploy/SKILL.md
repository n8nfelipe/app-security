name: deploy
description: Realiza deploy da aplicação

instructions:
- rodar build de produção
- buildar imagem Docker
- subir containers
- validar se app está respondendo (health check)
- exibir URL final