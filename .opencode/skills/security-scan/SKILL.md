name: security-scan
description: Escaneia vulnerabilidades e problemas de segurança

instructions:
- rodar npm audit
- listar vulnerabilidades críticas e altas
- sugerir npm audit fix quando possível
- verificar uso de secrets no código (.env, tokens)
- analisar dependências desatualizadas