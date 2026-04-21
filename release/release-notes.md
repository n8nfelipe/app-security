## Melhorias Implementadas

### CI/CD
- Push de tags automático no CI
- Permissão `contents:write` para criação de tags
- 35+ novos testes para checks e firewall

### Checkers (Arquitetura SOLID)
- Classes separadas para cada checker
- Docker checks isolados
- Firewall helpers extraídos
- Identity checks
- Network checks

### Parser & Scanner
- 18+ testes para parser
- 18+ testes para scoring e rules
- Portas ouvintes e conexões TCP detectadas

### Frontend
- Empty state na UI
- Meta tags SEO
- Robots.txt
- CORS hardening (origins, methods, headers)

### Backend
- Execução privilegiada com docker host mounts
- Suporte systemd
- Gerenciamento de db sessions
- Security hardening

### Documentação
- Screenshots atualizados
- README com execution modes
- Config sudo/root documentado
- Roadmap atualizado