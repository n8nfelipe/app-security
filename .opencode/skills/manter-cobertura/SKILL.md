name: manter-cobertura
description: Garante que novas funcionalidades e correções tenham testes correspondentes

instructions:
- Ao desenvolver nova funcionalidade, criar testes unitários e/ou de integracao antes de finalizar
- Ao corrigir bugs, criar primeiro um teste que falha demonstrando o bug, depois corrigir
- Seguir o padrao de testes ja existente no projeto (verificar package.json para framework)
- Testes devem ter nomes descritivos e cobrir casos de sucesso e edge cases
- Garantir que coverage nao diminua apos as mudancas
- Se testes ja existirem para a funcionalidade, atualiza-los quando necessario
- Apos implementar, rodar testes para confirmar que tudo passa