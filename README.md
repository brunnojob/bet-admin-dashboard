# NOVA BET

Painel administrativo local de depósitos, saques, sites, domínios e administradores. Desenvolvido por [brunnodev](https://brunnodev.store).

## Executar no PC

Requer Node.js 24 ou superior com npm. Python não é necessário.

```sh
npm install
npm run dev
```

Abra http://localhost:8000. Login inicial: `admingb` / `admin`.

`npm run dev` reinicia o servidor quando o código do servidor muda. Atualize o navegador após editar a interface. Use `npm start` para executar sem reinício automático e `npm test` para testar a API.

## Recursos

- Visão geral com totais em reais e pendências.
- CRUD e busca de depósitos, saques, sites, domínios e administradores.
- SQLite persistente, senhas com scrypt, sessão HttpOnly, proteção CSRF e limite de tentativas de login.
- Histórico de alterações e proteção do último administrador ativo.
- Interface responsiva em português.

## Gateway

O gateway ainda não está conectado. Depósitos e saques são registros administrativos; salvar um registro ou marcar como concluído não cobra nem transfere dinheiro. A API informa `gateway.connected: false`. A integração futura deve criar operações no provedor, armazenar seus identificadores e atualizar os estados por webhooks autenticados e idempotentes. Não marque pagamentos reais como concluídos a partir do formulário de CRUD.

Sites e domínios são cadastros; não há provisionamento de hospedagem nem alteração de DNS.

## Dados e configuração

O servidor escuta apenas em `127.0.0.1`. Os dados ficam em `admin.sqlite3`, ignorado pelo Git. Bancos criados pela versão anterior em Python são compatíveis, inclusive os hashes de senha. Faça backup antes de migrar.

Variáveis opcionais: `PORT` (padrão `8000`) e `BET_ADMIN_DB` (caminho do banco). Sessões são encerradas quando o servidor reinicia. Todos os administradores têm acesso ao CRUD completo. O login padrão é para desenvolvimento local; revise autenticação e permissões antes de publicar.
